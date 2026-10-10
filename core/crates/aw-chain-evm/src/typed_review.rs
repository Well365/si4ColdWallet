//! EIP-712 结构化数据的审查显示（P2a 第二部分）。
//!
//! 先给出"这是什么"的摘要（认得的类型见 `typed_known`），再**完整列出**消息的每一个字段。
//! 结构化签名常被用来做链下授权与挂单，签名后资产可被他人转走，所以一律按高风险处理（决策 D25、D29）。
//! 摘要只是帮助阅读；下面逐项列出的字段才是被签名的全部内容，任何字段都不截断：
//! 超长字段在解析时已拒签（`eip712::MAX_LEAF_BYTES`），十六进制按每行 32 字节切开。

use crate::chains::{chain_info, token_info};
use crate::eip712::{Digest, Leaf, LeafValue, TypedData};
use crate::message::{as_text, hex_lines};
use crate::review;
use crate::review::{contract_label, is_huge, token_amount};
use crate::typed_known;
use crate::uint::U256;
use crate::{checksum_address, EvmError};
use aw_common::display::{Display, Level, Style};

/// 摘要需要的上下文
pub(crate) struct Ctx<'a> {
    pub(crate) chain_id: Option<u64>,
    pub(crate) contract: Option<[u8; 20]>,
    pub(crate) own: &'a [u8; 20],
    pub(crate) msg: &'a [Leaf],
}

pub(crate) fn leaf<'a>(leaves: &'a [Leaf], path: &str) -> Option<&'a LeafValue> {
    leaves.iter().find(|l| l.path == path).map(|l| &l.value)
}

pub(crate) fn addr(leaves: &[Leaf], path: &str) -> Option<[u8; 20]> {
    match leaf(leaves, path)? {
        LeafValue::Address(a) => Some(*a),
        _ => None,
    }
}

pub(crate) fn bytes<'a>(leaves: &'a [Leaf], path: &str) -> Option<&'a [u8]> {
    match leaf(leaves, path)? {
        LeafValue::Bytes(b) => Some(b),
        _ => None,
    }
}

pub(crate) fn uint(leaves: &[Leaf], path: &str) -> Option<U256> {
    match leaf(leaves, path)? {
        LeafValue::Uint(v) => Some(*v),
        _ => None,
    }
}

/// 数组 `name[...]` 的元素个数（按叶子路径推算；空数组为 0）
pub(crate) fn array_len(leaves: &[Leaf], name: &str) -> usize {
    let head = format!("{name}[");
    leaves
        .iter()
        .filter_map(|l| l.path.strip_prefix(&head))
        .filter_map(|rest| rest.split(']').next()?.parse::<usize>().ok())
        .map(|i| i.saturating_add(1))
        .max()
        .unwrap_or(0)
}

/// Unix 秒 → "YYYY-MM-DD HH:MM UTC"（Howard Hinnant 的 civil_from_days 算法）
pub fn utc_time(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

/// 时间戳的显示；公元 10000 年以后的值视为"不过期"
pub(crate) fn time_text(v: U256) -> String {
    match v.to_u64() {
        Some(s) if s < 253_402_300_800 => format!("{}（{s}）", utc_time(s)),
        _ => format!("{}（实际上永不过期）", v.to_decimal()),
    }
}

/// 结构化数据里的字符串：除 `as_text` 白名单外，换行、制表符、引号也不允许——
/// 它们可以在一行里伪造出"另一行"或提前结束引号（审查 M3）
fn plain_text(s: &str) -> Option<&str> {
    as_text(s.as_bytes()).filter(|t| !t.contains(['\n', '\t', '"']))
}

/// 一个叶子的显示文字；不能安全显示的字符串改为十六进制，返回 (文字, 是否不安全)
fn leaf_text(v: &LeafValue) -> (String, bool) {
    match v {
        LeafValue::Address(a) => (checksum_address(a), false),
        LeafValue::Uint(u) => (u.to_decimal(), false),
        LeafValue::Int(neg, m) => {
            let sign = if *neg { "-" } else { "" };
            (format!("{sign}{}", m.to_decimal()), false)
        }
        LeafValue::Bool(b) => (
            if *b {
                "true（是）"
            } else {
                "false（否）"
            }
            .to_owned(),
            false,
        ),
        LeafValue::Bytes(b) => (hex_lines(b), false),
        LeafValue::Str(s) => match plain_text(s) {
            Some(t) => (format!("\"{t}\""), false),
            None => (
                format!(
                    "（含不能安全显示的字符，按十六进制显示）\n{}",
                    hex_lines(s.as_bytes())
                ),
                true,
            ),
        },
        LeafValue::EmptyArray => ("（空数组）".to_owned(), false),
    }
}

/// 授权额度：≥ 2^128 或已知代币超过 1 万亿枚视为无限额；精度未知时显示原始数值
pub(crate) fn allowance(chain_id: Option<u64>, token: Option<[u8; 20]>, v: U256) -> String {
    if U256::bit(128).is_some_and(|limit| v >= limit) {
        return format!("无限额或接近无限额（{}）", v.to_decimal());
    }
    match chain_id.zip(token) {
        Some((c, t)) if token_info(c, &t).is_some() && is_huge(c, &t, v) => {
            format!("接近无限额（{}）", token_amount(c, &t, v))
        }
        Some((c, t)) => token_amount(c, &t, v),
        None => format!("{}（代币精度未知，显示原始数值）", v.to_decimal()),
    }
}

/// 链名与网络；未知链、测试网给出适合"签名"（而不是"交易"）的说明（审查 L7）
fn chain_rows(disp: &mut Display, chain_id: Option<u64>) {
    match chain_id.map(|id| (id, chain_info(id))) {
        Some((_, Some(c))) => {
            disp.chain = c.name.to_owned();
            disp.network = c.network.to_owned();
            if c.testnet {
                disp.warn(Level::Info, "测试网上的签名");
            }
        }
        Some((id, None)) => {
            disp.network = format!("链 ID {id}");
            disp.warn(
                Level::Caution,
                format!("未知链（链 ID {id}）：请确认这正是你要使用的网络"),
            );
        }
        None => disp.warn(
            Level::Caution,
            "签名没有绑定链 ID：同一份签名可能在任何一条链上被使用",
        ),
    }
}

/// Safe 多签的交易签名（SafeTx）。多签真正起授权作用的就是这份签名，所以链上 execTransaction 的全部规则
/// 在这里同样适用（D33）：operation ≠ 0 拒签；data 套用内层审查；退款参数非零强警告；对多签自身的管理调用拒签。
/// 类型叫 SafeTx 就必须是 Safe 的完整结构（域里有多签地址，九个字段齐全且类型正确），否则按无法解析拒签。
fn safe_tx(disp: &mut Display, ctx: &Ctx) -> Result<(), EvmError> {
    let safe = ctx.contract.ok_or(EvmError::Parse)?;
    let operation = uint(ctx.msg, "operation")
        .and_then(|o| o.to_u64())
        .ok_or(EvmError::Parse)?;
    if operation != 0 {
        return Err(EvmError::DelegateCall);
    }
    let to = addr(ctx.msg, "to").ok_or(EvmError::Parse)?;
    let value = uint(ctx.msg, "value").ok_or(EvmError::Parse)?;
    let data = bytes(ctx.msg, "data").ok_or(EvmError::Parse)?;
    let refund = review::Refund {
        safe_tx_gas: uint(ctx.msg, "safeTxGas").ok_or(EvmError::Parse)?,
        base_gas: uint(ctx.msg, "baseGas").ok_or(EvmError::Parse)?,
        gas_price: uint(ctx.msg, "gasPrice").ok_or(EvmError::Parse)?,
        gas_token: addr(ctx.msg, "gasToken").ok_or(EvmError::Parse)?,
        refund_receiver: addr(ctx.msg, "refundReceiver").ok_or(EvmError::Parse)?,
    };
    disp.title = "Safe 多签交易（SafeTx）".to_owned();
    disp.row("多签合约", checksum_address(&safe), Style::Address);
    disp.warn(
        Level::Danger,
        "这是 Safe 多签交易的签名：达到阈值后多签会按下面的内层调用执行。只有逐项核对目标地址、金额与完整 data 后才继续",
    );
    let chain_id = ctx.chain_id.unwrap_or(0);
    let symbol = review::chain(chain_id, None).symbol;
    let inner = review::InnerCtx {
        chain_id,
        safe,
        symbol: &symbol,
        depth: 0,
    };
    review::safe_refund_rows(disp, &inner, &refund);
    review::inner_call_rows(disp, &inner, &to, value, data)
}

pub fn describe(
    td: &TypedData,
    d: &Digest,
    req_chain: Option<u64>,
    own: &[u8; 20],
    index: u32,
) -> Result<Display, EvmError> {
    let dom = &d.domain_leaves;
    let chain_id = match uint(dom, "chainId") {
        Some(c) => Some(c.to_u64().ok_or(EvmError::Parse)?),
        None => None,
    };
    if let (Some(a), Some(b)) = (chain_id, req_chain) {
        if a != b {
            return Err(EvmError::ChainMismatch);
        }
    }
    let mut disp = Display::new("EVM", "结构化签名", "结构化签名（EIP-712）");
    chain_rows(&mut disp, chain_id);
    disp.row(
        "签名地址",
        format!("{}（地址 #{index}）", checksum_address(own)),
        Style::Address,
    );
    domain_rows(&mut disp, dom, chain_id);
    let ctx = Ctx {
        chain_id,
        contract: addr(dom, "verifyingContract"),
        own,
        msg: &d.leaves,
    };
    let recognized = if td.primary == "SafeTx" {
        safe_tx(&mut disp, &ctx)?;
        true
    } else {
        typed_known::summarize(td, &ctx, &mut disp)
    };
    if !recognized {
        let p = td.primary.as_str();
        disp.title = format!("结构化签名（{p}）");
        disp.warn(
            Level::Danger,
            format!(
                "无法识别的结构化签名类型 {p}：签名机看不懂它会被如何使用，它可能是一份授权或订单。\
                 只有完全信任对方、并逐项核对下面的字段后才继续"
            ),
        );
    }
    // 完整列出全部字段：认得也好、认不得也好，用户都能看到被签名的每一个值
    for l in &d.leaves {
        let (text, unsafe_text) = leaf_text(&l.value);
        if unsafe_text {
            disp.warn(
                Level::Caution,
                format!("字段 {} 含不能安全显示的字符，已按十六进制显示", l.path),
            );
        }
        disp.row(&format!("字段 {}（{}）", l.path, l.ty), text, Style::Data);
    }
    disp.warn(
        Level::Info,
        "结构化签名本身不发送交易，但可能被合约当作授权或订单使用",
    );
    Ok(disp)
}

fn domain_rows(disp: &mut Display, dom: &[Leaf], chain_id: Option<u64>) {
    for l in dom {
        let (text, unsafe_text) = leaf_text(&l.value);
        let (label, text, style) = match (l.path.as_str(), &l.value) {
            ("name", _) => ("应用名称（对方自称，不能作为信任依据）", text, Style::Text),
            ("version", _) => ("应用版本", text, Style::Text),
            ("chainId", _) => ("链 ID", text, Style::Text),
            ("verifyingContract", LeafValue::Address(a)) => (
                "验证合约",
                chain_id.map_or(text, |c| contract_label(c, a)),
                Style::Address,
            ),
            _ => ("域 salt", text, Style::Data),
        };
        if unsafe_text {
            disp.warn(
                Level::Caution,
                format!("{label} 含不能安全显示的字符，已按十六进制显示"),
            );
        }
        disp.row(label, text, style);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::eip712::TypedData;

    #[test]
    fn utc_time_known_values() {
        assert_eq!(utc_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_time(1_893_456_000), "2030-01-01 00:00 UTC");
        assert_eq!(utc_time(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc_time(1_760_054_400 + 3_661), "2025-10-10 01:01 UTC");
        assert_eq!(utc_time(253_402_300_799), "9999-12-31 23:59 UTC");
    }

    #[test]
    fn strings_that_could_fake_rows_are_shown_as_hex() {
        for bad in ["a\nb", "a\tb", "a\"b", "a\u{202e}b"] {
            let (text, unsafe_text) = leaf_text(&LeafValue::Str(bad.to_owned()));
            assert!(unsafe_text && text.contains("0x"), "{bad:?}");
        }
        assert_eq!(
            leaf_text(&LeafValue::Str("Hello, Bob!".to_owned())),
            ("\"Hello, Bob!\"".to_owned(), false)
        );
        assert_eq!(leaf_text(&LeafValue::EmptyArray).0, "（空数组）");
    }

    /// Safe 多签的 SafeTx 结构化签名；operation 1 = DELEGATECALL
    fn safe_tx_json(operation: u8) -> String {
        safe_tx_json_with(
            &operation.to_string(),
            "0x2222222222222222222222222222222222222222",
            "0x",
            0,
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000",
        )
    }

    const SAFE: &str = "0x1111111111111111111111111111111111111111";

    fn safe_tx_json_with(
        operation: &str,
        to: &str,
        data_hex: &str,
        gas_price: u64,
        gas_token: &str,
        refund_receiver: &str,
    ) -> String {
        format!(
            r#"{{"types":{{"EIP712Domain":[{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"SafeTx":[{{"name":"to","type":"address"}},{{"name":"value","type":"uint256"}},{{"name":"data","type":"bytes"}},{{"name":"operation","type":"uint8"}},{{"name":"safeTxGas","type":"uint256"}},{{"name":"baseGas","type":"uint256"}},{{"name":"gasPrice","type":"uint256"}},{{"name":"gasToken","type":"address"}},{{"name":"refundReceiver","type":"address"}},{{"name":"nonce","type":"uint256"}}]}},"primaryType":"SafeTx","domain":{{"chainId":1,"verifyingContract":"{SAFE}"}},"message":{{"to":"{to}","value":0,"data":"{data_hex}","operation":{operation},"safeTxGas":0,"baseGas":0,"gasPrice":{gas_price},"gasToken":"{gas_token}","refundReceiver":"{refund_receiver}","nonce":5}}}}"#
        )
    }

    fn describe_json(json: &str) -> Result<Display, EvmError> {
        let td = TypedData::parse(json).unwrap();
        let d = td.digest().unwrap();
        describe(&td, &d, Some(1), &[0x33; 20], 0)
    }

    /// docs/01 T9、D23：Safe 的 DELEGATECALL 默认拒签——通过 EIP-712 SafeTx 签名的路径也必须拒
    #[test]
    fn safe_tx_delegatecall_is_refused() {
        let td = TypedData::parse(&safe_tx_json(1)).unwrap();
        let d = td.digest().unwrap();
        assert_eq!(
            describe(&td, &d, Some(1), &[0x33; 20], 0).unwrap_err(),
            EvmError::DelegateCall
        );
    }

    /// operation 0（普通 CALL）仍可签，但必须带高风险警告并标明是 Safe 多签交易
    #[test]
    fn safe_tx_call_is_shown_as_safe_transaction_with_strong_warning() {
        let td = TypedData::parse(&safe_tx_json(0)).unwrap();
        let d = td.digest().unwrap();
        let disp = describe(&td, &d, Some(1), &[0x33; 20], 0).unwrap();
        assert!(disp.has_danger(), "{:?}", disp.warnings);
        assert!(disp.title.contains("Safe"), "{}", disp.title);
    }

    /// D33：SafeTx 的 data 必须按与链上 execTransaction 相同的规则审查
    #[test]
    fn safe_tx_data_is_reviewed_like_exec_transaction() {
        // 内层 approveHash：预批看不到内容的交易 → 拒签
        let approve_hash = format!("0xd4d9bdcd{}", "ab".repeat(32));
        let j = safe_tx_json_with("0", SAFE, &approve_hash, 0, SAFE_ZERO, SAFE_ZERO);
        assert_eq!(describe_json(&j).unwrap_err(), EvmError::BlindApproval);
        // 内层 execTransaction(operation = 1) → 拒签
        let inner_exec = format!(
            "0x6a761202{}{}{:064x}{:064x}",
            "00".repeat(12) + &"22".repeat(20),
            "00".repeat(32),
            0x140,
            1
        );
        let j = safe_tx_json_with("0", SAFE, &inner_exec, 0, SAFE_ZERO, SAFE_ZERO);
        assert_eq!(describe_json(&j).unwrap_err(), EvmError::DelegateCall);
        // 内层对 USDT 的无限额 approve → 必须出现"无限额"高风险警告
        let usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let approve = format!(
            "0x095ea7b3{}{}",
            "00".repeat(12) + &"44".repeat(20),
            "ff".repeat(32)
        );
        let d = describe_json(&safe_tx_json_with(
            "0", usdt, &approve, 0, SAFE_ZERO, SAFE_ZERO,
        ))
        .unwrap();
        assert!(
            d.warnings
                .iter()
                .any(|w| w.level == Level::Danger && w.text.contains("无限额")),
            "{:?}",
            d.warnings
        );
    }

    const SAFE_ZERO: &str = "0x0000000000000000000000000000000000000000";

    /// D33：多签对自身的管理调用（启用模块等）移交控制权 → 拒签
    #[test]
    fn safe_tx_admin_self_call_is_refused() {
        let enable_module = format!("0x610b5925{}", "00".repeat(12) + &"66".repeat(20));
        let j = safe_tx_json_with("0", SAFE, &enable_module, 0, SAFE_ZERO, SAFE_ZERO);
        assert_eq!(describe_json(&j).unwrap_err(), EvmError::SafeAdmin);
        // 同样的调用数据发给别的合约不是多签自管理，只按未知调用处理（高风险但可确认）
        let j = safe_tx_json_with(
            "0",
            "0x2222222222222222222222222222222222222222",
            &enable_module,
            0,
            SAFE_ZERO,
            SAFE_ZERO,
        );
        assert!(describe_json(&j).unwrap().has_danger());
    }

    /// D33：退款参数非零时必须显示并强警告
    #[test]
    fn safe_tx_refund_params_are_flagged() {
        let usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
        let attacker = "0x6666666666666666666666666666666666666666";
        let d = describe_json(&safe_tx_json_with(
            "0",
            SAFE,
            "0x",
            1_000_000_000_000,
            usdt,
            attacker,
        ))
        .unwrap();
        assert!(
            d.rows.iter().any(|r| r
                .value
                .contains("0x6666666666666666666666666666666666666666")),
            "{:?}",
            d.rows
        );
        assert!(
            d.warnings
                .iter()
                .any(|w| w.level == Level::Danger && w.text.contains("退款")),
            "{:?}",
            d.warnings
        );
        // 退款参数全零时没有这条警告
        let d = describe_json(&safe_tx_json(0)).unwrap();
        assert!(!d.warnings.iter().any(|w| w.text.contains("退款")));
    }

    /// operation 缺失或不是整数：不是 Safe 的结构 → 按解析错误拒签
    #[test]
    fn safe_tx_without_integer_operation_is_a_parse_error() {
        let j = safe_tx_json_with("\"1\"", SAFE, "0x", 0, SAFE_ZERO, SAFE_ZERO).replace(
            r#"{"name":"operation","type":"uint8"}"#,
            r#"{"name":"operation","type":"string"}"#,
        );
        assert_eq!(describe_json(&j).unwrap_err(), EvmError::Parse);
    }

    /// 审计复审 #7：SafeTx 缺字段、字段类型不对、域里没有多签地址 → 按无法解析拒签，不能默认成零
    #[test]
    fn safe_tx_incomplete_structures_are_parse_errors() {
        let full = safe_tx_json(0);
        let no_to = full
            .replacen(r#"{"name":"to","type":"address"},"#, "", 1)
            .replacen(
                r#""to":"0x2222222222222222222222222222222222222222","#,
                "",
                1,
            );
        assert_ne!(no_to, full);
        assert_eq!(describe_json(&no_to).unwrap_err(), EvmError::Parse);
        let str_gas = full
            .replacen(
                r#"{"name":"gasPrice","type":"uint256"}"#,
                r#"{"name":"gasPrice","type":"string"}"#,
                1,
            )
            .replacen(r#""gasPrice":0,"#, r#""gasPrice":"0","#, 1);
        assert_ne!(str_gas, full);
        assert_eq!(describe_json(&str_gas).unwrap_err(), EvmError::Parse);
        let no_vc = full
            .replacen(r#",{"name":"verifyingContract","type":"address"}"#, "", 1)
            .replacen(&format!(r#","verifyingContract":"{SAFE}""#), "", 1);
        assert_ne!(no_vc, full);
        assert_eq!(describe_json(&no_vc).unwrap_err(), EvmError::Parse);
    }
}
