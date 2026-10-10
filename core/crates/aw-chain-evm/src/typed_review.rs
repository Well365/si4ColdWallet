//! EIP-712 结构化数据的审查显示（P2a 第二部分）。
//!
//! 先给出"这是什么"的摘要（认得的类型见 `typed_known`），再**完整列出**消息的每一个字段。
//! 结构化签名常被用来做链下授权与挂单，签名后资产可被他人转走，所以一律按高风险处理（决策 D25、D29）。
//! 摘要只是帮助阅读；下面逐项列出的字段才是被签名的全部内容，任何字段都不截断：
//! 超长字段在解析时已拒签（`eip712::MAX_LEAF_BYTES`），十六进制按每行 32 字节切开。

use crate::chains::{chain_info, token_info};
use crate::eip712::{Digest, Leaf, LeafValue, TypedData};
use crate::message::{as_text, hex_lines};
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
    if !typed_known::summarize(td, &ctx, &mut disp) {
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
    use super::*;

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
}
