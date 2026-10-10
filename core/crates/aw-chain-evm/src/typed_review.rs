//! EIP-712 结构化数据的审查显示（P2a 第二部分）。
//!
//! 先给出"这是什么"的摘要（Permit、Permit2、Seaport 挂单……），再**完整列出**消息的每一个字段。
//! 结构化签名常被用来做链下授权与挂单，签名后资产可被他人转走，所以一律按高风险处理（决策 D25、D29）：
//! 认得的类型给出具体说明，认不得的类型显示全部原始字段并提示无法识别。
//! 摘要只是帮助阅读；下面逐项列出的字段才是被签名的全部内容。

use crate::chains::PERMIT2;
use crate::eip712::{Digest, Leaf, LeafValue, TypedData};
use crate::message::as_text;
use crate::review::{amount, chain, contract_label, is_huge, token_amount};
use crate::uint::U256;
use crate::{checksum_address, EvmError};
use aw_common::display::{Display, Level, Style};
use aw_common::hex;

/// 摘要需要的上下文
struct Ctx<'a> {
    chain_id: Option<u64>,
    contract: Option<[u8; 20]>,
    own: &'a [u8; 20],
    msg: &'a [Leaf],
}

fn leaf<'a>(leaves: &'a [Leaf], path: &str) -> Option<&'a LeafValue> {
    leaves.iter().find(|l| l.path == path).map(|l| &l.value)
}

fn addr(leaves: &[Leaf], path: &str) -> Option<[u8; 20]> {
    match leaf(leaves, path)? {
        LeafValue::Address(a) => Some(*a),
        _ => None,
    }
}

fn uint(leaves: &[Leaf], path: &str) -> Option<U256> {
    match leaf(leaves, path)? {
        LeafValue::Uint(v) => Some(*v),
        _ => None,
    }
}

/// 数组 `name[...]` 的元素个数（按叶子路径推算；空数组为 0）
fn array_len(leaves: &[Leaf], name: &str) -> usize {
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
fn time_text(v: U256) -> String {
    match v.to_u64() {
        Some(s) if s < 253_402_300_800 => format!("{}（{s}）", utc_time(s)),
        _ => format!("{}（实际上永不过期）", v.to_decimal()),
    }
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
        LeafValue::Bytes(b) => (format!("0x{}", hex::encode(b)), false),
        LeafValue::Str(s) => match as_text(s.as_bytes()) {
            Some(t) => (format!("\"{t}\""), false),
            None => (
                format!("（含不能安全显示的字符）0x{}", hex::encode(s.as_bytes())),
                true,
            ),
        },
    }
}

/// 授权额度：≥ 2^128 或已知代币超过 1 万亿枚视为无限额；精度未知时显示原始数值
fn allowance(chain_id: Option<u64>, token: Option<[u8; 20]>, v: U256) -> String {
    if U256::bit(128).is_some_and(|limit| v >= limit) {
        return format!("无限额或接近无限额（{}）", v.to_decimal());
    }
    match chain_id.zip(token) {
        Some((c, t)) if crate::chains::token_info(c, &t).is_some() && is_huge(c, &t, v) => {
            format!("接近无限额（{}）", token_amount(c, &t, v))
        }
        Some((c, t)) => token_amount(c, &t, v),
        None => format!("{}（代币精度未知，显示原始数值）", v.to_decimal()),
    }
}

/// 类型 `ty` 是否包含全部给定字段（名称与类型都一致）
fn has_fields(td: &TypedData, ty: &str, want: &[(&str, &str)]) -> bool {
    td.types
        .iter()
        .find(|(n, _)| n == ty)
        .is_some_and(|(_, fields)| {
            want.iter()
                .all(|(n, t)| fields.iter().any(|f| f.name == *n && f.ty == *t))
        })
}

/// 类型 `ty` 的字段是否正好是给定列表（顺序也一致）
fn exact_fields(td: &TypedData, ty: &str, want: &[(&str, &str)]) -> bool {
    td.types
        .iter()
        .find(|(n, _)| n == ty)
        .is_some_and(|(_, fields)| {
            fields.len() == want.len()
                && fields
                    .iter()
                    .zip(want)
                    .all(|(f, (n, t))| f.name == *n && f.ty == *t)
        })
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
    match chain_id {
        Some(id) => {
            let c = chain(id, Some(&mut disp));
            disp.chain = c.name;
            disp.network = c.network;
        }
        None => disp.warn(
            Level::Caution,
            "签名没有绑定链 ID：同一份签名可能在任何一条链上被使用",
        ),
    }
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
    summarize(td, &ctx, &mut disp);
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

fn summarize(td: &TypedData, ctx: &Ctx, disp: &mut Display) {
    let p = td.primary.as_str();
    if ctx.contract == Some(PERMIT2) {
        permit2(p, ctx, disp);
    } else if p == "Permit"
        && exact_fields(
            td,
            p,
            &[
                ("owner", "address"),
                ("spender", "address"),
                ("value", "uint256"),
                ("nonce", "uint256"),
                ("deadline", "uint256"),
            ],
        )
    {
        eip2612(ctx, disp);
    } else if p == "Permit"
        && exact_fields(
            td,
            p,
            &[
                ("holder", "address"),
                ("spender", "address"),
                ("nonce", "uint256"),
                ("expiry", "uint256"),
                ("allowed", "bool"),
            ],
        )
    {
        dai_permit(ctx, disp);
    } else if is_seaport(td) {
        seaport(ctx, disp);
    } else {
        disp.title = format!("结构化签名（{p}）");
        disp.warn(
            Level::Danger,
            format!(
                "无法识别的结构化签名类型 {p}：签名机看不懂它会被如何使用，它可能是一份授权或订单。\
                 只有完全信任对方、并逐项核对下面的字段后才继续"
            ),
        );
    }
}

/// Uniswap Permit2：AllowanceTransfer（PermitSingle/PermitBatch 设定额度）
/// 与 SignatureTransfer（Permit*TransferFrom 一次性转账）
fn permit2(p: &str, ctx: &Ctx, disp: &mut Display) {
    let one_shot = p.ends_with("TransferFrom");
    disp.title = if one_shot {
        format!("Permit2 签名转账（{p}）")
    } else {
        format!("Permit2 授权（{p}）")
    };
    let mut k = 0;
    for l in ctx.msg {
        let Some(prefix) = l.path.strip_suffix(".token") else {
            continue;
        };
        if !(prefix.starts_with("details") || prefix.starts_with("permitted")) {
            continue;
        }
        let LeafValue::Address(token) = l.value else {
            continue;
        };
        k += 1;
        disp.row(
            &format!("代币 {k}"),
            ctx.chain_id
                .map_or(checksum_address(&token), |c| contract_label(c, &token)),
            Style::Address,
        );
        if let Some(v) = uint(ctx.msg, &format!("{prefix}.amount")) {
            disp.row(
                &format!("代币 {k} 额度"),
                allowance(ctx.chain_id, Some(token), v),
                Style::Amount,
            );
        }
        if let Some(e) = uint(ctx.msg, &format!("{prefix}.expiration")) {
            let text = if e.is_zero() {
                "0（只在提交上链的那个区块内有效）".to_owned()
            } else {
                time_text(e)
            };
            disp.row(&format!("代币 {k} 额度有效期至"), text, Style::Text);
        }
    }
    if let Some(s) = addr(ctx.msg, "spender") {
        disp.row("被授权方（spender）", checksum_address(&s), Style::Address);
    }
    for key in ["sigDeadline", "deadline"] {
        if let Some(t) = uint(ctx.msg, key) {
            disp.row("签名有效期至", time_text(t), Style::Text);
        }
    }
    if p.contains("Witness") {
        disp.warn(
            Level::Caution,
            "附带 witness 数据：它的含义由对方合约决定，请逐项核对下面的字段",
        );
    }
    disp.warn(
        Level::Danger,
        "Permit2 链下授权：签名后，被授权方可以在额度和期限内直接转走你的代币，不需要你再签任何交易",
    );
}

/// EIP-2612：验证合约就是代币合约
fn eip2612(ctx: &Ctx, disp: &mut Display) {
    disp.title = "代币 Permit 授权（EIP-2612，链下签名）".to_owned();
    if let Some(s) = addr(ctx.msg, "spender") {
        disp.row("被授权方（spender）", checksum_address(&s), Style::Address);
    }
    if let Some(v) = uint(ctx.msg, "value") {
        disp.row(
            "授权额度",
            allowance(ctx.chain_id, ctx.contract, v),
            Style::Amount,
        );
    }
    if let Some(t) = uint(ctx.msg, "deadline") {
        disp.row("签名有效期至", time_text(t), Style::Text);
    }
    if addr(ctx.msg, "owner").is_some_and(|o| o != *ctx.own) {
        disp.warn(Level::Caution, "授权人（owner）不是本签名地址");
    }
    disp.warn(
        Level::Danger,
        "链下授权：任何拿到这份签名的人都可以把它提交上链，让被授权方动用你的代币",
    );
}

/// DAI 式 permit：allowed = true 即无限额，expiry = 0 表示永不过期
fn dai_permit(ctx: &Ctx, disp: &mut Display) {
    disp.title = "DAI 式 Permit 授权（链下签名）".to_owned();
    if let Some(s) = addr(ctx.msg, "spender") {
        disp.row("被授权方（spender）", checksum_address(&s), Style::Address);
    }
    let allowed = matches!(leaf(ctx.msg, "allowed"), Some(LeafValue::Bool(true)));
    disp.row(
        "授权额度",
        if allowed {
            "无限额"
        } else {
            "0（撤销授权）"
        },
        Style::Amount,
    );
    if let Some(t) = uint(ctx.msg, "expiry") {
        let text = if t.is_zero() {
            "0（永不过期）".to_owned()
        } else {
            time_text(t)
        };
        disp.row("签名有效期至", text, Style::Text);
    }
    if addr(ctx.msg, "holder").is_some_and(|o| o != *ctx.own) {
        disp.warn(Level::Caution, "授权人（holder）不是本签名地址");
    }
    disp.warn(
        Level::Danger,
        "链下授权：任何拿到这份签名的人都可以把它提交上链；allowed 为 true 时就是无限额授权",
    );
}

const OFFER_ITEM: [(&str, &str); 5] = [
    ("itemType", "uint8"),
    ("token", "address"),
    ("identifierOrCriteria", "uint256"),
    ("startAmount", "uint256"),
    ("endAmount", "uint256"),
];

fn is_seaport(td: &TypedData) -> bool {
    td.primary == "OrderComponents"
        && has_fields(
            td,
            "OrderComponents",
            &[
                ("offerer", "address"),
                ("offer", "OfferItem[]"),
                ("consideration", "ConsiderationItem[]"),
                ("startTime", "uint256"),
                ("endTime", "uint256"),
            ],
        )
        && has_fields(td, "OfferItem", &OFFER_ITEM)
        && has_fields(td, "ConsiderationItem", &OFFER_ITEM)
        && has_fields(td, "ConsiderationItem", &[("recipient", "address")])
}

/// Seaport 物品：0 原生币、1 ERC-20、2 ERC-721、3 ERC-1155、4/5 按条件匹配的 721/1155
fn seaport_item(ctx: &Ctx, prefix: &str) -> String {
    let get = |f: &str| uint(ctx.msg, &format!("{prefix}.{f}")).unwrap_or(U256::ZERO);
    let kind = get("itemType").to_u64();
    let token = addr(ctx.msg, &format!("{prefix}.token")).unwrap_or([0; 20]);
    let tok = ctx
        .chain_id
        .map_or(checksum_address(&token), |c| contract_label(c, &token));
    let qty = |v: U256| match (kind, ctx.chain_id) {
        (Some(0), Some(c)) => amount(v, &chain(c, None).symbol),
        (Some(1), Some(c)) => token_amount(c, &token, v),
        _ => v.to_decimal(),
    };
    let (start, end) = (get("startAmount"), get("endAmount"));
    let n = if start == end {
        qty(start)
    } else {
        format!("{} → {}（随时间变化）", qty(start), qty(end))
    };
    let id = get("identifierOrCriteria").to_decimal();
    match kind {
        Some(0) => format!("{n}（原生币）"),
        Some(1) => format!("{n}（ERC-20 代币 {tok}）"),
        Some(2) => format!("NFT {tok} 编号 {id}（数量 {n}）"),
        Some(3) => format!("{n} 个 ERC-1155 {tok} 编号 {id}"),
        Some(4 | 5) => format!("{n} 个 {tok} 中任意符合条件的 NFT（criteria {id}）"),
        _ => "未知物品类型".to_owned(),
    }
}

fn seaport(ctx: &Ctx, disp: &mut Display) {
    disp.title = "Seaport 挂单（链下签名）".to_owned();
    let offerer = addr(ctx.msg, "offerer").unwrap_or([0; 20]);
    let who = if offerer == *ctx.own {
        "你"
    } else {
        disp.warn(Level::Caution, "挂单人（offerer）不是本签名地址");
        "挂单人"
    };
    for i in 0..array_len(ctx.msg, "offer") {
        disp.row(
            &format!("{who}给出 {}", i + 1),
            seaport_item(ctx, &format!("offer[{i}]")),
            Style::Amount,
        );
    }
    let mut to_self = 0;
    for i in 0..array_len(ctx.msg, "consideration") {
        let prefix = format!("consideration[{i}]");
        let to = addr(ctx.msg, &format!("{prefix}.recipient")).unwrap_or([0; 20]);
        let label = if to == offerer {
            to_self += 1;
            format!("{who}收到（第 {} 项）", i + 1)
        } else {
            format!("支付给 {}（第 {} 项）", checksum_address(&to), i + 1)
        };
        disp.row(&label, seaport_item(ctx, &prefix), Style::Amount);
    }
    for (key, label) in [("startTime", "挂单生效"), ("endTime", "挂单截止")] {
        if let Some(t) = uint(ctx.msg, key) {
            disp.row(label, time_text(t), Style::Text);
        }
    }
    if to_self == 0 {
        disp.warn(
            Level::Danger,
            format!(
                "这份挂单里{who}什么也收不到：这是典型的钓鱼挂单，签名后给出的资产可以被白白拿走"
            ),
        );
    }
    disp.warn(
        Level::Danger,
        "挂单签名：签名后任何人都可以按订单条件成交，转走你给出的 NFT 或代币。请逐项核对价格与收款方",
    );
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
}
