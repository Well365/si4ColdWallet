//! 认得的 EIP-712 类型：EIP-2612 Permit、DAI 式 permit、Uniswap Permit2、OpenSea Seaport 挂单。
//!
//! 只有"验证合约"与"结构"都对得上才给出摘要（审查 M2）：字段名任何人都能起，单凭字段名
//! 就说"你收到 1 ETH"会被伪造。对不上的一律按"无法识别"处理。所有分支都给高风险警告。

use crate::chains::{token_info, PERMIT2};
use crate::eip712::{LeafValue, TypedData};
use crate::review::{amount, chain, contract_label, token_amount};
use crate::typed_review::{addr, allowance, array_len, leaf, time_text, uint, Ctx};
use crate::uint::U256;
use crate::{checksum_address, parse_address};
use aw_common::display::{Display, Level, Style};

/// 类型 `ty` 的字段是否正好是给定列表（顺序也一致）
fn exact(td: &TypedData, ty: &str, want: &[(&str, &str)]) -> bool {
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

/// 类型 `ty` 的前若干个字段正好是给定列表
fn starts_with(td: &TypedData, ty: &str, want: &[(&str, &str)]) -> bool {
    td.types
        .iter()
        .find(|(n, _)| n == ty)
        .is_some_and(|(_, fields)| {
            fields.len() > want.len()
                && fields
                    .iter()
                    .zip(want)
                    .all(|(f, (n, t))| f.name == *n && f.ty == *t)
        })
}

const EIP2612: [(&str, &str); 5] = [
    ("owner", "address"),
    ("spender", "address"),
    ("value", "uint256"),
    ("nonce", "uint256"),
    ("deadline", "uint256"),
];

const DAI: [(&str, &str); 5] = [
    ("holder", "address"),
    ("spender", "address"),
    ("nonce", "uint256"),
    ("expiry", "uint256"),
    ("allowed", "bool"),
];

/// 识别并写出摘要；返回 false 表示不认识
pub fn summarize(td: &TypedData, ctx: &Ctx, disp: &mut Display) -> bool {
    let p = td.primary.as_str();
    if ctx.contract == Some(PERMIT2) {
        return permit2(td, ctx, disp);
    }
    if p == "Permit" && exact(td, p, &EIP2612) {
        eip2612(ctx, disp);
        return true;
    }
    if p == "Permit" && exact(td, p, &DAI) {
        dai_permit(ctx, disp);
        return true;
    }
    if is_seaport(td, ctx) {
        seaport(ctx, disp);
        return true;
    }
    false
}

/// 验证合约不在已知代币表中：额度只能按原始数值显示，也无法确认它真是代币
fn unknown_token_note(ctx: &Ctx, disp: &mut Display) {
    let known = ctx
        .chain_id
        .zip(ctx.contract)
        .is_some_and(|(c, a)| token_info(c, &a).is_some());
    if !known {
        disp.warn(
            Level::Caution,
            "验证合约不在已知代币表中：无法确认它是哪种代币，额度按原始数值显示",
        );
    }
}

const PERMIT_DETAILS: [(&str, &str); 4] = [
    ("token", "address"),
    ("amount", "uint160"),
    ("expiration", "uint48"),
    ("nonce", "uint48"),
];
const TOKEN_PERMISSIONS: [(&str, &str); 2] = [("token", "address"), ("amount", "uint256")];

/// Permit2 的六种结构（AllowanceTransfer 两种、SignatureTransfer 四种），结构必须完全一致
fn permit2_shape(td: &TypedData) -> bool {
    let p = td.primary.as_str();
    match p {
        "PermitSingle" => {
            exact(td, "PermitDetails", &PERMIT_DETAILS)
                && exact(
                    td,
                    p,
                    &[
                        ("details", "PermitDetails"),
                        ("spender", "address"),
                        ("sigDeadline", "uint256"),
                    ],
                )
        }
        "PermitBatch" => {
            exact(td, "PermitDetails", &PERMIT_DETAILS)
                && exact(
                    td,
                    p,
                    &[
                        ("details", "PermitDetails[]"),
                        ("spender", "address"),
                        ("sigDeadline", "uint256"),
                    ],
                )
        }
        "PermitTransferFrom" | "PermitBatchTransferFrom" => {
            exact(td, "TokenPermissions", &TOKEN_PERMISSIONS)
                && exact(td, p, &transfer_head(p == "PermitBatchTransferFrom"))
        }
        "PermitWitnessTransferFrom" | "PermitBatchWitnessTransferFrom" => {
            let head = transfer_head(p == "PermitBatchWitnessTransferFrom");
            exact(td, "TokenPermissions", &TOKEN_PERMISSIONS)
                && starts_with(td, p, &head)
                && td.types.iter().find(|(n, _)| n == p).is_some_and(|(_, f)| {
                    f.len() == 5 && f.get(4).is_some_and(|w| w.name == "witness")
                })
        }
        _ => false,
    }
}

fn transfer_head(batch: bool) -> [(&'static str, &'static str); 4] {
    [
        (
            "permitted",
            if batch {
                "TokenPermissions[]"
            } else {
                "TokenPermissions"
            },
        ),
        ("spender", "address"),
        ("nonce", "uint256"),
        ("deadline", "uint256"),
    ]
}

/// Uniswap Permit2：AllowanceTransfer（PermitSingle/PermitBatch 设定额度）
/// 与 SignatureTransfer（Permit*TransferFrom 一次性转账）
fn permit2(td: &TypedData, ctx: &Ctx, disp: &mut Display) -> bool {
    let p = td.primary.as_str();
    if !permit2_shape(td) {
        disp.title = format!("Permit2 合约的未知签名（{p}）");
        disp.warn(
            Level::Danger,
            "验证合约是 Permit2，但签名结构不是已知的任何一种：签名机无法确定它的含义，可能被用来转走你授权给 Permit2 的代币",
        );
        return true;
    }
    disp.title = if p.ends_with("TransferFrom") {
        format!("Permit2 签名转账（{p}）")
    } else {
        format!("Permit2 授权（{p}）")
    };
    let list = if p.starts_with("PermitBatch") {
        let name = if p == "PermitBatch" {
            "details"
        } else {
            "permitted"
        };
        (0..array_len(ctx.msg, name))
            .map(|i| format!("{name}[{i}]"))
            .collect::<Vec<_>>()
    } else if p == "PermitSingle" {
        vec!["details".to_owned()]
    } else {
        vec!["permitted".to_owned()]
    };
    for (k, prefix) in list.iter().enumerate() {
        permit2_token(ctx, disp, k + 1, prefix);
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
    true
}

fn permit2_token(ctx: &Ctx, disp: &mut Display, k: usize, prefix: &str) {
    let Some(token) = addr(ctx.msg, &format!("{prefix}.token")) else {
        return;
    };
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
    unknown_token_note(ctx, disp);
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
    unknown_token_note(ctx, disp);
    disp.warn(
        Level::Danger,
        "链下授权：任何拿到这份签名的人都可以把它提交上链；allowed 为 true 时就是无限额授权",
    );
}

/// Seaport 官方跨链部署地址（github.com/ProjectOpenSea/seaport，1.1–1.6）
const SEAPORT: [&str; 6] = [
    "0x00000000006c3852cbEf3e08E8dF289169EdE581",
    "0x00000000000006c7676171937C444f6BDe3D6282",
    "0x0000000000000aD24e80fd803C6ac37206a45f15",
    "0x00000000000001ad428e4906aE43D8F9852d0dD6",
    "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",
    "0x0000000000000068F116a894984e2DB1123eB395",
];

const OFFER_ITEM: [(&str, &str); 5] = [
    ("itemType", "uint8"),
    ("token", "address"),
    ("identifierOrCriteria", "uint256"),
    ("startAmount", "uint256"),
    ("endAmount", "uint256"),
];

const CONSIDERATION_ITEM: [(&str, &str); 6] = [
    ("itemType", "uint8"),
    ("token", "address"),
    ("identifierOrCriteria", "uint256"),
    ("startAmount", "uint256"),
    ("endAmount", "uint256"),
    ("recipient", "address"),
];

const ORDER_COMPONENTS: [(&str, &str); 11] = [
    ("offerer", "address"),
    ("zone", "address"),
    ("offer", "OfferItem[]"),
    ("consideration", "ConsiderationItem[]"),
    ("orderType", "uint8"),
    ("startTime", "uint256"),
    ("endTime", "uint256"),
    ("zoneHash", "bytes32"),
    ("salt", "uint256"),
    ("conduitKey", "bytes32"),
    ("counter", "uint256"),
];

fn is_seaport(td: &TypedData, ctx: &Ctx) -> bool {
    let official = ctx
        .contract
        .is_some_and(|c| SEAPORT.iter().any(|s| parse_address(s) == Some(c)));
    official
        && td.primary == "OrderComponents"
        && exact(td, "OrderComponents", &ORDER_COMPONENTS)
        && exact(td, "OfferItem", &OFFER_ITEM)
        && exact(td, "ConsiderationItem", &CONSIDERATION_ITEM)
}

/// Seaport 物品：0 原生币、1 ERC-20、2 ERC-721、3 ERC-1155、4/5 按条件匹配的 721/1155。
/// 返回 (显示文字, 数量是否为正, 价值是否可核实——原生币或已知代币)
fn seaport_item(ctx: &Ctx, prefix: &str) -> (String, bool, bool) {
    let get = |f: &str| uint(ctx.msg, &format!("{prefix}.{f}")).unwrap_or(U256::ZERO);
    let kind = get("itemType").to_u64();
    let token = addr(ctx.msg, &format!("{prefix}.token")).unwrap_or([0; 20]);
    let tok = ctx
        .chain_id
        .map_or(checksum_address(&token), |c| contract_label(c, &token));
    let known_token = ctx
        .chain_id
        .is_some_and(|c| token_info(c, &token).is_some());
    let qty = |v: U256| match (kind, ctx.chain_id) {
        (Some(0), Some(c)) => amount(v, &chain(c, None).symbol),
        (Some(1), Some(c)) => token_amount(c, &token, v),
        _ => v.to_decimal(),
    };
    let (start, end) = (get("startAmount"), get("endAmount"));
    let positive = !start.is_zero() || !end.is_zero();
    let n = if start == end {
        qty(start)
    } else {
        format!("{} → {}（随时间变化）", qty(start), qty(end))
    };
    let id = get("identifierOrCriteria").to_decimal();
    let (text, verifiable) = match kind {
        Some(0) => (format!("{n}（原生币）"), true),
        Some(1) => (format!("{n}（ERC-20 代币 {tok}）"), known_token),
        Some(2) => (format!("NFT {tok} 编号 {id}（数量 {n}）"), false),
        Some(3) => (format!("{n} 个 ERC-1155 {tok} 编号 {id}"), false),
        Some(4 | 5) => (
            format!("{n} 个 {tok} 中任意符合条件的 NFT（criteria {id}）"),
            false,
        ),
        _ => ("未知物品类型".to_owned(), false),
    };
    (text, positive, verifiable)
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
        let (text, _, _) = seaport_item(ctx, &format!("offer[{i}]"));
        disp.row(
            &format!("{who}给出（第 {} 项）", i + 1),
            text,
            Style::Amount,
        );
    }
    let (mut received, mut verifiable) = (0, 0);
    for i in 0..array_len(ctx.msg, "consideration") {
        let prefix = format!("consideration[{i}]");
        let to = addr(ctx.msg, &format!("{prefix}.recipient")).unwrap_or([0; 20]);
        let (text, positive, known) = seaport_item(ctx, &prefix);
        let label = if to == offerer {
            if positive {
                received += 1;
                verifiable += usize::from(known);
            }
            format!("{who}收到（第 {} 项）", i + 1)
        } else {
            format!("支付给 {}（第 {} 项）", checksum_address(&to), i + 1)
        };
        disp.row(&label, text, Style::Amount);
    }
    for (key, label) in [("startTime", "挂单生效"), ("endTime", "挂单截止")] {
        if let Some(t) = uint(ctx.msg, key) {
            disp.row(label, time_text(t), Style::Text);
        }
    }
    if received == 0 {
        disp.warn(
            Level::Danger,
            format!(
                "这份挂单里{who}什么也收不到（没有数量大于 0 的收款项）：这是典型的钓鱼挂单，签名后给出的资产可以被白白拿走"
            ),
        );
    } else if verifiable == 0 {
        disp.warn(
            Level::Danger,
            format!("{who}收到的全是无法核实价值的代币或 NFT：钓鱼挂单常用不值钱的代币冒充对价"),
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
    fn seaport_addresses_are_valid_checksums() {
        assert!(SEAPORT.iter().all(|s| parse_address(s).is_some()));
    }
}
