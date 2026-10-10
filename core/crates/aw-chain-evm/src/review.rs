//! 签名前审查（威胁 T5/T8/T9/T11）：从待签字节重新解析出全部字段，生成通用显示模型。
//!
//! 默认拒签（返回错误）：路径不是本账户、声明地址不符、链 ID 不一致、无重放保护、
//! EIP-7702、Safe DELEGATECALL、EIP-712 域的链 ID 与请求不一致。强警告：无限额授权、Permit2、
//! setApprovalForAll、未知合约调用、部署合约、未知链、32 字节消息、一切 EIP-712 结构化签名。

use crate::abi::{self, Call};
use crate::chains::{chain_info, token_info, PERMIT2};
use crate::eip712::TypedData;
use crate::keccak::keccak256;
use crate::message::{as_text, personal_hash};
use crate::request::{DataType, SignRequest};
use crate::tx::{parse_legacy, parse_typed, TxKind, UnsignedTx, VStyle};
use crate::typed_review;
use crate::uint::U256;
use crate::{checksum_address, Account, EvmError};
use aw_common::display::{Display, Level, Style};
use aw_common::hex;
use bitcoin::secp256k1::{Secp256k1, Verification};

/// Gas 单价超过 1000 gwei 视为异常
const HIGH_GAS_PRICE_WEI: u64 = 1_000_000_000_000;
/// 优先费超过 100 gwei 视为异常
const HIGH_PRIORITY_FEE_WEI: u64 = 100_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewed {
    pub display: Display,
    /// 要签名的 32 字节哈希
    pub hash: [u8; 32],
    /// 签名用的地址序号（m/44'/60'/0'/0/i）
    pub index: u32,
    pub v_style: VStyle,
}

pub(crate) struct Chain {
    pub(crate) name: String,
    pub(crate) network: String,
    pub(crate) symbol: String,
}

pub(crate) fn chain(id: u64, d: Option<&mut Display>) -> Chain {
    match chain_info(id) {
        Some(c) => {
            if let (Some(d), true) = (d, c.testnet) {
                d.warn(Level::Info, "测试网交易（测试币没有价值）");
            }
            Chain {
                name: c.name.to_owned(),
                network: c.network.to_owned(),
                symbol: c.symbol.to_owned(),
            }
        }
        None => {
            if let Some(d) = d {
                d.warn(
                    Level::Caution,
                    format!("未知链（链 ID {id}）：请确认这正是你要使用的网络，同一笔签名在别的链上无效"),
                );
            }
            Chain {
                name: "EVM".to_owned(),
                network: format!("链 ID {id}"),
                symbol: "原生币".to_owned(),
            }
        }
    }
}

pub(crate) fn amount(v: U256, symbol: &str) -> String {
    format!("{} {symbol}", v.format_units(18))
}

fn gwei(v: U256) -> String {
    format!("{} gwei", v.format_units(9))
}

pub(crate) fn token_amount(chain_id: u64, contract: &[u8; 20], v: U256) -> String {
    match token_info(chain_id, contract) {
        Some(t) => format!("{} {}", v.format_units(t.decimals), t.symbol),
        None => format!("{}（代币精度未知，显示原始数值）", v.to_decimal()),
    }
}

pub(crate) fn contract_label(chain_id: u64, c: &[u8; 20]) -> String {
    match token_info(chain_id, c) {
        Some(t) => format!("{}（{}）", checksum_address(c), t.symbol),
        None => checksum_address(c),
    }
}

/// 额度"极大"：≥ 2^128，或已知代币超过 1 万亿枚（实际上等于无限额）
pub(crate) fn is_huge(chain_id: u64, token: &[u8; 20], v: U256) -> bool {
    /// 2^128 的大端字节
    const TWO_POW_128: [u8; 17] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if U256::from_be_slice(&TWO_POW_128).is_some_and(|limit| v >= limit) {
        return true;
    }
    match token_info(chain_id, token) {
        Some(t) => {
            let mut limit = U256::from_u64(1_000_000_000_000);
            for _ in 0..t.decimals {
                limit = limit.checked_mul(U256::from_u64(10)).unwrap_or(U256::MAX);
            }
            v > limit
        }
        None => true,
    }
}

/// 授权额度的显示与警告。ERC-20 与 ERC-721 的 approve 选择器相同：对未知合约，
/// 数值可能是"额度"也可能是"NFT 编号"，一律按高风险处理，且不显示"撤销"字样。
fn approval_rows(d: &mut Display, chain_id: u64, token: &[u8; 20], a: U256, plain_approve: bool) {
    let known = token_info(chain_id, token).is_some();
    if !known {
        d.row("额度或 NFT 编号", a.to_decimal(), Style::Amount);
        d.warn(
            Level::Danger,
            "未知合约的授权：签名机无法确定这是代币额度还是 NFT 编号。如果是 NFT 合约，被授权方将能转走该编号的 NFT",
        );
        return;
    }
    if a.is_zero() && plain_approve {
        d.row("授权额度", "0（撤销授权）", Style::Amount);
    } else if is_huge(chain_id, token, a) {
        d.row("授权额度", "无限额或接近无限额", Style::Amount);
        d.warn(
            Level::Danger,
            "无限额授权：被授权方可以随时转走你在该代币中的全部余额",
        );
    } else {
        d.row("授权额度", token_amount(chain_id, token, a), Style::Amount);
        d.warn(
            Level::Caution,
            "授权后，被授权方可以在额度内随时转走你的代币",
        );
    }
}

fn data_preview(data: &[u8]) -> String {
    let shown = data.get(..64).unwrap_or(data);
    let more = if data.len() > shown.len() { "…" } else { "" };
    format!("{} 字节：0x{}{more}", data.len(), hex::encode(shown))
}

pub fn review<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    req: &SignRequest,
) -> Result<Reviewed, EvmError> {
    let index = account
        .match_path(&req.path)
        .ok_or(EvmError::PathMismatch)?;
    let own = account.address(secp, index)?;
    if req.address.is_some_and(|a| a != own) {
        return Err(EvmError::AddressMismatch);
    }
    match req.data_type {
        DataType::LegacyTx | DataType::TypedTx => {
            let typed = req.data_type == DataType::TypedTx;
            let tx = if typed {
                parse_typed(&req.sign_data)?
            } else {
                parse_legacy(&req.sign_data)?
            };
            if req.chain_id.is_some_and(|c| c != tx.chain_id) {
                return Err(EvmError::ChainMismatch);
            }
            let display = describe_tx(&tx, &own, index)?;
            Ok(Reviewed {
                display,
                hash: keccak256(&req.sign_data),
                index,
                v_style: if typed {
                    VStyle::Parity
                } else {
                    VStyle::Eip155(tx.chain_id)
                },
            })
        }
        DataType::PersonalMessage => Ok(Reviewed {
            display: describe_message(&req.sign_data, req.chain_id, &own, index),
            hash: personal_hash(&req.sign_data),
            index,
            v_style: VStyle::Legacy27,
        }),
        DataType::TypedData => {
            let json = core::str::from_utf8(&req.sign_data).map_err(|_| EvmError::Parse)?;
            let td = TypedData::parse(json)?;
            let digest = td.digest()?;
            Ok(Reviewed {
                display: typed_review::describe(&td, &digest, req.chain_id, &own, index)?,
                hash: digest.hash,
                index,
                v_style: VStyle::Legacy27,
            })
        }
    }
}

fn describe_message(msg: &[u8], chain_id: Option<u64>, own: &[u8; 20], index: u32) -> Display {
    // personal_sign 的签名与链无关；请求里的链 ID 只是对方的说法，不作为标题
    let mut d = Display::new("EVM", "消息签名", "签名消息（personal_sign）");
    d.row(
        "签名地址",
        format!("{}（地址 #{index}）", checksum_address(own)),
        Style::Address,
    );
    if let Some(id) = chain_id {
        d.row(
            "请求声明的链（未经验证，不影响签名）",
            format!("链 ID {id}"),
            Style::Text,
        );
    }
    match as_text(msg) {
        Some(t) => d.row("消息", t, Style::Text),
        None => {
            d.row(
                "消息（十六进制）",
                format!("0x{}", hex::encode(msg)),
                Style::Data,
            );
            d.warn(
                Level::Caution,
                "消息含有不能安全显示的字符（不可见字符、方向控制符或易混淆的外文字母），只能显示十六进制",
            );
        }
    }
    if msg.len() == 32 {
        d.warn(
            Level::Danger,
            "消息恰好 32 字节，很可能是某笔交易或授权的哈希。签它等于盲签，可能被用来转走资产",
        );
    }
    d.warn(
        Level::Info,
        "消息签名不会直接发送交易，但可能被用作登录凭证或链下授权",
    );
    d
}

fn describe_tx(tx: &UnsignedTx, own: &[u8; 20], index: u32) -> Result<Display, EvmError> {
    let mut d = Display::new("", "", "");
    let c = chain(tx.chain_id, Some(&mut d));
    d.chain = c.name.clone();
    d.network = c.network.clone();
    d.row(
        "网络",
        format!("{} {}（链 ID {}）", c.name, c.network, tx.chain_id),
        Style::Text,
    );
    d.row(
        "发送方",
        format!("{}（地址 #{index}）", checksum_address(own)),
        Style::Address,
    );

    let call = abi::decode(&tx.data)?;
    match (tx.to, &call) {
        (None, _) => {
            d.title = "部署合约".to_owned();
            d.row("合约代码", data_preview(&tx.data), Style::Data);
            d.warn(
                Level::Danger,
                "这笔交易会部署一个新合约：请确认代码来源可信",
            );
        }
        (Some(to), Call::None) => {
            d.title = format!("发送 {}", c.symbol);
            d.row("收款地址", checksum_address(&to), Style::Address);
        }
        (
            Some(token),
            Call::Transfer {
                to: rcpt,
                amount: a,
            },
        ) => {
            d.title = "代币转账".to_owned();
            d.row(
                "代币合约",
                contract_label(tx.chain_id, &token),
                Style::Address,
            );
            d.row("收款地址", checksum_address(rcpt), Style::Address);
            d.row(
                "代币数量",
                token_amount(tx.chain_id, &token, *a),
                Style::Amount,
            );
        }
        (Some(token), Call::Approve { spender, amount: a })
        | (Some(token), Call::IncreaseAllowance { spender, amount: a }) => {
            d.title = if matches!(call, Call::Approve { .. }) {
                "授权"
            } else {
                "增加授权额度"
            }
            .to_owned();
            d.row("合约", contract_label(tx.chain_id, &token), Style::Address);
            d.row("被授权方", checksum_address(spender), Style::Address);
            approval_rows(
                &mut d,
                tx.chain_id,
                &token,
                *a,
                matches!(call, Call::Approve { .. }),
            );
            if *spender == PERMIT2 {
                d.warn(
                    Level::Danger,
                    "授权给 Permit2：之后任何拿到你签名许可的人都能动用这些代币",
                );
            }
        }
        (
            Some(target),
            Call::Permit2Approve {
                token,
                spender,
                amount: a,
            },
        ) => {
            d.title = "Permit2 授权".to_owned();
            d.row("Permit2 合约", checksum_address(&target), Style::Address);
            d.row(
                "代币合约",
                contract_label(tx.chain_id, token),
                Style::Address,
            );
            d.row("被授权方", checksum_address(spender), Style::Address);
            d.row("额度", token_amount(tx.chain_id, token, *a), Style::Amount);
            d.warn(
                Level::Danger,
                "Permit2 授权：被授权方可以在额度和期限内转走你的代币",
            );
        }
        (
            Some(token),
            Call::DaiPermit {
                holder,
                spender,
                allowed,
            },
        ) => {
            d.title = "提交 DAI 式 Permit 授权".to_owned();
            d.row(
                "代币合约",
                contract_label(tx.chain_id, &token),
                Style::Address,
            );
            d.row("授权人", checksum_address(holder), Style::Address);
            d.row("被授权方", checksum_address(spender), Style::Address);
            d.row(
                "授权",
                if *allowed { "无限额" } else { "撤销" },
                Style::Amount,
            );
            if *allowed {
                d.warn(Level::Danger, "DAI 式 permit 一旦生效就是无限额授权");
            }
        }
        (
            Some(token),
            Call::TransferFrom {
                from,
                to: rcpt,
                amount: a,
            },
        ) => {
            d.title = "转出（transferFrom）".to_owned();
            d.row("合约", contract_label(tx.chain_id, &token), Style::Address);
            d.row("转出地址", checksum_address(from), Style::Address);
            d.row("收款地址", checksum_address(rcpt), Style::Address);
            if token_info(tx.chain_id, &token).is_some() {
                d.row(
                    "代币数量",
                    token_amount(tx.chain_id, &token, *a),
                    Style::Amount,
                );
            } else {
                d.row("数量或 NFT 编号", a.to_decimal(), Style::Amount);
                d.warn(
                    Level::Caution,
                    "未知合约：无法确定这是代币数量还是 NFT 编号",
                );
            }
            if from != own {
                d.warn(Level::Caution, "从别人的地址转出（需要对方事先授权给你）");
            }
        }
        (Some(target), Call::SetApprovalForAll { operator, approved }) => {
            d.row("合约", checksum_address(&target), Style::Address);
            d.row("操作方", checksum_address(operator), Style::Address);
            if *approved {
                d.title = "授权管理全部 NFT".to_owned();
                d.warn(
                    Level::Danger,
                    "操作方将能转走你在该合约中的全部 NFT（setApprovalForAll）",
                );
            } else {
                d.title = "撤销 NFT 管理授权".to_owned();
            }
        }
        (
            Some(token),
            Call::Permit {
                owner,
                spender,
                value,
            },
        ) => {
            d.title = "提交 Permit 授权".to_owned();
            d.row(
                "代币合约",
                contract_label(tx.chain_id, &token),
                Style::Address,
            );
            d.row("授权人", checksum_address(owner), Style::Address);
            d.row("被授权方", checksum_address(spender), Style::Address);
            d.row(
                "额度",
                token_amount(tx.chain_id, &token, *value),
                Style::Amount,
            );
            if is_huge(tx.chain_id, &token, *value) {
                d.warn(Level::Danger, "在链上提交一份接近无限额的 permit 授权");
            } else {
                d.warn(Level::Caution, "在链上提交一份 permit 授权");
            }
        }
        (Some(target), Call::Unknown { selector, .. }) => {
            d.title = "合约调用".to_owned();
            d.row("合约地址", checksum_address(&target), Style::Address);
            if let Some(s) = selector {
                d.row("函数选择器", format!("0x{}", hex::encode(s)), Style::Data);
            }
            d.row("调用数据", data_preview(&tx.data), Style::Data);
            d.warn(
                Level::Danger,
                "无法识别的合约调用：签名机看不懂它会做什么。只有完全信任该合约和这次操作时才继续",
            );
        }
    }
    if tx.to == Some(PERMIT2) {
        d.warn(Level::Danger, "目标是 Permit2 合约：请确认你了解这次操作");
    }
    if !tx.value.is_zero() || matches!(call, Call::None) {
        d.row("金额", amount(tx.value, &c.symbol), Style::Amount);
    }
    if !tx.value.is_zero() && !matches!(call, Call::None) && tx.to.is_some() {
        d.warn(
            Level::Caution,
            format!("这次调用同时转出 {}", amount(tx.value, &c.symbol)),
        );
    }
    fee_rows(&mut d, tx, &c.symbol)?;
    Ok(d)
}

fn fee_rows(d: &mut Display, tx: &UnsignedTx, symbol: &str) -> Result<(), EvmError> {
    let max_fee = tx.max_fee()?;
    d.row("最高手续费", amount(max_fee, symbol), Style::Amount);
    match tx.kind {
        TxKind::DynamicFee => {
            d.row("最高 Gas 单价", gwei(tx.gas_price), Style::Text);
            if let Some(p) = tx.max_priority_fee {
                d.row("优先费", gwei(p), Style::Text);
            }
        }
        TxKind::Legacy | TxKind::AccessList => d.row("Gas 单价", gwei(tx.gas_price), Style::Text),
    }
    d.row("Gas 上限", tx.gas_limit.to_string(), Style::Text);
    d.row("Nonce", tx.nonce.to_string(), Style::Text);
    if tx.access_list_entries > 0 {
        d.row(
            "访问列表",
            format!("{} 项", tx.access_list_entries),
            Style::Text,
        );
    }
    if tx.gas_price > U256::from_u64(HIGH_GAS_PRICE_WEI) {
        d.warn(
            Level::Caution,
            format!("Gas 单价异常高（{}）", gwei(tx.gas_price)),
        );
    }
    if tx
        .max_priority_fee
        .is_some_and(|p| p > U256::from_u64(HIGH_PRIORITY_FEE_WEI))
    {
        d.warn(
            Level::Caution,
            "优先费异常高（超过 100 gwei）：节点给出的建议值可能有问题",
        );
    }
    // 原生币转账：手续费上限超过金额的 10%
    if !tx.value.is_zero() && tx.data.is_empty() {
        let ten_x = max_fee
            .checked_mul(U256::from_u64(10))
            .ok_or(EvmError::Overflow)?;
        if ten_x > tx.value {
            d.warn(Level::Caution, "最高手续费超过转账金额的 10%");
        }
    }
    Ok(())
}
