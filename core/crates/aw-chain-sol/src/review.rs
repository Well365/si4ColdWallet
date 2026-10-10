//! Solana 交易审查（P2c-T2，决策 D37）：从待签消息重新解析出全部内容，生成通用显示模型。
//!
//! 默认拒签（返回错误）：消息无法严格解析；v0 地址查找表（被引用的地址离线无法核实）；本账户不是签名者；
//! System `Assign` / `AssignWithSeed`（改账户归属程序）；SPL Token `SetAuthority`；关联代币账户地址与推导不符。
//! 强警告：未知程序、未知代币、代币授权、关闭代币账户、durable nonce、不常见的指令、手续费过高。
//! 手续费 = 5000 lamports × 签名数 + 计算单元价格 × 计算单元上限 / 10⁶（向上取整）。

use crate::message::Message;
use crate::programs::{
    associated_token_account, known_token, ATA, COMPUTE_BUDGET, MEMO, SYSTEM, TOKEN, TOKEN_2022,
};
use crate::{address, SolError};
use aw_common::display::{Display, Level, Style};

/// 每个签名的基础手续费
pub const BASE_FEE_PER_SIGNATURE: u64 = 5_000;
/// 没有设置计算单元上限时，每条非 ComputeBudget 指令默认 20 万，整笔最多 140 万
const DEFAULT_UNITS_PER_INSTRUCTION: u64 = 200_000;
const MAX_UNITS: u64 = 1_400_000;
/// 手续费超过 0.01 SOL 即高风险
pub const HIGH_FEE_LAMPORTS: u64 = 10_000_000;
/// 新建代币账户（165 字节）的免租押金；关闭账户时可取回
pub const ATA_RENT_LAMPORTS: u64 = 2_039_280;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewed {
    pub display: Display,
    /// 最高手续费（lamports）
    pub fee: u64,
    /// 从本账户转出的 SOL（不含手续费、押金）
    pub native_out: u64,
    /// 本账户可能要付的新建代币账户押金
    pub rent_deposit: u64,
}

/// 无符号整数按小数位显示（不四舍五入，去掉末尾的 0）
pub fn units(v: u64, decimals: u8) -> String {
    let s = v.to_string();
    let d = usize::from(decimals);
    if d == 0 {
        return s;
    }
    let padded = if s.len() <= d {
        format!("{}{}", "0".repeat(d + 1 - s.len()), s)
    } else {
        s
    };
    let (int, frac) = padded.split_at(padded.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int.to_owned()
    } else {
        format!("{int}.{frac}")
    }
}

pub fn sol(lamports: u64) -> String {
    format!("{} SOL", units(lamports, 9))
}

/// 备注文字：只按文字显示可打印 ASCII 与常用中文，其余显示十六进制
fn safe_text(b: &[u8]) -> Option<&str> {
    let s = core::str::from_utf8(b).ok()?;
    s.chars()
        .all(
            |c| matches!(c, ' '..='~' | '\u{4e00}'..='\u{9fff}' | '，' | '。' | '：' | '！' | '？'),
        )
        .then_some(s)
}

fn u64_at(data: &[u8], at: usize) -> Result<u64, SolError> {
    let b: [u8; 8] = data
        .get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or(SolError::Parse)?;
    Ok(u64::from_le_bytes(b))
}

struct Ctx<'a> {
    m: &'a Message,
    own: &'a [u8; 32],
    d: Display,
    native_out: u64,
    rent_deposit: u64,
    /// 交易中"按需创建关联代币账户"指令登记的（代币账户 → 钱包）
    created_atas: Vec<([u8; 32], [u8; 32])>,
    ops: Vec<&'static str>,
}

impl Ctx<'_> {
    fn acct(&self, ix: &crate::message::Instruction, n: usize) -> Result<[u8; 32], SolError> {
        let i = *ix.accounts.get(n).ok_or(SolError::Parse)?;
        self.m.key(i).copied().ok_or(SolError::Parse)
    }

    fn add_out(&mut self, lamports: u64) -> Result<(), SolError> {
        self.native_out = self
            .native_out
            .checked_add(lamports)
            .ok_or(SolError::Overflow)?;
        Ok(())
    }
}

pub fn review(msg: &[u8], own: &[u8; 32]) -> Result<Reviewed, SolError> {
    let m = Message::parse(msg)?;
    if !m.lookups.is_empty() {
        return Err(SolError::LookupTable);
    }
    let own_idx = m
        .account_keys
        .iter()
        .position(|k| k == own)
        .filter(|&i| m.is_signer(i))
        .ok_or(SolError::NotSigner)?;
    let (unit_limit, unit_price) = compute_budget(&m)?;
    let mut c = Ctx {
        m: &m,
        own,
        d: Display::new("Solana", "", "Solana 交易"),
        native_out: 0,
        rent_deposit: 0,
        created_atas: Vec::new(),
        ops: Vec::new(),
    };
    c.d.network = "由最近区块哈希决定（交易里没有网络标识）".to_owned();
    c.d.row("签名地址", address(own), Style::Address);
    let payer = *m.account_keys.first().ok_or(SolError::Parse)?;
    if own_idx != 0 {
        c.d.row("手续费付款人", address(&payer), Style::Address);
        c.d.warn(
            Level::Caution,
            "手续费由另一个账户支付：这笔交易还需要它的签名",
        );
    }
    // 先登记关联代币账户的创建（代币转账要用它核对收款人）
    for ix in &m.instructions {
        if m.key(ix.program) == Some(&ATA) {
            register_ata(&mut c, ix)?;
        }
    }
    for (n, ix) in m.instructions.iter().enumerate() {
        let program = *m.key(ix.program).ok_or(SolError::Parse)?;
        let label = format!("第 {} 项", n + 1);
        match program {
            p if p == COMPUTE_BUDGET => {}
            p if p == SYSTEM => system(&mut c, ix, &label)?,
            p if p == TOKEN || p == TOKEN_2022 => token(&mut c, ix, &label, &p)?,
            p if p == ATA => ata_row(&mut c, ix, &label)?,
            p if p == MEMO => memo(&mut c, ix, &label),
            p => {
                c.d.row(&label, format!("未知程序 {}", address(&p)), Style::Address);
                c.d.row("　数据", aw_common::hex::encode(&ix.data), Style::Data);
                c.d.warn(
                    Level::Danger,
                    format!(
                        "{label}调用未知程序：签名机看不懂它会做什么。只有完全信任这个程序时才继续"
                    ),
                );
                c.ops.push("合约调用");
            }
        }
    }
    let fee = fee(&m, unit_limit, unit_price)?;
    c.d.row("最近区块哈希", address(&m.recent_blockhash), Style::Data);
    c.d.row("最高手续费", sol(fee), Style::Fee);
    if let Some(p) = unit_price.filter(|&p| p > 0) {
        c.d.row(
            "　其中优先费",
            format!(
                "{}（计算单元价格 {} 微 lamports × 上限 {}）",
                sol(fee - BASE_FEE_PER_SIGNATURE * u64::from(m.required_signatures)),
                p,
                effective_units(&m, unit_limit)
            ),
            Style::Fee,
        );
    }
    if fee > HIGH_FEE_LAMPORTS {
        c.d.warn(
            Level::Danger,
            format!(
                "最高手续费超过 {}：请确认优先费没有被改大",
                sol(HIGH_FEE_LAMPORTS)
            ),
        );
    }
    let total = c.native_out.checked_add(fee).ok_or(SolError::Overflow)?;
    c.d.row(
        if c.native_out == 0 {
            "最多扣除（仅手续费）"
        } else {
            "总计最多扣除（金额 + 最高手续费）"
        },
        sol(total),
        Style::Amount,
    );
    if c.rent_deposit > 0 {
        c.d.row(
            "　可能另需押金",
            format!(
                "{}（为收款方新建代币账户；账户已存在则不收）",
                sol(c.rent_deposit)
            ),
            Style::Fee,
        );
    }
    let others = usize::from(m.required_signatures).saturating_sub(1);
    if others > 0 {
        c.d.warn(
            Level::Caution,
            format!("这笔交易还需要另外 {others} 个签名才能上链"),
        );
    }
    c.d.title = match c.ops.as_slice() {
        [one] => (*one).to_owned(),
        [] => "Solana 交易（只设置手续费）".to_owned(),
        _ => "Solana 交易（多项操作）".to_owned(),
    };
    Ok(Reviewed {
        display: c.d,
        fee,
        native_out: c.native_out,
        rent_deposit: c.rent_deposit,
    })
}

/// ComputeBudget：上限与价格各最多出现一次（与节点规则相同）
fn compute_budget(m: &Message) -> Result<(Option<u32>, Option<u64>), SolError> {
    let (mut limit, mut price) = (None, None);
    for ix in &m.instructions {
        if m.key(ix.program) != Some(&COMPUTE_BUDGET) {
            continue;
        }
        match ix.data.split_first() {
            Some((2, rest)) if rest.len() == 4 && limit.is_none() => {
                let b: [u8; 4] = rest.try_into().map_err(|_| SolError::Parse)?;
                limit = Some(u32::from_le_bytes(b));
            }
            Some((3, rest)) if rest.len() == 8 && price.is_none() => {
                price = Some(u64_at(rest, 0)?);
            }
            _ => return Err(SolError::Parse),
        }
    }
    Ok((limit, price))
}

fn effective_units(m: &Message, limit: Option<u32>) -> u64 {
    limit.map_or_else(
        || {
            let n = m
                .instructions
                .iter()
                .filter(|ix| m.key(ix.program) != Some(&COMPUTE_BUDGET))
                .count() as u64;
            (n * DEFAULT_UNITS_PER_INSTRUCTION).min(MAX_UNITS)
        },
        |l| u64::from(l).min(MAX_UNITS),
    )
}

/// 最高手续费：基础费 + ⌈价格 × 上限 / 10⁶⌉
pub fn fee(m: &Message, limit: Option<u32>, price: Option<u64>) -> Result<u64, SolError> {
    let base = BASE_FEE_PER_SIGNATURE
        .checked_mul(u64::from(m.required_signatures))
        .ok_or(SolError::Overflow)?;
    let units = u128::from(effective_units(m, limit));
    let prio = (u128::from(price.unwrap_or(0)) * units).div_ceil(1_000_000);
    let prio = u64::try_from(prio).map_err(|_| SolError::Overflow)?;
    base.checked_add(prio).ok_or(SolError::Overflow)
}

fn system(c: &mut Ctx<'_>, ix: &crate::message::Instruction, label: &str) -> Result<(), SolError> {
    let tag: [u8; 4] = ix
        .data
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .ok_or(SolError::Parse)?;
    match u32::from_le_bytes(tag) {
        // Transfer
        2 if ix.data.len() == 12 => {
            let from = c.acct(ix, 0)?;
            let to = c.acct(ix, 1)?;
            let l = u64_at(&ix.data, 4)?;
            c.d.row(label, "转账 SOL", Style::Text);
            c.d.row("　收款地址", address(&to), Style::Address);
            c.d.row("　金额", sol(l), Style::Amount);
            if from == *c.own {
                c.add_out(l)?;
            } else {
                c.d.row("　转出地址", address(&from), Style::Address);
                c.d.warn(Level::Caution, format!("{label}从另一个账户转出"));
            }
            c.ops.push("发送 SOL");
        }
        // CreateAccount
        0 if ix.data.len() == 52 => {
            let from = c.acct(ix, 0)?;
            let new = c.acct(ix, 1)?;
            let l = u64_at(&ix.data, 4)?;
            let owner: [u8; 32] = ix
                .data
                .get(20..52)
                .and_then(|s| s.try_into().ok())
                .ok_or(SolError::Parse)?;
            c.d.row(label, "创建新账户", Style::Text);
            c.d.row("　新账户", address(&new), Style::Address);
            c.d.row("　存入", sol(l), Style::Amount);
            c.d.row("　归属程序", address(&owner), Style::Address);
            if from == *c.own {
                c.add_out(l)?;
            }
            let level = if owner == SYSTEM || owner == TOKEN || owner == TOKEN_2022 {
                Level::Caution
            } else {
                Level::Danger
            };
            c.d.warn(level, format!("{label}创建新账户并存入 {}", sol(l)));
            c.ops.push("创建账户");
        }
        // Assign / AssignWithSeed：改变账户归属的程序，等于把账户交给那个程序处置
        1 | 10 => return Err(SolError::OwnerChange),
        // AdvanceNonceAccount
        4 => {
            c.d.row(label, "推进 durable nonce", Style::Text);
            c.d.warn(
                Level::Danger,
                "这是 durable nonce 交易：它不会过期，拿到签名的人可以在任何时候提交",
            );
            c.ops.push("durable nonce");
        }
        n => {
            c.d.row(label, format!("系统指令 {n}"), Style::Text);
            c.d.row("　数据", aw_common::hex::encode(&ix.data), Style::Data);
            c.d.warn(
                Level::Danger,
                format!("{label}是不常见的系统指令（编号 {n}），请确认你了解它"),
            );
            c.ops.push("系统指令");
        }
    }
    Ok(())
}

fn register_ata(c: &mut Ctx<'_>, ix: &crate::message::Instruction) -> Result<(), SolError> {
    match ix.data.as_slice() {
        [] | [0] | [1] => {}
        _ => return Ok(()), // 其他 ATA 指令在 ata_row 里按"不常见"处理
    }
    let ata = c.acct(ix, 1)?;
    let owner = c.acct(ix, 2)?;
    let mint = c.acct(ix, 3)?;
    let token_program = c.acct(ix, 5)?;
    if token_program != TOKEN && token_program != TOKEN_2022 {
        return Err(SolError::Parse);
    }
    // 地址必须就是 (钱包, 代币程序, mint) 推导出的关联代币账户，否则链上也会失败，直接拒签
    if associated_token_account(&owner, &mint, &token_program) != Some(ata) {
        return Err(SolError::Parse);
    }
    c.created_atas.push((ata, owner));
    Ok(())
}

fn ata_row(c: &mut Ctx<'_>, ix: &crate::message::Instruction, label: &str) -> Result<(), SolError> {
    match ix.data.as_slice() {
        [] | [0] | [1] => {
            let payer = c.acct(ix, 0)?;
            let owner = c.acct(ix, 2)?;
            c.d.row(label, "为收款方建立代币账户（已存在则跳过）", Style::Text);
            c.d.row("　代币账户所属钱包", address(&owner), Style::Address);
            if payer == *c.own {
                c.rent_deposit = c
                    .rent_deposit
                    .checked_add(ATA_RENT_LAMPORTS)
                    .ok_or(SolError::Overflow)?;
            }
        }
        _ => {
            c.d.row(label, "关联代币账户程序的其他指令", Style::Text);
            c.d.warn(Level::Danger, format!("{label}是不常见的关联代币账户指令"));
            c.ops.push("合约调用");
        }
    }
    Ok(())
}

fn token(
    c: &mut Ctx<'_>,
    ix: &crate::message::Instruction,
    label: &str,
    program: &[u8; 32],
) -> Result<(), SolError> {
    let (&tag, rest) = ix.data.split_first().ok_or(SolError::Parse)?;
    match tag {
        // TransferChecked
        12 if rest.len() == 9 => {
            let source = c.acct(ix, 0)?;
            let mint = c.acct(ix, 1)?;
            let dest = c.acct(ix, 2)?;
            let authority = c.acct(ix, 3)?;
            let amount = u64_at(rest, 0)?;
            let decimals = *rest.get(8).ok_or(SolError::Parse)?;
            c.d.row(label, "代币转账", Style::Text);
            match known_token(&mint) {
                Some(t) if t.decimals == decimals => {
                    c.d.row(
                        "　代币",
                        format!("{}（{}）", t.symbol, address(&mint)),
                        Style::Address,
                    );
                    c.d.row(
                        "　数量",
                        format!("{} {}", units(amount, decimals), t.symbol),
                        Style::Amount,
                    );
                }
                Some(t) => {
                    c.d.row(
                        "　代币",
                        format!("{}（{}）", t.symbol, address(&mint)),
                        Style::Address,
                    );
                    c.d.row("　数量（原始数值）", amount.to_string(), Style::Amount);
                    c.d.warn(
                        Level::Danger,
                        format!(
                            "{label}的小数位 {decimals} 与 {} 的 {} 不符",
                            t.symbol, t.decimals
                        ),
                    );
                }
                None => {
                    c.d.row("　代币 mint", address(&mint), Style::Address);
                    c.d.row("　数量", units(amount, decimals), Style::Amount);
                    c.d.warn(
                        Level::Danger,
                        format!(
                            "{label}是未知代币：签名机无法确认它的名称与价值，请核对 mint 地址"
                        ),
                    );
                }
            }
            recipient_rows(c, &dest)?;
            if authority != *c.own {
                c.d.warn(Level::Caution, format!("{label}的代币授权人不是本账户"));
            } else if associated_token_account(c.own, &mint, program) != Some(source) {
                c.d.row("　转出代币账户", address(&source), Style::Address);
                c.d.warn(Level::Caution, format!("{label}从非默认的代币账户转出"));
            }
            c.ops.push("代币转账");
        }
        // Transfer（不带 mint 与小数位）
        3 if rest.len() == 8 => {
            let dest = c.acct(ix, 1)?;
            c.d.row(label, "代币转账（未标明代币种类）", Style::Text);
            c.d.row(
                "　数量（最小单位）",
                u64_at(rest, 0)?.to_string(),
                Style::Amount,
            );
            recipient_rows(c, &dest)?;
            c.d.warn(
                Level::Caution,
                format!("{label}没有标明代币种类与小数位：签名机只能显示原始数量"),
            );
            c.ops.push("代币转账");
        }
        // Approve / ApproveChecked
        4 | 13 => {
            let delegate = c.acct(ix, if tag == 4 { 1 } else { 2 })?;
            c.d.row(label, "代币授权", Style::Text);
            c.d.row("　被授权方", address(&delegate), Style::Address);
            c.d.row(
                "　额度（最小单位）",
                u64_at(rest, 0)?.to_string(),
                Style::Amount,
            );
            c.d.warn(
                Level::Danger,
                format!("{label}授权他人动用你的代币：被授权方可以在额度内随时转走"),
            );
            c.ops.push("代币授权");
        }
        // Revoke
        5 => {
            c.d.row(label, "撤销代币授权", Style::Text);
            c.ops.push("撤销授权");
        }
        // SetAuthority：把代币账户或 mint 的控制权交给别人
        6 => return Err(SolError::SetAuthority),
        // CloseAccount
        9 => {
            let account = c.acct(ix, 0)?;
            let dest = c.acct(ix, 1)?;
            c.d.row(label, "关闭代币账户", Style::Text);
            c.d.row("　代币账户", address(&account), Style::Address);
            c.d.row("　押金退给", address(&dest), Style::Address);
            let level = if dest == *c.own {
                Level::Caution
            } else {
                Level::Danger
            };
            c.d.warn(
                level,
                format!("{label}关闭代币账户，账户里的押金退给上面的地址"),
            );
            c.ops.push("关闭代币账户");
        }
        // SyncNative
        17 => {
            c.d.row(label, "同步 wSOL 余额", Style::Text);
            c.ops.push("同步余额");
        }
        n => {
            c.d.row(label, format!("代币程序指令 {n}"), Style::Text);
            c.d.row("　数据", aw_common::hex::encode(&ix.data), Style::Data);
            c.d.warn(
                Level::Danger,
                format!("{label}是不常见的代币指令（编号 {n}），请确认你了解它"),
            );
            c.ops.push("代币指令");
        }
    }
    Ok(())
}

/// 收款方：同一笔交易里"按需创建关联代币账户"登记过、且推导核对一致时，显示钱包地址；否则只能显示代币账户
fn recipient_rows(c: &mut Ctx<'_>, dest: &[u8; 32]) -> Result<(), SolError> {
    match c.created_atas.iter().find(|(a, _)| a == dest) {
        Some((_, owner)) => {
            let owner = *owner;
            c.d.row("　收款人", address(&owner), Style::Address);
            c.d.row(
                "　收款代币账户（已核对归属）",
                address(dest),
                Style::Address,
            );
        }
        None => {
            c.d.row("　收款代币账户", address(dest), Style::Address);
            c.d.warn(
                Level::Caution,
                "签名机无法核对收款代币账户属于谁：请在观察机上核对收款人",
            );
        }
    }
    Ok(())
}

fn memo(c: &mut Ctx<'_>, ix: &crate::message::Instruction, label: &str) {
    match safe_text(&ix.data) {
        Some(t) => c.d.row(label, format!("备注：{t}"), Style::Text),
        None => {
            c.d.row(
                label,
                format!("备注（十六进制）：{}", aw_common::hex::encode(&ix.data)),
                Style::Data,
            );
            c.d.warn(
                Level::Caution,
                format!("{label}的备注含有不能安全显示的字符"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::programs::*;

    const OWN: [u8; 32] = [0x11; 32];
    const BOB: [u8; 32] = [0x22; 32];
    const BH: [u8; 32] = [0x33; 32];

    fn msg(ixs: &[Ix]) -> Vec<u8> {
        compile_legacy(&OWN, ixs, &BH).unwrap()
    }

    fn danger(r: &Reviewed, needle: &str) -> bool {
        r.display
            .warnings
            .iter()
            .any(|w| w.level == Level::Danger && w.text.contains(needle))
    }

    fn row<'a>(r: &'a Reviewed, label: &str) -> Option<&'a str> {
        r.display
            .rows
            .iter()
            .find(|x| x.label == label)
            .map(|x| x.value.as_str())
    }

    #[test]
    fn units_format() {
        assert_eq!(units(1_500_000_000, 9), "1.5");
        assert_eq!(units(1, 9), "0.000000001");
        assert_eq!(units(0, 6), "0");
        assert_eq!(units(12_345, 0), "12345");
    }

    #[test]
    fn sol_transfer_with_priority_fee() {
        let m = msg(&[
            compute_unit_limit(450),
            compute_unit_price(2_000_000),
            system_transfer(&OWN, &BOB, 1_500_000_000),
        ]);
        let r = review(&m, &OWN).unwrap();
        // 5000 + ⌈2_000_000 × 450 / 10⁶⌉ = 5000 + 900
        assert_eq!(r.fee, 5_900);
        assert_eq!(r.native_out, 1_500_000_000);
        assert_eq!(r.display.title, "发送 SOL");
        assert_eq!(row(&r, "　金额"), Some("1.5 SOL"));
        assert_eq!(row(&r, "最高手续费"), Some("0.0000059 SOL"));
        assert_eq!(
            row(&r, "总计最多扣除（金额 + 最高手续费）"),
            Some("1.5000059 SOL")
        );
        assert!(!r.display.has_danger(), "{:?}", r.display.warnings);
    }

    #[test]
    fn default_compute_units_when_limit_missing() {
        let m = msg(&[
            compute_unit_price(1_000_000),
            system_transfer(&OWN, &BOB, 1),
        ]);
        // 1 条非 ComputeBudget 指令 → 20 万单元 → 优先费 200 000 lamports
        assert_eq!(review(&m, &OWN).unwrap().fee, 205_000);
    }

    #[test]
    fn token_transfer_with_verified_recipient() {
        let usdc = KNOWN_TOKENS[0].mint;
        let src = associated_token_account(&OWN, &usdc, &TOKEN).unwrap();
        let dst = associated_token_account(&BOB, &usdc, &TOKEN).unwrap();
        let m = msg(&[
            create_ata_idempotent(&OWN, &dst, &BOB, &usdc, &TOKEN),
            token_transfer_checked(&TOKEN, &src, &usdc, &dst, &OWN, 12_500_000, 6),
        ]);
        let r = review(&m, &OWN).unwrap();
        assert_eq!(row(&r, "　数量"), Some("12.5 USDC"));
        assert_eq!(row(&r, "　收款人"), Some(address(&BOB).as_str()));
        assert_eq!(r.rent_deposit, ATA_RENT_LAMPORTS);
        assert_eq!(r.native_out, 0);
        assert!(!r.display.has_danger(), "{:?}", r.display.warnings);
        assert_eq!(r.display.title, "代币转账");
    }

    #[test]
    fn token_transfer_without_create_cannot_verify_recipient() {
        let usdc = KNOWN_TOKENS[0].mint;
        let src = associated_token_account(&OWN, &usdc, &TOKEN).unwrap();
        let m = msg(&[token_transfer_checked(
            &TOKEN,
            &src,
            &usdc,
            &[0x44; 32],
            &OWN,
            1,
            6,
        )]);
        let r = review(&m, &OWN).unwrap();
        assert!(row(&r, "　收款人").is_none());
        assert!(r
            .display
            .warnings
            .iter()
            .any(|w| w.text.contains("无法核对收款代币账户")));
    }

    #[test]
    fn forged_ata_and_dangerous_instructions_are_refused() {
        let usdc = KNOWN_TOKENS[0].mint;
        // 声称是 BOB 的关联代币账户，其实不是
        let fake = create_ata_idempotent(&OWN, &[0x55; 32], &BOB, &usdc, &TOKEN);
        assert_eq!(review(&msg(&[fake]), &OWN), Err(SolError::Parse));
        // System Assign
        let mut assign = system_transfer(&OWN, &BOB, 0);
        assign.data = 1u32
            .to_le_bytes()
            .iter()
            .copied()
            .chain([7u8; 32])
            .collect();
        assign.accounts.truncate(1);
        assert_eq!(review(&msg(&[assign]), &OWN), Err(SolError::OwnerChange));
        // SPL SetAuthority
        let set_auth = Ix {
            program: TOKEN,
            accounts: vec![
                AccountMeta::new([0x66; 32], false, true),
                AccountMeta::new(OWN, true, false),
            ],
            data: vec![6, 2, 0],
        };
        assert_eq!(review(&msg(&[set_auth]), &OWN), Err(SolError::SetAuthority));
        // 不是签名者
        assert_eq!(
            review(&msg(&[system_transfer(&OWN, &BOB, 1)]), &BOB),
            Err(SolError::NotSigner)
        );
        // 重复的 ComputeBudget 指令
        assert_eq!(
            review(&msg(&[compute_unit_price(1), compute_unit_price(2)]), &OWN),
            Err(SolError::Parse)
        );
    }

    #[test]
    fn strong_warnings() {
        let usdc = KNOWN_TOKENS[0].mint;
        let src = associated_token_account(&OWN, &usdc, &TOKEN).unwrap();
        // 未知程序
        let unknown = Ix {
            program: [0x77; 32],
            accounts: vec![],
            data: vec![1, 2, 3],
        };
        assert!(danger(&review(&msg(&[unknown]), &OWN).unwrap(), "未知程序"));
        // 未知代币
        let r = review(
            &msg(&[token_transfer_checked(
                &TOKEN,
                &[0x88; 32],
                &[0x99; 32],
                &[0x44; 32],
                &OWN,
                1,
                6,
            )]),
            &OWN,
        )
        .unwrap();
        assert!(danger(&r, "未知代币"));
        // 小数位与已知代币不符
        let r = review(
            &msg(&[token_transfer_checked(
                &TOKEN,
                &src,
                &usdc,
                &[0x44; 32],
                &OWN,
                1,
                9,
            )]),
            &OWN,
        )
        .unwrap();
        assert!(danger(&r, "小数位"));
        // 代币授权
        let approve = Ix {
            program: TOKEN,
            accounts: vec![
                AccountMeta::new(src, false, true),
                AccountMeta::new(BOB, false, false),
                AccountMeta::new(OWN, true, false),
            ],
            data: [vec![4], 5u64.to_le_bytes().to_vec()].concat(),
        };
        assert!(danger(&review(&msg(&[approve]), &OWN).unwrap(), "授权"));
        // durable nonce
        let nonce = Ix {
            program: SYSTEM,
            accounts: vec![
                AccountMeta::new([0x45; 32], false, true),
                AccountMeta::new(SYSVAR_RECENT_BLOCKHASHES, false, false),
                AccountMeta::new(OWN, true, false),
            ],
            data: 4u32.to_le_bytes().to_vec(),
        };
        assert!(danger(
            &review(&msg(&[nonce, system_transfer(&OWN, &BOB, 1)]), &OWN).unwrap(),
            "durable nonce"
        ));
        // 手续费过高：价格 10⁸ 微 lamports × 20 万单元 = 0.02 SOL
        let r = review(
            &msg(&[
                compute_unit_price(100_000_000),
                system_transfer(&OWN, &BOB, 1),
            ]),
            &OWN,
        )
        .unwrap();
        assert!(danger(&r, "最高手续费超过"));
        // 备注
        let memo = Ix {
            program: MEMO,
            accounts: vec![],
            data: b"invoice 42".to_vec(),
        };
        let r = review(&msg(&[memo, system_transfer(&OWN, &BOB, 1)]), &OWN).unwrap();
        assert!(r.display.rows.iter().any(|x| x.value == "备注：invoice 42"));
    }

    /// 审查是签名机处理不可信输入的第一道门：任意截断与逐字节改动都不能 panic
    #[test]
    fn never_panics_on_mutations() {
        let usdc = KNOWN_TOKENS[0].mint;
        let src = associated_token_account(&OWN, &usdc, &TOKEN).unwrap();
        let dst = associated_token_account(&BOB, &usdc, &TOKEN).unwrap();
        let good = msg(&[
            compute_unit_limit(50_000),
            compute_unit_price(1_000),
            create_ata_idempotent(&OWN, &dst, &BOB, &usdc, &TOKEN),
            token_transfer_checked(&TOKEN, &src, &usdc, &dst, &OWN, 7, 6),
            system_transfer(&OWN, &BOB, 9),
        ]);
        for cut in 0..=good.len() {
            let _ = review(&good[..cut], &OWN);
        }
        for i in 0..good.len() {
            for v in [0u8, 1, 2, 3, 4, 6, 9, 12, 0x7f, 0x80, 0xff] {
                let mut t = good.clone();
                t[i] = v;
                let _ = review(&t, &OWN);
            }
        }
    }
}
