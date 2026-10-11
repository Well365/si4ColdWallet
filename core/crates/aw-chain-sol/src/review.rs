//! Solana 交易审查（P2c-T2，决策 D37）：从待签消息重新解析出全部内容，生成通用显示模型。
//!
//! 默认拒签（返回错误）：消息无法严格解析；v0 地址查找表（被引用的地址离线无法核实）；本账户不是签名者；
//! System `Assign` / `AssignWithSeed`（改账户归属程序）；SPL Token `SetAuthority`；关联代币账户地址与推导不符。
//! 强警告：未知程序、未知代币、代币授权、关闭代币账户、durable nonce、不常见的指令、手续费过高。
//! 手续费 = 5000 lamports × 签名数 + 计算单元价格 × 计算单元上限 / 10⁶（向上取整）。

use crate::message::Message;
use crate::programs::{
    associated_token_account, known_token, ATA, COMPUTE_BUDGET, MEMO, SIG_PRECOMPILES, SYSTEM,
    TOKEN, TOKEN_2022,
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
/// Token-2022 的关联代币账户带 ImmutableOwner 扩展（170 字节）的免租押金
pub const ATA_2022_RENT_LAMPORTS: u64 = 2_074_080;

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
    /// 有用到本账户、但签名机没有完全解析的指令：这时"最多扣除"无法确定
    uncertain: bool,
}

impl Ctx<'_> {
    fn acct(&self, ix: &crate::message::Instruction, n: usize) -> Result<[u8; 32], SolError> {
        let i = *ix.accounts.get(n).ok_or(SolError::Parse)?;
        self.m.key(i).copied().ok_or(SolError::Parse)
    }

    fn involves_own(&self, ix: &crate::message::Instruction) -> bool {
        ix.accounts.iter().any(|&i| self.m.key(i) == Some(self.own))
    }

    /// 没有完全解析的指令：列出它用到的全部账户；用到本账户时"最多扣除"标为无法确定
    fn undecoded(&mut self, ix: &crate::message::Instruction) {
        for (n, &i) in ix.accounts.iter().enumerate() {
            let who = self
                .m
                .key(i)
                .map_or_else(|| "（地址查找表）".to_owned(), address);
            let mark = if self.m.key(i) == Some(self.own) {
                "（本账户）"
            } else {
                ""
            };
            self.d.row(
                &format!("　账户 {}", n + 1),
                format!("{who}{mark}"),
                Style::Address,
            );
        }
        if self.involves_own(ix) {
            self.uncertain = true;
        }
    }

    /// 指令数据比解析需要的长：节点会忽略多余字节照常执行，签名机按前缀解析并提醒
    fn trailing(&mut self, label: &str, extra: usize) {
        if extra > 0 {
            self.d.warn(
                Level::Caution,
                format!("{label}的指令数据末尾有 {extra} 个多余字节（节点会忽略它们）"),
            );
        }
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
        uncertain: false,
    };
    c.d.network = "由最近区块哈希决定（交易里没有网络标识）".to_owned();
    c.d.warn(
        Level::Caution,
        "签名机无法从交易判断是主网还是测试网：请核对下面的最近区块哈希与观察机显示的一致",
    );
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
                c.undecoded(ix);
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
    // 本账户付手续费时才计入；押金只在收款方代币账户不存在时才收，按最坏情况计入
    let own_fee = if own_idx == 0 { fee } else { 0 };
    let total = c
        .native_out
        .checked_add(own_fee)
        .and_then(|t| t.checked_add(c.rent_deposit))
        .ok_or(SolError::Overflow)?;
    let label = match (c.uncertain, c.native_out > 0, c.rent_deposit > 0) {
        (true, _, _) => "最多扣除：无法确定（含未完全解析、用到本账户的指令）",
        (false, true, true) => "总计最多扣除（金额 + 最高手续费 + 可能的押金）",
        (false, true, false) => "总计最多扣除（金额 + 最高手续费）",
        (false, false, true) => "最多扣除（手续费 + 可能的押金）",
        (false, false, false) => "最多扣除（仅手续费）",
    };
    let value = if c.uncertain {
        format!("至少 {}", sol(total))
    } else {
        sol(total)
    };
    c.d.row(label, value, Style::Amount);
    if c.uncertain {
        c.d.warn(
            Level::Danger,
            "这笔交易里有签名机无法完全解析、又用到本账户的指令：它可能动用本账户的资产，最多扣除多少无法确定",
        );
    }
    if c.rent_deposit > 0 {
        c.d.row(
            "　其中可能的押金",
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
    // 标题按主要操作取：建立代币账户、备注只是附带的（除非交易里只有它们）
    let main: Vec<&str> = c
        .ops
        .iter()
        .copied()
        .filter(|o| !matches!(*o, "建立代币账户" | "备注"))
        .collect();
    let ops = if main.is_empty() { c.ops.clone() } else { main };
    c.d.title = match ops.as_slice() {
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

/// 最高手续费：(交易签名数 + 预编译程序校验的签名数) × 5000 + ⌈价格 × 上限 / 10⁶⌉
pub fn fee(m: &Message, limit: Option<u32>, price: Option<u64>) -> Result<u64, SolError> {
    let precompile_sigs: u64 = m
        .instructions
        .iter()
        .filter(|ix| {
            m.key(ix.program)
                .is_some_and(|p| SIG_PRECOMPILES.contains(p))
        })
        .map(|ix| u64::from(ix.data.first().copied().unwrap_or(0)))
        .sum();
    let base = BASE_FEE_PER_SIGNATURE
        .checked_mul(u64::from(m.required_signatures) + precompile_sigs)
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
        // Transfer（节点只读前缀，多余字节被忽略）
        2 if ix.data.len() >= 12 => {
            c.trailing(label, ix.data.len() - 12);
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
        0 if ix.data.len() >= 52 => {
            c.trailing(label, ix.data.len() - 52);
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
        // Allocate / AllocateWithSeed 作用于本账户：账户有了数据，System Transfer 再也转不出它的 SOL
        8 | 9 if c.acct(ix, 0)? == *c.own => return Err(SolError::AccountLock),
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
            c.undecoded(ix);
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
            let rent = if c.acct(ix, 5)? == TOKEN_2022 {
                ATA_2022_RENT_LAMPORTS
            } else {
                ATA_RENT_LAMPORTS
            };
            c.d.row(label, "为收款方建立代币账户（已存在则跳过）", Style::Text);
            c.d.row("　代币账户所属钱包", address(&owner), Style::Address);
            if payer == *c.own {
                c.rent_deposit = c.rent_deposit.checked_add(rent).ok_or(SolError::Overflow)?;
            }
            c.ops.push("建立代币账户");
        }
        _ => {
            c.d.row(label, "关联代币账户程序的其他指令", Style::Text);
            c.undecoded(ix);
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
        // TransferChecked（节点只读前缀，多余字节被忽略）
        12 if rest.len() >= 9 => {
            c.trailing(label, rest.len() - 9);
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
        3 if rest.len() >= 8 => {
            c.trailing(label, rest.len() - 8);
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
            c.undecoded(ix);
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
    c.ops.push("备注");
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

    fn sys_ix(tag: u32, accounts: Vec<AccountMeta>, extra: &[u8]) -> Ix {
        Ix {
            program: SYSTEM,
            accounts,
            data: [tag.to_le_bytes().to_vec(), extra.to_vec()].concat(),
        }
    }

    /// 复审 #1：多余字节的转账照常解析、计入扣除；没完全解析又用到本账户的指令让"最多扣除"变成无法确定
    #[test]
    fn trailing_bytes_and_undecoded_instructions_affect_the_total() {
        let mut t = system_transfer(&OWN, &BOB, 5_000_000_000);
        t.data.push(0);
        let r = review(&msg(&[t]), &OWN).unwrap();
        assert_eq!(r.native_out, 5_000_000_000);
        assert!(r
            .display
            .warnings
            .iter()
            .any(|w| w.text.contains("多余字节")));
        // CreateAccountWithSeed（编号 3）从本账户出资：不解析，但扣除标为无法确定
        let cws = sys_ix(
            3,
            vec![
                AccountMeta::new(OWN, true, true),
                AccountMeta::new([0x44; 32], false, true),
            ],
            &[0; 40],
        );
        let r = review(&msg(&[cws]), &OWN).unwrap();
        assert!(
            r.display
                .rows
                .iter()
                .any(|x| x.label.starts_with("最多扣除：无法确定")),
            "{:?}",
            r.display.rows
        );
        assert!(danger(&r, "无法完全解析"));
        // 未知程序拿到本账户签名：同样无法确定
        let unknown = Ix {
            program: [0x77; 32],
            accounts: vec![AccountMeta::new(OWN, true, true)],
            data: vec![1],
        };
        assert!(review(&msg(&[unknown]), &OWN)
            .unwrap()
            .display
            .rows
            .iter()
            .any(|x| x.label.starts_with("最多扣除：无法确定")));
        // 未知程序不碰本账户：扣除仍可确定
        let other = Ix {
            program: [0x77; 32],
            accounts: vec![AccountMeta::new(BOB, false, true)],
            data: vec![1],
        };
        assert!(review(&msg(&[other]), &OWN)
            .unwrap()
            .display
            .rows
            .iter()
            .any(|x| x.label == "最多扣除（仅手续费）"));
        // 代币转账带多余字节
        let usdc = KNOWN_TOKENS[0].mint;
        let src = associated_token_account(&OWN, &usdc, &TOKEN).unwrap();
        let mut tc = token_transfer_checked(&TOKEN, &src, &usdc, &[0x44; 32], &OWN, 7, 6);
        tc.data.push(9);
        let r = review(&msg(&[tc]), &OWN).unwrap();
        assert!(r.display.rows.iter().any(|x| x.value == "0.000007 USDC"));
    }

    /// 复审 #2 与测试缺口：Allocate 作用于本账户、AssignWithSeed、Token-2022 SetAuthority、地址查找表一律拒签
    #[test]
    fn more_refusals() {
        let alloc = sys_ix(
            8,
            vec![AccountMeta::new(OWN, true, true)],
            &10u64.to_le_bytes(),
        );
        assert_eq!(review(&msg(&[alloc]), &OWN), Err(SolError::AccountLock));
        let alloc_seed = sys_ix(
            9,
            vec![
                AccountMeta::new(OWN, true, true),
                AccountMeta::new(BOB, true, false),
            ],
            &[0; 8],
        );
        assert_eq!(
            review(&msg(&[alloc_seed]), &OWN),
            Err(SolError::AccountLock)
        );
        // Allocate 作用于别的新账户：不拒，但按未解析处理
        let alloc_other = sys_ix(
            8,
            vec![AccountMeta::new([0x45; 32], true, true)],
            &10u64.to_le_bytes(),
        );
        assert!(review(&msg(&[alloc_other]), &OWN)
            .unwrap()
            .display
            .has_danger());
        let assign_seed = sys_ix(10, vec![AccountMeta::new(OWN, true, true)], &[0; 8]);
        assert_eq!(
            review(&msg(&[assign_seed]), &OWN),
            Err(SolError::OwnerChange)
        );
        let set_auth_2022 = Ix {
            program: TOKEN_2022,
            accounts: vec![
                AccountMeta::new([0x66; 32], false, true),
                AccountMeta::new(OWN, true, false),
            ],
            data: vec![6, 2, 0],
        };
        assert_eq!(
            review(&msg(&[set_auth_2022]), &OWN),
            Err(SolError::SetAuthority)
        );
        // v0 + 地址查找表
        let legacy = msg(&[system_transfer(&OWN, &BOB, 1)]);
        let mut v0 = vec![0x80];
        v0.extend_from_slice(&legacy);
        crate::message::encode_shortvec(&mut v0, 1);
        v0.extend_from_slice(&[0x99; 32]);
        crate::message::encode_shortvec(&mut v0, 1);
        v0.push(0);
        crate::message::encode_shortvec(&mut v0, 0);
        assert_eq!(review(&v0, &OWN), Err(SolError::LookupTable));
        // 没有查找表的 v0 可以审查
        let mut v0_plain = vec![0x80];
        v0_plain.extend_from_slice(&legacy);
        crate::message::encode_shortvec(&mut v0_plain, 0);
        assert!(review(&v0_plain, &OWN).is_ok());
        // 关联代币账户指令里的代币程序不是 Token / Token-2022
        let usdc = KNOWN_TOKENS[0].mint;
        let dst = associated_token_account(&BOB, &usdc, &TOKEN).unwrap();
        let mut bad = create_ata_idempotent(&OWN, &dst, &BOB, &usdc, &TOKEN);
        bad.accounts[5].key = [0x55; 32];
        assert_eq!(review(&msg(&[bad]), &OWN), Err(SolError::Parse));
    }

    /// 测试缺口：手续费向上取整、140 万上限、预编译签名计费
    #[test]
    fn fee_rounding_caps_and_precompiles() {
        // 3 × 333_333 / 10⁶ = 0.999999 → 向上取整为 1
        assert_eq!(
            review(
                &msg(&[
                    compute_unit_limit(3),
                    compute_unit_price(333_333),
                    system_transfer(&OWN, &BOB, 1)
                ]),
                &OWN
            )
            .unwrap()
            .fee,
            5_001
        );
        // 上限 200 万按 140 万计
        assert_eq!(
            review(
                &msg(&[
                    compute_unit_limit(2_000_000),
                    compute_unit_price(1_000_000),
                    system_transfer(&OWN, &BOB, 1)
                ]),
                &OWN
            )
            .unwrap()
            .fee,
            5_000 + 1_400_000
        );
        // 8 条非 ComputeBudget 指令按 160 万默认、封顶 140 万
        let mut ixs = vec![compute_unit_price(1_000_000)];
        ixs.extend((0..8).map(|i| system_transfer(&OWN, &[i + 0x30; 32], 1)));
        assert_eq!(review(&msg(&ixs), &OWN).unwrap().fee, 5_000 + 1_400_000);
        // Ed25519 预编译：2 个签名各收 5000
        let pre = Ix {
            program: SIG_PRECOMPILES[0],
            accounts: vec![],
            data: vec![2, 0],
        };
        assert_eq!(
            review(&msg(&[pre, system_transfer(&OWN, &BOB, 1)]), &OWN)
                .unwrap()
                .fee,
            15_000
        );
    }

    /// 测试缺口：本账户不是付款人时总额不含手续费；押金只在本账户付款时计入，Token-2022 押金不同
    #[test]
    fn totals_follow_who_pays() {
        let usdc = KNOWN_TOKENS[0].mint;
        let dst = associated_token_account(&BOB, &usdc, &TOKEN).unwrap();
        let r = review(
            &msg(&[create_ata_idempotent(&OWN, &dst, &BOB, &usdc, &TOKEN)]),
            &OWN,
        )
        .unwrap();
        assert_eq!(r.rent_deposit, ATA_RENT_LAMPORTS);
        assert!(r
            .display
            .rows
            .iter()
            .any(|x| x.label == "最多扣除（手续费 + 可能的押金）"
                && x.value == sol(5_000 + ATA_RENT_LAMPORTS)));
        let dst22 = associated_token_account(&BOB, &usdc, &TOKEN_2022).unwrap();
        assert_eq!(
            review(
                &msg(&[create_ata_idempotent(
                    &OWN,
                    &dst22,
                    &BOB,
                    &usdc,
                    &TOKEN_2022
                )]),
                &OWN
            )
            .unwrap()
            .rent_deposit,
            ATA_2022_RENT_LAMPORTS
        );
        // 别人付押金
        let carol = [0x55; 32];
        let ix = create_ata_idempotent(&carol, &dst, &BOB, &usdc, &TOKEN);
        let m = compile_legacy(&carol, &[ix, system_transfer(&OWN, &BOB, 3)], &BH).unwrap();
        let r = review(&m, &OWN).unwrap();
        assert_eq!(r.rent_deposit, 0);
        // 本账户不付手续费：总额只有金额
        assert!(
            r.display
                .rows
                .iter()
                .any(|x| x.label == "总计最多扣除（金额 + 最高手续费）" && x.value == sol(3)),
            "{:?}",
            r.display.rows
        );
        assert!(r
            .display
            .warnings
            .iter()
            .any(|w| w.text.contains("另一个账户支付")));
    }

    /// 测试缺口：转出方 / 授权人不是本账户、CreateAccount 归属未知程序、CloseAccount 押金去向、备注白名单、多个 ATA
    #[test]
    fn warning_levels_are_pinned() {
        let carol = [0x55; 32];
        // 别人转出（需要别人签名）
        let m = compile_legacy(&OWN, &[system_transfer(&carol, &BOB, 1)], &BH).unwrap();
        let r = review(&m, &OWN).unwrap();
        assert_eq!(r.native_out, 0);
        assert!(r
            .display
            .warnings
            .iter()
            .any(|w| w.level == Level::Caution && w.text.contains("从另一个账户转出")));
        // 代币授权人不是本账户
        let usdc = KNOWN_TOKENS[0].mint;
        let m = compile_legacy(
            &OWN,
            &[token_transfer_checked(
                &TOKEN,
                &[0x88; 32],
                &usdc,
                &[0x44; 32],
                &carol,
                1,
                6,
            )],
            &BH,
        )
        .unwrap();
        assert!(review(&m, &OWN)
            .unwrap()
            .display
            .warnings
            .iter()
            .any(|w| w.text.contains("授权人不是本账户")));
        // CreateAccount：归属 System 是提醒，归属未知程序是高风险
        let create = |owner: [u8; 32]| {
            let mut d = 0u32.to_le_bytes().to_vec();
            d.extend_from_slice(&1_000u64.to_le_bytes());
            d.extend_from_slice(&0u64.to_le_bytes());
            d.extend_from_slice(&owner);
            Ix {
                program: SYSTEM,
                accounts: vec![
                    AccountMeta::new(OWN, true, true),
                    AccountMeta::new(carol, true, true),
                ],
                data: d,
            }
        };
        let r = review(&msg(&[create(SYSTEM)]), &OWN).unwrap();
        assert!(!r.display.has_danger() && r.native_out == 1_000);
        assert!(danger(
            &review(&msg(&[create([0x99; 32])]), &OWN).unwrap(),
            "创建新账户"
        ));
        // CloseAccount：押金退给自己是提醒，退给别人是高风险
        let close = |dest: [u8; 32]| Ix {
            program: TOKEN,
            accounts: vec![
                AccountMeta::new([0x88; 32], false, true),
                AccountMeta::new(dest, false, true),
                AccountMeta::new(OWN, true, false),
            ],
            data: vec![9],
        };
        assert!(!review(&msg(&[close(OWN)]), &OWN)
            .unwrap()
            .display
            .has_danger());
        assert!(danger(
            &review(&msg(&[close(carol)]), &OWN).unwrap(),
            "关闭代币账户"
        ));
        // 备注：方向控制符等不能按文字显示
        let memo = Ix {
            program: MEMO,
            accounts: vec![],
            data: "pay\u{202e}bob".as_bytes().to_vec(),
        };
        let r = review(&msg(&[memo]), &OWN).unwrap();
        assert!(r
            .display
            .rows
            .iter()
            .any(|x| x.value.starts_with("备注（十六进制）")));
        assert_eq!(r.display.title, "备注");
        // 两个 ATA：收款人必须对应目标代币账户，而不是第一个登记的
        let d1 = associated_token_account(&BOB, &usdc, &TOKEN).unwrap();
        let d2 = associated_token_account(&carol, &usdc, &TOKEN).unwrap();
        let src = associated_token_account(&OWN, &usdc, &TOKEN).unwrap();
        let m = msg(&[
            create_ata_idempotent(&OWN, &d1, &BOB, &usdc, &TOKEN),
            create_ata_idempotent(&OWN, &d2, &carol, &usdc, &TOKEN),
            token_transfer_checked(&TOKEN, &src, &usdc, &d2, &OWN, 1, 6),
        ]);
        let r = review(&m, &OWN).unwrap();
        assert_eq!(row(&r, "　收款人"), Some(address(&carol).as_str()));
        assert_eq!(r.display.title, "代币转账");
    }
}
