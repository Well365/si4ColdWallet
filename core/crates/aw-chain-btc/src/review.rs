//! 签名前审查（威胁 T5/T8/T9）：不信任 PSBT 中的任何声明，全部重新计算。
//!
//! 通过审查的交易满足：
//! - 每个输入都附带完整前序交易，哈希吻合，金额取自前序交易（防手续费欺骗）
//! - 每个输入都是本账户的 P2WPKH，派生路径、公钥、脚本三者一致
//! - 只使用 SIGHASH_ALL
//! - 声称属于本钱包的输出，脚本必须真的由声称的路径派生（防找零替换）
//! - 其余输出都能显示为地址，金额与手续费明确

use crate::{Account, BtcError, DUST_P2WPKH, MAX_IO, P2WPKH_WITNESS_WU};
use aw_common::display::{Display, Level, Style};
use aw_common::json::Json;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Address, Amount, EcdsaSighashType, TxOut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// 付给外部地址
    External,
    /// 找零（m/…/1/i），已验证属于本钱包
    Change(u32),
    /// 转到本钱包收款地址（m/…/0/i），已验证
    SelfReceive(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputInfo {
    pub address: String,
    pub amount: u64,
    pub kind: OutputKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputInfo {
    pub change: bool,
    pub index: u32,
    pub amount: u64,
    pub script: bitcoin::ScriptBuf,
}

/// 手续费占付款金额的比例上限：超过 1/20（5%）即高风险（docs/01 T5）
pub const HIGH_FEE_RATIO_DIVISOR: u64 = 20;
/// 手续费绝对值上限：超过即高风险，与比例无关（docs/01 T5 "绝对值异常"）
pub const HIGH_FEE_ABSOLUTE_SAT: u64 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// 手续费率超过 500 sat/vB
    HighFeeRate,
    /// 手续费超过付款金额的 5%（没有对外付款时按全部输出计）
    HighFeeRatio,
    /// 手续费绝对值超过 HIGH_FEE_ABSOLUTE_SAT
    HighFeeAbsolute,
    /// 对外付款金额低于粉尘阈值
    DustOutput,
    /// 没有对外付款（全部转给自己）
    SelfTransferOnly,
    /// 设置了非零 locktime
    Locktime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub network: bitcoin::Network,
    pub inputs: Vec<InputInfo>,
    pub outputs: Vec<OutputInfo>,
    pub input_total: u64,
    pub external_total: u64,
    pub fee: u64,
    /// 签名后虚拟大小的上界估计
    pub vsize_estimate: u64,
    pub locktime: u32,
    pub rbf: bool,
    pub warnings: Vec<Warning>,
}

pub fn parse(psbt_bytes: &[u8]) -> Result<Psbt, BtcError> {
    Psbt::deserialize(psbt_bytes).map_err(|_| BtcError::Parse)
}

fn check_input<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    psbt: &Psbt,
    i: usize,
) -> Result<InputInfo, BtcError> {
    let txin = psbt.unsigned_tx.input.get(i).ok_or(BtcError::Parse)?;
    let inp = psbt.inputs.get(i).ok_or(BtcError::Parse)?;
    if inp.final_script_sig.is_some() || inp.final_script_witness.is_some() {
        return Err(BtcError::AlreadyFinalized(i));
    }
    // 1. 金额只信前序交易
    let prev_tx = inp
        .non_witness_utxo
        .as_ref()
        .ok_or(BtcError::MissingPrevTx(i))?;
    if prev_tx.compute_txid() != txin.previous_output.txid {
        return Err(BtcError::PrevTxMismatch(i));
    }
    let vout =
        usize::try_from(txin.previous_output.vout).map_err(|_| BtcError::PrevTxMismatch(i))?;
    let prev_out: &TxOut = prev_tx
        .output
        .get(vout)
        .ok_or(BtcError::PrevTxMismatch(i))?;
    if let Some(w) = &inp.witness_utxo {
        if w != prev_out {
            return Err(BtcError::WitnessUtxoMismatch(i));
        }
    }
    if !prev_out.script_pubkey.is_p2wpkh() {
        return Err(BtcError::UnsupportedInputScript(i));
    }
    // 2. 只签 SIGHASH_ALL
    if let Some(t) = inp.sighash_type {
        if t.ecdsa_hash_ty() != Ok(EcdsaSighashType::All) {
            return Err(BtcError::SighashNotAll(i));
        }
    }
    // 3. 必须是本账户：路径匹配 + 公钥一致 + 脚本一致
    let (change, index) = inp
        .bip32_derivation
        .iter()
        .find_map(|(pk, (fp, path))| {
            let (change, index) = account.match_path(*fp, path)?;
            let derived = account.derive_pubkey(secp, change, index).ok()?;
            (derived.0 == *pk
                && account.script_for(secp, change, index).ok()? == prev_out.script_pubkey)
                .then_some((change, index))
        })
        .ok_or(BtcError::ForeignInput(i))?;
    Ok(InputInfo {
        change,
        index,
        amount: prev_out.value.to_sat(),
        script: prev_out.script_pubkey.clone(),
    })
}

fn check_output<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    psbt: &Psbt,
    o: usize,
) -> Result<OutputInfo, BtcError> {
    let txout = psbt.unsigned_tx.output.get(o).ok_or(BtcError::Parse)?;
    let meta = psbt.outputs.get(o).ok_or(BtcError::Parse)?;
    let address = Address::from_script(&txout.script_pubkey, account.network)
        .map_err(|_| BtcError::UnsupportedOutputScript(o))?
        .to_string();
    let mut kind = OutputKind::External;
    for (pk, (fp, path)) in &meta.bip32_derivation {
        if *fp != account.master_fingerprint {
            continue;
        }
        // 声称是本钱包：必须完全吻合，否则视为攻击而拒绝
        let (change, index) = account
            .match_path(*fp, path)
            .ok_or(BtcError::ChangeMismatch(o))?;
        let derived = account.derive_pubkey(secp, change, index)?;
        if derived.0 != *pk || account.script_for(secp, change, index)? != txout.script_pubkey {
            return Err(BtcError::ChangeMismatch(o));
        }
        kind = if change {
            OutputKind::Change(index)
        } else {
            OutputKind::SelfReceive(index)
        };
    }
    Ok(OutputInfo {
        address,
        amount: txout.value.to_sat(),
        kind,
    })
}

fn checked_sum(mut it: impl Iterator<Item = u64>) -> Result<u64, BtcError> {
    it.try_fold(0u64, u64::checked_add)
        .ok_or(BtcError::AmountOverflow)
}

/// 估算签名后的虚拟大小（上界）：无见证部分 ×4 + 标记/标志 2 WU + 每个输入 108 WU。
fn vsize_estimate(psbt: &Psbt) -> u64 {
    let base_wu = psbt.unsigned_tx.weight().to_wu();
    let wu = base_wu + 2 + P2WPKH_WITNESS_WU * psbt.unsigned_tx.input.len() as u64;
    wu.div_ceil(4)
}

pub fn review<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    psbt: &Psbt,
) -> Result<Review, BtcError> {
    let tx = &psbt.unsigned_tx;
    if tx.input.is_empty() || tx.output.is_empty() {
        return Err(BtcError::Empty);
    }
    if tx.input.len() > MAX_IO || tx.output.len() > MAX_IO {
        return Err(BtcError::TooManyIo);
    }
    if psbt.inputs.len() != tx.input.len() || psbt.outputs.len() != tx.output.len() {
        return Err(BtcError::Parse);
    }
    let inputs = (0..tx.input.len())
        .map(|i| check_input(secp, account, psbt, i))
        .collect::<Result<Vec<_>, _>>()?;
    let outputs = (0..tx.output.len())
        .map(|o| check_output(secp, account, psbt, o))
        .collect::<Result<Vec<_>, _>>()?;

    let input_total = checked_sum(inputs.iter().map(|i| i.amount))?;
    let output_total = checked_sum(outputs.iter().map(|o| o.amount))?;
    let external_total = checked_sum(
        outputs
            .iter()
            .filter(|o| o.kind == OutputKind::External)
            .map(|o| o.amount),
    )?;
    let fee = input_total
        .checked_sub(output_total)
        .ok_or(BtcError::NegativeFee)?;
    if Amount::from_sat(input_total) > Amount::MAX_MONEY {
        return Err(BtcError::AmountOverflow);
    }
    let vsize = vsize_estimate(psbt);

    let mut warnings = Vec::new();
    if fee > vsize.saturating_mul(500) {
        warnings.push(Warning::HighFeeRate);
    }
    // 比例按对外付款金额算；全部转回自己（整理 UTXO 等）时按全部输出算，不能因此跳过检查
    let ratio_base = if external_total > 0 {
        external_total
    } else {
        output_total
    };
    // 输出总额为 0（手续费 100%）时任何手续费都算超比例
    if fee > 0 && fee.saturating_mul(HIGH_FEE_RATIO_DIVISOR) > ratio_base {
        warnings.push(Warning::HighFeeRatio);
    }
    if fee > HIGH_FEE_ABSOLUTE_SAT {
        warnings.push(Warning::HighFeeAbsolute);
    }
    if outputs
        .iter()
        .any(|o| o.kind == OutputKind::External && o.amount < DUST_P2WPKH)
    {
        warnings.push(Warning::DustOutput);
    }
    // "转给自己"按"没有任何对外输出"判定：0 聪的对外输出仍是对外付款（粉尘）
    if !outputs.iter().any(|o| o.kind == OutputKind::External) {
        warnings.push(Warning::SelfTransferOnly);
    }
    let locktime = tx.lock_time.to_consensus_u32();
    if locktime != 0 {
        warnings.push(Warning::Locktime);
    }
    Ok(Review {
        network: account.network,
        inputs,
        outputs,
        input_total,
        external_total,
        fee,
        vsize_estimate: vsize,
        locktime,
        rbf: tx.input.iter().any(|i| i.sequence.is_rbf()),
        warnings,
    })
}

impl Review {
    /// 给界面的显示模型（JSON）。字段名在 Swift 侧有对应的 Decodable 结构。
    /// 通用显示模型（P2：签名机界面对所有链用同一套渲染）
    pub fn to_display(&self) -> Display {
        let testnet = self.network != bitcoin::Network::Bitcoin;
        let unit = if testnet { "tBTC" } else { "BTC" };
        let btc = |sat: u64| format!("{} {unit}", format_sat(sat));
        let title = if !self.outputs.iter().any(|o| o.kind == OutputKind::External) {
            "转给自己"
        } else {
            "发送 BTC"
        };
        let mut d = Display::new("Bitcoin", if testnet { "测试网" } else { "主网" }, title);
        if testnet {
            d.warn(Level::Info, "测试网交易（测试币没有价值）");
        }
        for o in &self.outputs {
            match o.kind {
                OutputKind::External => {
                    d.row("收款地址", o.address.as_str(), Style::Address);
                    d.row("金额", btc(o.amount), Style::Amount);
                }
                OutputKind::Change(i) => {
                    d.row(
                        &format!("找零地址（本钱包 #{i}，已核验）"),
                        o.address.as_str(),
                        Style::Address,
                    );
                    d.row("找零金额", btc(o.amount), Style::Text);
                }
                OutputKind::SelfReceive(i) => {
                    d.row(
                        &format!("本钱包收款地址 #{i}（已核验）"),
                        o.address.as_str(),
                        Style::Address,
                    );
                    d.row("金额", btc(o.amount), Style::Text);
                }
            }
        }
        d.row(
            "输入",
            format!("{} 个，共 {}", self.inputs.len(), btc(self.input_total)),
            Style::Text,
        );
        let rate = self.fee / self.vsize_estimate.max(1);
        d.row(
            "手续费",
            format!("{}（约 {rate} sat/vB）", btc(self.fee)),
            Style::Amount,
        );
        if self.locktime != 0 {
            d.row("锁定时间", self.locktime.to_string(), Style::Text);
        }
        d.row(
            "可加速替换（RBF）",
            if self.rbf { "是" } else { "否" },
            Style::Text,
        );
        for w in &self.warnings {
            match w {
                Warning::HighFeeRate => d.warn(Level::Danger, "手续费率异常高（超过 500 sat/vB）"),
                Warning::HighFeeRatio => d.warn(
                    Level::Danger,
                    "手续费超过付款金额的 5%（没有对外付款时按全部输出计）",
                ),
                Warning::HighFeeAbsolute => d.warn(
                    Level::Danger,
                    format!("手续费绝对值异常高（超过 {}）", btc(HIGH_FEE_ABSOLUTE_SAT)),
                ),
                Warning::DustOutput => {
                    d.warn(Level::Caution, "付款金额低于粉尘阈值，交易可能无法广播")
                }
                Warning::SelfTransferOnly => {
                    d.warn(Level::Info, "没有对外付款：资金全部转回本钱包")
                }
                Warning::Locktime => {
                    d.warn(Level::Caution, "设置了锁定时间：在指定时间之前交易无法上链")
                }
            }
        }
        d
    }

    pub fn to_json(&self) -> Json {
        let outputs = self
            .outputs
            .iter()
            .map(|o| {
                let (kind, index) = match o.kind {
                    OutputKind::External => ("external", Json::Null),
                    OutputKind::Change(i) => ("change", Json::UInt(u64::from(i))),
                    OutputKind::SelfReceive(i) => ("self", Json::UInt(u64::from(i))),
                };
                Json::obj(vec![
                    ("address", Json::str(o.address.clone())),
                    ("amount_sat", Json::UInt(o.amount)),
                    ("kind", Json::str(kind)),
                    ("index", index),
                ])
            })
            .collect();
        let warnings = self
            .warnings
            .iter()
            .map(|w| {
                Json::str(match w {
                    Warning::HighFeeRate => "high_fee_rate",
                    Warning::HighFeeRatio => "high_fee_ratio",
                    Warning::HighFeeAbsolute => "high_fee_absolute",
                    Warning::DustOutput => "dust_output",
                    Warning::SelfTransferOnly => "self_transfer_only",
                    Warning::Locktime => "locktime",
                })
            })
            .collect();
        Json::obj(vec![
            ("chain", Json::str("btc")),
            (
                "network",
                Json::str(if self.network == bitcoin::Network::Bitcoin {
                    "mainnet"
                } else {
                    "testnet"
                }),
            ),
            ("input_count", Json::UInt(self.inputs.len() as u64)),
            ("input_total_sat", Json::UInt(self.input_total)),
            ("external_total_sat", Json::UInt(self.external_total)),
            ("fee_sat", Json::UInt(self.fee)),
            ("vsize_estimate", Json::UInt(self.vsize_estimate)),
            ("locktime", Json::UInt(u64::from(self.locktime))),
            ("rbf", Json::Bool(self.rbf)),
            ("outputs", Json::Array(outputs)),
            ("warnings", Json::Array(warnings)),
        ])
    }
}

/// 聪 → BTC 文本（8 位小数，去掉末尾的 0）
pub fn format_sat(sat: u64) -> String {
    let int = sat / 100_000_000;
    let frac = format!("{:08}", sat % 100_000_000);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int.to_string()
    } else {
        format!("{int}.{frac}")
    }
}
