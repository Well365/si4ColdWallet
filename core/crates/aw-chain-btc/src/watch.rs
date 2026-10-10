//! 观察机（feature `watch`）：构造未签名 PSBT、合并签名机返回的签名、提取可广播交易。
//!
//! 观察机不持有私钥。它同样不完全信任签名机返回的内容：
//! 交易本体必须与发出去的完全一致，每个签名都要用自己计算的签名哈希验证。

use crate::{Account, BtcError, DUST_P2WPKH, MAX_IO, P2WPKH_WITNESS_WU};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1, Verification};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, EcdsaSighashType, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// 一个可花费的 UTXO：完整前序交易 + 输出序号 + 属于本账户的哪个地址。
#[derive(Debug, Clone)]
pub struct Utxo {
    pub prev_tx: Transaction,
    pub vout: u32,
    pub change: bool,
    pub index: u32,
}

impl Utxo {
    fn txout(&self) -> Option<&TxOut> {
        self.prev_tx.output.get(usize::try_from(self.vout).ok()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSummary {
    pub inputs: usize,
    pub amount: u64,
    pub fee: u64,
    pub change: Option<u64>,
    pub vsize_estimate: u64,
}

fn vsize_for(inputs: usize, outputs: usize) -> u64 {
    // 无见证部分：版本 4 + 输入数 1 + 每个输入 41 + 输出数 1 + 每个 P2WPKH 输出 31 + locktime 4
    let base = 4 + 1 + 41 * inputs as u64 + 1 + 31 * outputs as u64 + 4;
    (base * 4 + 2 + P2WPKH_WITNESS_WU * inputs as u64).div_ceil(4)
}

fn child_path(account: &Account, change: bool, index: u32) -> Result<DerivationPath, BtcError> {
    let tail = [
        ChildNumber::from_normal_idx(u32::from(change)).map_err(|_| BtcError::Derivation)?,
        ChildNumber::from_normal_idx(index).map_err(|_| BtcError::Derivation)?,
    ];
    Ok(account.account_path.extend(tail))
}

/// 构造付款 PSBT：最大面额优先选币；找零低于粉尘阈值时并入手续费；启用 RBF。
pub fn build_payment<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    utxos: &[Utxo],
    to: &Address,
    amount: u64,
    fee_rate_sat_vb: u64,
    change_index: u32,
) -> Result<(Psbt, BuildSummary), BtcError> {
    if amount < DUST_P2WPKH || fee_rate_sat_vb == 0 || utxos.len() > MAX_IO {
        return Err(BtcError::Empty);
    }
    for (i, u) in utxos.iter().enumerate() {
        let out = u.txout().ok_or(BtcError::UtxoNotOurs(i))?;
        if out.script_pubkey != account.script_for(secp, u.change, u.index)? {
            return Err(BtcError::UtxoNotOurs(i));
        }
    }
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.txout().map_or(0, |o| o.value.to_sat())));

    let mut chosen = Vec::new();
    let mut total = 0u64;
    for u in sorted {
        chosen.push(u);
        total = total
            .checked_add(u.txout().map_or(0, |o| o.value.to_sat()))
            .ok_or(BtcError::AmountOverflow)?;
        if total >= amount + fee_rate_sat_vb * vsize_for(chosen.len(), 2) {
            break;
        }
    }
    let fee_two = fee_rate_sat_vb * vsize_for(chosen.len(), 2);
    let fee_one = fee_rate_sat_vb * vsize_for(chosen.len(), 1);
    let (change, fee) = match total.checked_sub(amount + fee_two) {
        Some(c) if c >= DUST_P2WPKH => (Some(c), fee_two),
        _ => {
            let fee = total
                .checked_sub(amount)
                .ok_or(BtcError::InsufficientFunds)?;
            if fee < fee_one {
                return Err(BtcError::InsufficientFunds);
            }
            (None, fee)
        }
    };

    let mut output = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: to.script_pubkey(),
    }];
    if let Some(c) = change {
        output.push(TxOut {
            value: Amount::from_sat(c),
            script_pubkey: account.script_for(secp, true, change_index)?,
        });
    }
    let input = chosen
        .iter()
        .map(|u| TxIn {
            previous_output: OutPoint {
                txid: u.prev_tx.compute_txid(),
                vout: u.vout,
            },
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..TxIn::default()
        })
        .collect();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|_| BtcError::Parse)?;

    for (slot, u) in psbt.inputs.iter_mut().zip(&chosen) {
        let pk = account.derive_pubkey(secp, u.change, u.index)?;
        slot.non_witness_utxo = Some(u.prev_tx.clone());
        slot.witness_utxo = u.txout().cloned();
        slot.bip32_derivation.insert(
            pk.0,
            (
                account.master_fingerprint,
                child_path(account, u.change, u.index)?,
            ),
        );
    }
    if change.is_some() {
        let pk = account.derive_pubkey(secp, true, change_index)?;
        if let Some(slot) = psbt.outputs.get_mut(1) {
            slot.bip32_derivation.insert(
                pk.0,
                (
                    account.master_fingerprint,
                    child_path(account, true, change_index)?,
                ),
            );
        }
    }
    let summary = BuildSummary {
        inputs: chosen.len(),
        amount,
        fee,
        change,
        vsize_estimate: vsize_for(chosen.len(), if change.is_some() { 2 } else { 1 }),
    };
    Ok((psbt, summary))
}

/// 合并签名并提取交易。`original` 是观察机自己发出去的 PSBT。
pub fn finalize<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    original: &Psbt,
    signed_bytes: &[u8],
) -> Result<Transaction, BtcError> {
    let mut signed = Psbt::deserialize(signed_bytes).map_err(|_| BtcError::Parse)?;
    if signed.unsigned_tx != original.unsigned_tx {
        return Err(BtcError::TxChanged);
    }
    let tx = original.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    for (i, orig_in) in original.inputs.iter().enumerate() {
        let prev_out = orig_in
            .witness_utxo
            .as_ref()
            .ok_or(BtcError::MissingPrevTx(i))?;
        let (pk, (fp, path)) = orig_in
            .bip32_derivation
            .iter()
            .next()
            .ok_or(BtcError::ForeignInput(i))?;
        let (change, index) = account
            .match_path(*fp, path)
            .ok_or(BtcError::ForeignInput(i))?;
        if account.derive_pubkey(secp, change, index)?.0 != *pk {
            return Err(BtcError::ForeignInput(i));
        }
        let slot = signed.inputs.get_mut(i).ok_or(BtcError::Parse)?;
        let expected_key = bitcoin::PublicKey::new(*pk);
        if slot.partial_sigs.len() != 1 {
            return Err(BtcError::BadSignature(i));
        }
        let sig = *slot
            .partial_sigs
            .get(&expected_key)
            .ok_or(BtcError::BadSignature(i))?;
        if sig.sighash_type != EcdsaSighashType::All {
            return Err(BtcError::BadSignature(i));
        }
        let sighash = cache
            .p2wpkh_signature_hash(
                i,
                &prev_out.script_pubkey,
                prev_out.value,
                EcdsaSighashType::All,
            )
            .map_err(|_| BtcError::BadSignature(i))?;
        let msg = Message::from_digest(bitcoin::hashes::Hash::to_byte_array(sighash));
        secp.verify_ecdsa(&msg, &sig.signature, pk)
            .map_err(|_| BtcError::BadSignature(i))?;

        slot.final_script_witness = Some(Witness::p2wpkh(&sig, pk));
        slot.partial_sigs.clear();
        slot.bip32_derivation.clear();
        slot.sighash_type = None;
    }
    signed.extract_tx().map_err(|_| BtcError::Parse)
}
