//! 签名（只在签名机中编译，feature `signing`）。
//!
//! - 先完整复跑审查；审查不过不签
//! - 私钥逐个派生、用完即清零（`SecretXpriv`）
//! - ECDSA 使用 RFC6979 确定性随机数：同一笔交易在两台独立设备上应得到逐字节相同的签名，
//!   可用来比对、防止恶意固件借随机数泄露私钥（威胁 T7）
//! - 每个签名签完立即自验（防故障注入导致的错误签名泄露私钥）

use crate::review::{review, Review};
use crate::{Account, BtcError};
use aw_keys::SecretXpriv;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::{ecdsa, Amount, EcdsaSighashType};

/// 签名机侧的账户：公开信息 + 账户私钥。
pub struct SigningAccount {
    pub account: Account,
    account_xprv: SecretXpriv,
}

impl SigningAccount {
    /// 由根私钥派生 BIP84 账户。
    pub fn from_master(
        secp: &Secp256k1<All>,
        master: &SecretXpriv,
        network: bitcoin::Network,
        account_index: u32,
    ) -> Result<Self, BtcError> {
        let account_path = crate::bip84_account_path(network, account_index)?;
        let account_xprv = master
            .derive(secp, &account_path)
            .map_err(|_| BtcError::Derivation)?;
        let account_xpub = bitcoin::bip32::Xpub::from_priv(secp, account_xprv.expose());
        let account = Account {
            network,
            master_fingerprint: aw_keys::master_fingerprint(secp, master),
            account_path,
            account_xpub,
        };
        Ok(Self {
            account,
            account_xprv,
        })
    }
}

/// 审查并签名。返回签名后的 PSBT（只新增 partial_sigs）和审查结果。
pub fn sign_psbt(
    secp: &Secp256k1<All>,
    signer: &SigningAccount,
    psbt: &mut Psbt,
) -> Result<Review, BtcError> {
    let r = review(secp, &signer.account, psbt)?;
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    for (i, info) in r.inputs.iter().enumerate() {
        let rel = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(u32::from(info.change))
                .map_err(|_| BtcError::Derivation)?,
            ChildNumber::from_normal_idx(info.index).map_err(|_| BtcError::Derivation)?,
        ]);
        let child = signer
            .account_xprv
            .derive(secp, &rel)
            .map_err(|_| BtcError::Derivation)?;
        let sk = child.expose().private_key;
        let pk = PublicKey::from_secret_key(secp, &sk);
        let sighash = cache
            .p2wpkh_signature_hash(
                i,
                &info.script,
                Amount::from_sat(info.amount),
                EcdsaSighashType::All,
            )
            .map_err(|_| BtcError::SelfCheck)?;
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &sk);
        secp.verify_ecdsa(&msg, &sig, &pk)
            .map_err(|_| BtcError::SelfCheck)?;
        let input = psbt.inputs.get_mut(i).ok_or(BtcError::Parse)?;
        input.partial_sigs.insert(
            bitcoin::PublicKey::new(pk),
            ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            },
        );
    }
    Ok(r)
}

use bitcoin::hashes::Hash as _;
