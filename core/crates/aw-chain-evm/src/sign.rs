//! 签名（只在签名机中编译，feature `signing`）。
//!
//! - 先完整复跑审查；审查不过不签
//! - 私钥逐个派生、用完即清零（`SecretXpriv`）
//! - RFC 6979 确定性签名（libsecp256k1）：同一请求在两台设备上签名逐字节相同（威胁 T7）
//! - 签完立即从签名恢复公钥，必须得到本账户地址（防故障注入）

use crate::request::{SignRequest, Signature};
use crate::review::{review, Reviewed};
use crate::tx::{encode_sig, EthSig};
use crate::{account_path, address_of, Account, EvmError};
use aw_keys::SecretXpriv;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::NetworkKind;

/// 签名机侧的 EVM 账户：公开信息 + 账户私钥（m/44'/60'/0'）
pub struct EvmSigner {
    pub account: Account,
    account_xprv: SecretXpriv,
}

impl EvmSigner {
    pub fn from_master(secp: &Secp256k1<All>, master: &SecretXpriv) -> Result<Self, EvmError> {
        let account_xprv = master
            .derive(secp, &account_path())
            .map_err(|_| EvmError::Derivation)?;
        let mut account_xpub = Xpub::from_priv(secp, account_xprv.expose());
        // EVM 没有"测试网版本字节"的概念；统一记为主网，与观察机导入的结果一致
        account_xpub.network = NetworkKind::Main;
        let account = Account {
            master_fingerprint: aw_keys::master_fingerprint(secp, master),
            account_xpub,
        };
        Ok(Self {
            account,
            account_xprv,
        })
    }
}

/// 审查并签名，返回审查结果与 `eth-signature` 内容
pub fn sign(
    secp: &Secp256k1<All>,
    signer: &EvmSigner,
    req: &SignRequest,
) -> Result<(Reviewed, Signature), EvmError> {
    let r = review(secp, &signer.account, req)?;
    let rel = DerivationPath::from(vec![
        ChildNumber::from_normal_idx(0).map_err(|_| EvmError::Derivation)?,
        ChildNumber::from_normal_idx(r.index).map_err(|_| EvmError::Derivation)?,
    ]);
    let child = signer
        .account_xprv
        .derive(secp, &rel)
        .map_err(|_| EvmError::Derivation)?;
    let sk = child.expose().private_key;
    let msg = Message::from_digest(r.hash);
    let rsig = secp.sign_ecdsa_recoverable(&msg, &sk);
    // 自检：从签名恢复出的公钥必须是本账户该地址的公钥
    let recovered = secp
        .recover_ecdsa(&msg, &rsig)
        .map_err(|_| EvmError::SelfCheck)?;
    if address_of(&recovered) != signer.account.address(secp, r.index)? {
        return Err(EvmError::SelfCheck);
    }
    let (recid, compact) = rsig.serialize_compact();
    let mut sig = EthSig {
        r: [0; 32],
        s: [0; 32],
        recid: u8::try_from(recid.to_i32()).map_err(|_| EvmError::SelfCheck)?,
    };
    let (r_bytes, s_bytes) = compact.split_at(32);
    sig.r.copy_from_slice(r_bytes);
    sig.s.copy_from_slice(s_bytes);
    if sig.recid > 1 {
        return Err(EvmError::SelfCheck); // 只可能出现在 r ≥ n 的极端情况，不签
    }
    let signature = encode_sig(&sig, r.v_style)?;
    Ok((
        r,
        Signature {
            request_id: req.request_id,
            signature,
            origin: None,
        },
    ))
}
