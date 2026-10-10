//! EVM 账户公钥 ↔ UR `crypto-hdkey`（签名机导出 → 观察机导入），与 Keystone / MetaMask 的
//! ERC-4527 用法一致：路径 m/44'/60'/0'、币种 60、带来源指纹。
//!
//! 观察机只接受：币种 60、路径正好是 m/44'/60'/0'、带来源指纹的压缩公钥 + 链码。

use crate::{Account, EvmError, COIN_TYPE};
use aw_ur::registry::{HdKey, KeyPath};
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::NetworkKind;

pub fn account_to_hdkey(a: &Account) -> HdKey {
    HdKey {
        key_data: a.account_xpub.public_key.serialize(),
        chain_code: Some(a.account_xpub.chain_code.to_bytes()),
        coin_type: u64::from(COIN_TYPE),
        network: 0,
        origin: Some(KeyPath {
            components: vec![(44, true), (COIN_TYPE, true), (0, true)],
            source_fingerprint: Some(u32::from_be_bytes(a.master_fingerprint.to_bytes())),
            depth: Some(3),
        }),
        parent_fingerprint: Some(u32::from_be_bytes(
            a.account_xpub.parent_fingerprint.to_bytes(),
        )),
    }
}

pub fn account_from_hdkey(k: &HdKey) -> Result<Account, EvmError> {
    if k.coin_type != u64::from(COIN_TYPE) || k.network != 0 {
        return Err(EvmError::Parse);
    }
    let origin = k.origin.as_ref().ok_or(EvmError::Parse)?;
    let fp = origin.source_fingerprint.ok_or(EvmError::Parse)?;
    if origin.components.as_slice() != [(44, true), (COIN_TYPE, true), (0, true)]
        || origin.depth.is_some_and(|d| d != 3)
    {
        return Err(EvmError::Parse);
    }
    let public_key =
        bitcoin::secp256k1::PublicKey::from_slice(&k.key_data).map_err(|_| EvmError::Parse)?;
    let account_xpub = Xpub {
        network: NetworkKind::Main,
        depth: 3,
        parent_fingerprint: Fingerprint::from(k.parent_fingerprint.unwrap_or(0).to_be_bytes()),
        child_number: ChildNumber::from_hardened_idx(0).map_err(|_| EvmError::Parse)?,
        public_key,
        chain_code: ChainCode::from(k.chain_code.ok_or(EvmError::Parse)?),
    };
    Ok(Account {
        master_fingerprint: Fingerprint::from(fp.to_be_bytes()),
        account_xpub,
    })
}
