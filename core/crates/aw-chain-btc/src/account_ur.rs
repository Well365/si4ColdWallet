//! 账户公钥 ↔ UR hdkey（签名机导出 → 观察机导入）。
//!
//! 观察机只接受：带来源指纹与路径 m/84'/coin'/account' 的压缩公钥 + 链码，网络与币种一致。

use crate::{bip84_account_path, coin_type, Account, BtcError};
use aw_ur::registry::{HdKey, KeyPath};
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::{Network, NetworkKind};

pub fn account_to_hdkey(a: &Account) -> HdKey {
    let components = a
        .account_path
        .as_ref()
        .iter()
        .map(|c| match c {
            ChildNumber::Hardened { index } => (*index, true),
            ChildNumber::Normal { index } => (*index, false),
        })
        .collect();
    HdKey {
        key_data: a.account_xpub.public_key.serialize(),
        chain_code: Some(a.account_xpub.chain_code.to_bytes()),
        coin_type: 0,
        network: u64::from(a.network != Network::Bitcoin),
        origin: Some(KeyPath {
            components,
            source_fingerprint: Some(u32::from_be_bytes(a.master_fingerprint.to_bytes())),
            depth: Some(a.account_xpub.depth),
        }),
        parent_fingerprint: Some(u32::from_be_bytes(
            a.account_xpub.parent_fingerprint.to_bytes(),
        )),
    }
}

pub fn account_from_hdkey(k: &HdKey) -> Result<Account, BtcError> {
    if k.coin_type != 0 {
        return Err(BtcError::Parse); // 不是比特币账户
    }
    let network = match k.network {
        0 => Network::Bitcoin,
        1 => Network::Testnet,
        _ => return Err(BtcError::Parse),
    };
    let origin = k.origin.as_ref().ok_or(BtcError::Parse)?;
    let fp = origin.source_fingerprint.ok_or(BtcError::Parse)?;
    let account_index = match origin.components.as_slice() {
        [(84, true), (coin, true), (acct, true)] if *coin == coin_type(network) => *acct,
        _ => return Err(BtcError::Parse),
    };
    if origin.depth.is_some_and(|d| d != 3) {
        return Err(BtcError::Parse);
    }
    let public_key =
        bitcoin::secp256k1::PublicKey::from_slice(&k.key_data).map_err(|_| BtcError::Parse)?;
    let chain_code = ChainCode::from(k.chain_code.ok_or(BtcError::Parse)?);
    let account_xpub = Xpub {
        network: NetworkKind::from(network),
        depth: 3,
        parent_fingerprint: Fingerprint::from(k.parent_fingerprint.unwrap_or(0).to_be_bytes()),
        child_number: ChildNumber::from_hardened_idx(account_index).map_err(|_| BtcError::Parse)?,
        public_key,
        chain_code,
    };
    Ok(Account {
        network,
        master_fingerprint: Fingerprint::from(fp.to_be_bytes()),
        account_path: bip84_account_path(network, account_index)?,
        account_xpub,
    })
}
