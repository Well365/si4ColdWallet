//! Dogecoin 地址（P2：先做地址；交易在 P2b 复用比特币模块）。
//!
//! 账户路径：BIP44 `m/44'/3'/0'/0/i`（测试网 `m/44'/1'/0'/0/i`）；
//! P2PKH 地址 = Base58Check(版本 ‖ HASH160(压缩公钥))，主网版本 0x1E（D 开头），测试网 0x71（n 开头）。

use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::PublicKey;

pub fn coin_type(testnet: bool) -> u32 {
    if testnet {
        1
    } else {
        3
    }
}

pub fn path_string(testnet: bool, index: u32) -> String {
    format!("m/44'/{}'/0'/0/{index}", coin_type(testnet))
}

pub fn address(pk: &PublicKey, testnet: bool) -> String {
    let mut data = vec![if testnet { 0x71 } else { 0x1e }];
    data.extend_from_slice(hash160::Hash::hash(&pk.serialize()).as_byte_array());
    base58ck::encode_check(&data)
}
