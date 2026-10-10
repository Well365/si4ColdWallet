//! TRON（P2：先做地址）。
//!
//! 账户路径：BIP44 `m/44'/195'/0'/0/i`（TronLink 默认）。
//! 地址 = Base58Check(0x41 ‖ Keccak-256(未压缩公钥去掉 0x04)[12..])——与以太坊地址同源，只是前缀与编码不同。

use bitcoin::secp256k1::PublicKey;

pub const COIN_TYPE: u32 = 195;
const PREFIX: u8 = 0x41;

pub fn path_string(index: u32) -> String {
    format!("m/44'/195'/0'/0/{index}")
}

pub fn address(pk: &PublicKey) -> String {
    let mut data = vec![PREFIX];
    data.extend_from_slice(&aw_chain_evm::address_of(pk));
    base58ck::encode_check(&data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// 已知助记词的地址在 aw-e2e 的 addresses 测试中与独立 Python 实现核对；这里只检查格式
    #[test]
    fn format() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let a = address(&PublicKey::from_secret_key(&secp, &sk));
        assert!(a.starts_with('T') && a.len() == 34, "{a}");
        assert_eq!(path_string(4), "m/44'/195'/0'/0/4");
    }
}
