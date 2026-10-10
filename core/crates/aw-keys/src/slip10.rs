//! SLIP-10 的 Ed25519 派生（Solana、NEAR 使用）。只支持强化派生（Ed25519 本身不支持普通派生）。
//!
//! 主节点：I = HMAC-SHA512("ed25519 seed", 种子)；子节点：I = HMAC-SHA512(链码, 0x00 ‖ 私钥 ‖ ser32(i + 2^31))。
//! 私钥 = I 的前 32 字节，链码 = 后 32 字节。公钥由 ed25519-compact 计算（第三方，见 docs/05 D26）。

use aw_common::secret::{wipe_bytes, SecretBytes};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::{sha512, Hash, HashEngine};

use crate::KeyError;

/// 节点：前 32 字节私钥，后 32 字节链码；释放时清零
pub struct Ed25519Node(SecretBytes<64>);

fn hmac(key: &[u8], parts: &[&[u8]]) -> SecretBytes<64> {
    let mut e = HmacEngine::<sha512::Hash>::new(key);
    for p in parts {
        e.input(p);
    }
    let mut out = SecretBytes::<64>::zeroed();
    let mut i = Hmac::<sha512::Hash>::from_engine(e).to_byte_array();
    out.expose_mut().copy_from_slice(&i);
    wipe_bytes(&mut i);
    out
}

impl Ed25519Node {
    pub fn master(seed: &SecretBytes<64>) -> Self {
        Self(hmac(b"ed25519 seed", &[seed.expose()]))
    }

    fn key(&self) -> &[u8] {
        self.0.expose().get(..32).unwrap_or(&[])
    }

    fn chain_code(&self) -> &[u8] {
        self.0.expose().get(32..).unwrap_or(&[])
    }

    /// 强化子节点 i'（i < 2^31）
    pub fn child(&self, index: u32) -> Result<Self, KeyError> {
        if index >= 0x8000_0000 {
            return Err(KeyError::Derivation);
        }
        let ser = (index | 0x8000_0000).to_be_bytes();
        Ok(Self(hmac(self.chain_code(), &[&[0u8], self.key(), &ser])))
    }

    /// 依次派生一组强化索引（如 [44, 501, 0, 0] 表示 m/44'/501'/0'/0'）
    pub fn derive(&self, path: &[u32]) -> Result<Self, KeyError> {
        let mut node = self.child(*path.first().ok_or(KeyError::Derivation)?)?;
        for &i in path.get(1..).unwrap_or(&[]) {
            node = node.child(i)?;
        }
        Ok(node)
    }

    /// Ed25519 公钥（32 字节）。私钥全零的概率可以忽略，但第三方库遇到时会中止程序，这里提前拒绝。
    pub fn public_key(&self) -> Result<[u8; 32], KeyError> {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(self.key());
        if seed.iter().all(|&b| b == 0) {
            return Err(KeyError::Derivation);
        }
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
        wipe_bytes(&mut seed);
        Ok(*kp.pk)
    }

    /// 仅供测试与自检核对：私钥与链码
    #[cfg(test)]
    pub(crate) fn raw(&self) -> &[u8; 64] {
        self.0.expose()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use aw_common::hex;

    /// SLIP-0010 官方测试向量 1（ed25519），种子 000102030405060708090a0b0c0d0e0f
    #[test]
    fn slip10_official_vector_1() {
        let mut seed64 = SecretBytes::<64>::zeroed();
        // SLIP-10 的种子是 16 字节；这里的 master() 接受 64 字节 BIP39 种子，所以单独计算 16 字节的情形
        let m = Ed25519Node(hmac(
            b"ed25519 seed",
            &[&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()],
        ));
        assert_eq!(
            hex::encode(&m.raw()[..32]),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(&m.raw()[32..]),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
        assert_eq!(
            hex::encode(&m.public_key().unwrap()),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );
        let c = m.child(0).unwrap();
        assert_eq!(
            hex::encode(&c.raw()[..32]),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(&c.raw()[32..]),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );
        assert_eq!(
            hex::encode(&c.public_key().unwrap()),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );
        let deep = m.derive(&[0, 1, 2, 2, 1_000_000_000]).unwrap();
        assert_eq!(
            hex::encode(&deep.raw()[..32]),
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
        );
        assert_eq!(
            hex::encode(&deep.public_key().unwrap()),
            "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"
        );
        seed64.expose_mut()[0] = 1;
        assert!(Ed25519Node::master(&seed64).child(0x8000_0000).is_err());
    }
}
