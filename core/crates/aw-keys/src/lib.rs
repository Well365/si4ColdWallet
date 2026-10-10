//! 密钥派生（P1：BTC BIP84）。
//!
//! 椭圆曲线运算全部走 libsecp256k1（经 rust-secp256k1，C 源码已由检查 C7 核对上游）。
//! 种子只以 `SecretBytes<64>` 传入，本模块不保存种子。

pub mod slip10;

use aw_common::secret::{wipe_bytes, SecretBytes};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// BIP32 派生失败（概率可忽略，但必须处理）
    Derivation,
}

/// 创建 secp256k1 上下文，并用调用方提供的 32 字节随机数做侧信道防护随机化。
/// 随机数应来自系统安全随机源（iOS：`SecRandomCopyBytes`）。
pub fn secp_context(randomization: &[u8; 32]) -> Secp256k1<All> {
    let mut secp = Secp256k1::new();
    secp.seeded_randomize(randomization);
    secp
}

/// 扩展私钥的持有者：离开作用域时清零私钥与链码（P1 Rust 审查 M1）。
///
/// 第三方 `Xpriv` 是 `Copy` 且没有 `Drop`，用完不会自动清零；本模块只对外交出这个包装。
pub struct SecretXpriv(Xpriv);

impl SecretXpriv {
    fn new(x: Xpriv) -> Self {
        Self(x)
    }

    pub fn expose(&self) -> &Xpriv {
        &self.0
    }

    /// 继续派生；结果同样被包装。
    pub fn derive(
        &self,
        secp: &Secp256k1<All>,
        path: &DerivationPath,
    ) -> Result<SecretXpriv, KeyError> {
        self.0
            .derive_priv(secp, path)
            .map(SecretXpriv::new)
            .map_err(|_| KeyError::Derivation)
    }
}

impl Drop for SecretXpriv {
    fn drop(&mut self) {
        self.0.private_key.non_secure_erase();
        wipe_bytes(self.0.chain_code.as_mut());
    }
}

impl core::fmt::Debug for SecretXpriv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretXpriv(<已隐藏>)")
    }
}

/// 由 BIP39 种子生成 BIP32 根私钥。
pub fn master(seed: &SecretBytes<64>, network: Network) -> Result<SecretXpriv, KeyError> {
    Xpriv::new_master(NetworkKind::from(network), seed.expose())
        .map(SecretXpriv::new)
        .map_err(|_| KeyError::Derivation)
}

/// 根私钥的指纹（PSBT 中用来认出"这是我的钥匙"）。
pub fn master_fingerprint(
    secp: &Secp256k1<All>,
    master: &SecretXpriv,
) -> bitcoin::bip32::Fingerprint {
    master.expose().fingerprint(secp)
}

/// BIP84 账户路径：m/84'/coin'/account'（主网 coin=0，测试网 coin=1）。
pub fn bip84_account_path(network: Network, account: u32) -> Result<DerivationPath, KeyError> {
    let coin = if network == Network::Bitcoin { 0 } else { 1 };
    let parts = [84, coin, account]
        .into_iter()
        .map(|i| ChildNumber::from_hardened_idx(i).map_err(|_| KeyError::Derivation))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DerivationPath::from(parts))
}

/// 导出 BIP84 账户公钥（给观察机）。
pub fn bip84_account_xpub(
    secp: &Secp256k1<All>,
    seed: &SecretBytes<64>,
    network: Network,
    account: u32,
) -> Result<Xpub, KeyError> {
    let path = bip84_account_path(network, account)?;
    let account_xprv = master(seed, network)?.derive(secp, &path)?;
    Ok(Xpub::from_priv(secp, account_xprv.expose()))
}

/// 由账户公钥计算 BIP84 地址：`change` 0=收款、1=找零。只用公钥，观察机也可调用。
pub fn bip84_address(
    secp: &Secp256k1<All>,
    account_xpub: &Xpub,
    change: bool,
    index: u32,
    network: Network,
) -> Result<Address, KeyError> {
    let path = [
        ChildNumber::from_normal_idx(u32::from(change)).map_err(|_| KeyError::Derivation)?,
        ChildNumber::from_normal_idx(index).map_err(|_| KeyError::Derivation)?,
    ];
    let child = account_xpub
        .derive_pub(secp, &path)
        .map_err(|_| KeyError::Derivation)?;
    Ok(Address::p2wpkh(
        &CompressedPublicKey(child.public_key),
        network,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use aw_bip39::Mnemonic;

    const ABANDON_ABOUT: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn ctx() -> Secp256k1<All> {
        secp_context(&[7u8; 32])
    }

    /// BIP39 官方向量的第 4 列：BIP32 根私钥（passphrase "TREZOR"）。
    #[test]
    fn master_xprv_matches_bip39_vectors() {
        let json = include_str!("../../../../third_party/python-mnemonic/vectors.json");
        let english = &json[json.find("\"english\"").unwrap()..];
        let english = &english[..english.find("\n    ],").unwrap()];
        let strings: Vec<&str> = english.split('"').skip(3).step_by(2).collect();
        let (groups, rest) = strings.as_chunks::<4>();
        assert!(rest.is_empty());
        for [_entropy, mnemonic, _seed, expected_xprv] in groups {
            let m = Mnemonic::parse(mnemonic).unwrap();
            let xprv = master(&m.to_seed("TREZOR").unwrap(), Network::Bitcoin).unwrap();
            assert_eq!(&xprv.expose().to_string(), expected_xprv);
        }
        assert_eq!(groups.len(), 24);
    }

    /// BIP84 官方向量（bitcoin/bips@927b6de bip-0084.mediawiki 第 77–90 行）。
    #[test]
    fn bip84_addresses_match_official_vectors() {
        let secp = ctx();
        let seed = Mnemonic::parse(ABANDON_ABOUT).unwrap().to_seed("").unwrap();
        let xpub = bip84_account_xpub(&secp, &seed, Network::Bitcoin, 0).unwrap();
        let addr = |change, i| {
            bip84_address(&secp, &xpub, change, i, Network::Bitcoin)
                .unwrap()
                .to_string()
        };
        assert_eq!(addr(false, 0), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(addr(false, 1), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(addr(true, 0), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    }

    #[test]
    fn testnet_uses_coin_type_1_and_tb_prefix() {
        let secp = ctx();
        let seed = Mnemonic::parse(ABANDON_ABOUT).unwrap().to_seed("").unwrap();
        assert_eq!(
            bip84_account_path(Network::Testnet, 0).unwrap().to_string(),
            "84'/1'/0'"
        );
        let xpub = bip84_account_xpub(&secp, &seed, Network::Testnet, 0).unwrap();
        let a = bip84_address(&secp, &xpub, false, 0, Network::Testnet)
            .unwrap()
            .to_string();
        assert!(a.starts_with("tb1q"), "{a}");
    }

    #[test]
    fn randomization_does_not_change_results() {
        let seed = Mnemonic::parse(ABANDON_ABOUT).unwrap().to_seed("").unwrap();
        let a = bip84_account_xpub(&secp_context(&[1u8; 32]), &seed, Network::Bitcoin, 0).unwrap();
        let b = bip84_account_xpub(&secp_context(&[2u8; 32]), &seed, Network::Bitcoin, 0).unwrap();
        assert_eq!(a, b);
    }
}
