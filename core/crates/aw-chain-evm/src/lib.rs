//! EVM 链（ETH、BNB Smart Chain 及其他按 chain-id 区分的 EVM 链），P2a。
//!
//! 与 BTC 模块同一套思路：签名机不信任请求中的任何声明，全部从待签字节重新解析；
//! "默认拒签"的危险操作（docs/01）直接返回错误，界面无法绕过。
//!
//! 账户：BIP44 `m/44'/60'/0'`，地址 `m/44'/60'/0'/0/i`（MetaMask、Keystone 等通用）。

pub mod abi;
pub mod account_ur;
pub mod chains;
pub mod eip712;
pub mod keccak;
pub mod message;
pub mod request;
pub mod review;
pub mod rlp;
pub mod tx;
mod typed_known;
pub mod typed_review;
pub mod uint;

#[cfg(feature = "signing")]
pub mod sign;
#[cfg(feature = "watch")]
pub mod watch;

use aw_ur::registry::KeyPath;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1, Verification};

/// SLIP-44 币种：ETH 及所有 EVM 链共用
pub const COIN_TYPE: u32 = 60;
/// 待签数据上限（大于此的请求直接拒绝）
pub const MAX_SIGN_DATA: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmError {
    /// 数据无法解析或结构不对
    Parse,
    /// 不支持的交易类型（如 blob 交易）或数据类型
    Unsupported,
    /// EIP-7702 授权交易：会把账户的代码委托给别的合约，默认拒签（docs/01）
    Eip7702,
    /// 没有链 ID 的旧式交易：可在任何链上重放，拒签
    NoReplayProtection,
    /// 请求声明的链 ID 与交易内的不一致
    ChainMismatch,
    /// 派生路径不是本账户的地址路径，或来源指纹不符
    PathMismatch,
    /// 请求声明的地址与路径派生出的地址不一致
    AddressMismatch,
    /// Safe 多签的 DELEGATECALL：可改写多签本身，默认拒签（docs/01）
    DelegateCall,
    /// 数值溢出
    Overflow,
    /// 密钥派生失败
    Derivation,
    /// 签名自检失败（恢复出的地址与本账户不符）
    SelfCheck,
    /// 签名无效或不属于本账户（观察机核对签名机返回值时）
    BadSignature,
    /// 签名机返回的签名与请求不对应
    RequestMismatch,
    /// 预先批准一笔看不到内容的交易（Safe approveHash），默认拒签
    BlindApproval,
    /// 需要用户确认高风险警告后才能签名
    NeedsConfirmation,
    /// 待签内容里有超长字段，签名机无法完整显示，拒签（避免"太长看不完"变成盲签）
    TooLong,
    /// Safe 多签对自身的管理调用（所有者 / 阈值 / 模块 / 守卫 / 回退处理器）：移交多签控制权，默认拒签（D33）
    SafeAdmin,
}

impl From<rlp::RlpError> for EvmError {
    fn from(_: rlp::RlpError) -> Self {
        EvmError::Parse
    }
}

/// 账户 m/44'/60'/0' 的公开信息（签名机导出，观察机导入）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub master_fingerprint: Fingerprint,
    pub account_xpub: Xpub,
}

pub fn account_path() -> DerivationPath {
    DerivationPath::from(vec![
        ChildNumber::Hardened { index: 44 },
        ChildNumber::Hardened { index: COIN_TYPE },
        ChildNumber::Hardened { index: 0 },
    ])
}

impl Account {
    pub fn pubkey<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        index: u32,
    ) -> Result<PublicKey, EvmError> {
        let path = [
            ChildNumber::from_normal_idx(0).map_err(|_| EvmError::Derivation)?,
            ChildNumber::from_normal_idx(index).map_err(|_| EvmError::Derivation)?,
        ];
        self.account_xpub
            .derive_pub(secp, &path)
            .map(|x| x.public_key)
            .map_err(|_| EvmError::Derivation)
    }

    pub fn address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        index: u32,
    ) -> Result<[u8; 20], EvmError> {
        Ok(address_of(&self.pubkey(secp, index)?))
    }

    /// 路径必须正好是 m/44'/60'/0'/0/i；带来源指纹时必须是本钱包。返回 i。
    pub fn match_path(&self, kp: &KeyPath) -> Option<u32> {
        if kp
            .source_fingerprint
            .is_some_and(|fp| fp.to_be_bytes() != self.master_fingerprint.to_bytes())
        {
            return None;
        }
        match kp.components.as_slice() {
            [(44, true), (60, true), (0, true), (0, false), (i, false)] => Some(*i),
            _ => None,
        }
    }

    pub fn keypath(&self, index: u32) -> KeyPath {
        KeyPath {
            components: vec![
                (44, true),
                (COIN_TYPE, true),
                (0, true),
                (0, false),
                (index, false),
            ],
            source_fingerprint: Some(u32::from_be_bytes(self.master_fingerprint.to_bytes())),
            depth: None,
        }
    }
}

/// 以太坊地址 = Keccak-256(未压缩公钥去掉 0x04 前缀) 的后 20 字节
pub fn address_of(pk: &PublicKey) -> [u8; 20] {
    let uncompressed = pk.serialize_uncompressed();
    let h = keccak::keccak256(uncompressed.get(1..).unwrap_or(&[]));
    let mut a = [0u8; 20];
    a.copy_from_slice(h.get(12..).unwrap_or(&[0; 20]));
    a
}

/// EIP-55 大小写校验格式："0x" + 40 位十六进制
pub fn checksum_address(a: &[u8; 20]) -> String {
    let lower = aw_common::hex::encode(a);
    let h = keccak::keccak256(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = h
            .get(i / 2)
            .map_or(0, |b| if i % 2 == 0 { b >> 4 } else { b & 0x0f });
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// 解析 "0x…" 地址；若含大写字母，必须符合 EIP-55 校验（防手抄错误）
pub fn parse_address(s: &str) -> Option<[u8; 20]> {
    let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    if body.len() != 40 {
        return None;
    }
    let bytes = aw_common::hex::decode(&body.to_ascii_lowercase())?;
    let mut a = [0u8; 20];
    a.copy_from_slice(&bytes);
    let mixed = body.chars().any(|c| c.is_ascii_uppercase())
        && body.chars().any(|c| c.is_ascii_lowercase());
    if mixed && checksum_address(&a).get(2..) != Some(body) {
        return None;
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// EIP-55 规范中的示例
    #[test]
    fn eip55_examples() {
        for s in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let a = parse_address(s).unwrap();
            assert_eq!(checksum_address(&a), s);
        }
        // 大小写混合但校验错误
        assert!(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD").is_none());
        // 全小写可接受
        assert!(parse_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").is_some());
        assert!(parse_address("0x1234").is_none());
    }
}
