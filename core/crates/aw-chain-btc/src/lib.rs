//! BTC（BIP84 原生隔离见证 P2WPKH）交易处理。
//!
//! - `review`：签名机在签名前做的全部检查，并生成给用户看的内容（两端都可用，无秘密）
//! - `sign`（feature `signing`）：只在签名机中编译
//! - `watch`（feature `watch`）：只在观察机中编译
//!
//! 威胁模型：观察机已被控制（T5），所以签名机不信任 PSBT 里的任何"声明"，一切都自己重新计算。

pub mod account_ur;
pub mod doge;
pub mod review;
#[cfg(feature = "signing")]
pub mod sign;
#[cfg(feature = "watch")]
pub mod watch;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{CompressedPublicKey, Network, ScriptBuf};

/// 单笔交易的输入/输出数量上限（防止恶意 PSBT 让签名机做大量计算或界面无法显示）。
pub const MAX_IO: usize = 256;
/// P2WPKH 输出的粉尘阈值（聪）。
pub const DUST_P2WPKH: u64 = 294;
/// 一个 P2WPKH 输入签名后的见证最大重量（WU）：1 + (1+72) + (1+33)。
pub const P2WPKH_WITNESS_WU: u64 = 108;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcError {
    /// PSBT 无法解析
    Parse,
    /// 没有输入或没有输出
    Empty,
    /// 输入或输出数量超过上限
    TooManyIo,
    /// 输入已经最终化（含 final_script_sig/witness）
    AlreadyFinalized(usize),
    /// 缺少完整的前序交易（防手续费欺骗，必须提供）
    MissingPrevTx(usize),
    /// 前序交易的哈希与输入引用不符
    PrevTxMismatch(usize),
    /// witness_utxo 与前序交易中的输出不一致
    WitnessUtxoMismatch(usize),
    /// 输入不是 P2WPKH
    UnsupportedInputScript(usize),
    /// 输入不属于本钱包（没有匹配的派生路径，或路径与脚本不符）
    ForeignInput(usize),
    /// 输入要求的签名类型不是 SIGHASH_ALL
    SighashNotAll(usize),
    /// 输出声称是本钱包地址，但脚本与派生路径不符（典型的"找零替换"攻击）
    ChangeMismatch(usize),
    /// 输出脚本无法显示为地址（不支持的类型）
    UnsupportedOutputScript(usize),
    /// 输出总额大于输入总额
    NegativeFee,
    /// 金额溢出
    AmountOverflow,
    /// 派生失败
    Derivation,
    /// 签名后自检失败
    SelfCheck,
    /// 观察机：签名机返回的交易与原交易不同
    TxChanged,
    /// 观察机：缺少或多出签名、签名无效
    BadSignature(usize),
    /// 观察机：余额不足
    InsufficientFunds,
    /// 观察机：UTXO 与派生地址不符
    UtxoNotOurs(usize),
}

/// 一个 BIP84 账户（只含公开信息）：m/84'/coin'/account'
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub network: Network,
    pub master_fingerprint: Fingerprint,
    pub account_path: DerivationPath,
    pub account_xpub: Xpub,
}

pub fn coin_type(network: Network) -> u32 {
    if network == Network::Bitcoin {
        0
    } else {
        1
    }
}

pub fn bip84_account_path(network: Network, account: u32) -> Result<DerivationPath, BtcError> {
    [84, coin_type(network), account]
        .into_iter()
        .map(|i| ChildNumber::from_hardened_idx(i).map_err(|_| BtcError::Derivation))
        .collect::<Result<Vec<_>, _>>()
        .map(DerivationPath::from)
}

impl Account {
    /// 公钥派生：m/84'/coin'/account'/change/index
    pub fn derive_pubkey<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        change: bool,
        index: u32,
    ) -> Result<CompressedPublicKey, BtcError> {
        let path = [
            ChildNumber::from_normal_idx(u32::from(change)).map_err(|_| BtcError::Derivation)?,
            ChildNumber::from_normal_idx(index).map_err(|_| BtcError::Derivation)?,
        ];
        self.account_xpub
            .derive_pub(secp, &path)
            .map(|x| CompressedPublicKey(x.public_key))
            .map_err(|_| BtcError::Derivation)
    }

    pub fn script_for<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        change: bool,
        index: u32,
    ) -> Result<ScriptBuf, BtcError> {
        Ok(ScriptBuf::new_p2wpkh(
            &self.derive_pubkey(secp, change, index)?.wpubkey_hash(),
        ))
    }

    pub fn address<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        change: bool,
        index: u32,
    ) -> Result<bitcoin::Address, BtcError> {
        Ok(bitcoin::Address::p2wpkh(
            &self.derive_pubkey(secp, change, index)?,
            self.network,
        ))
    }

    /// 如果 `path` 正好是 本账户路径 + [0|1, 普通索引]，返回 (是否找零, 索引)。
    pub fn match_path(
        &self,
        fingerprint: Fingerprint,
        path: &DerivationPath,
    ) -> Option<(bool, u32)> {
        if fingerprint != self.master_fingerprint {
            return None;
        }
        let prefix: &[ChildNumber] = self.account_path.as_ref();
        let full: &[ChildNumber] = path.as_ref();
        if full.len() != prefix.len() + 2 || full.get(..prefix.len()) != Some(prefix) {
            return None;
        }
        match full.get(prefix.len()..) {
            Some([ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }])
                if *chain <= 1 =>
            {
                Some((*chain == 1, *index))
            }
            _ => None,
        }
    }
}
