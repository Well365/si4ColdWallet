//! 签名机直接显示各链收款地址（P2：先做地址）。
//!
//! 解锁时只保存**公开信息**：BTC / EVM 的账户公钥已在会话中；DOGE、TRON 保存账户扩展公钥；
//! Solana、NEAR 的 Ed25519 路径全部强化、不能由公钥继续派生，所以解锁时预先算好前 20 个账户的公钥，
//! 派生用的私钥随即清零（交易签名在 P2c / P2d 实现时再按需派生）。
//! Solana 有三种派生方案（Phantom / Ledger Live / Ledger Live 主账户，决策 D34），每种都预先算好。

use aw_chain_sol::Scheme as SolScheme;
use aw_common::explorer::{self, Chain};
use aw_common::json::Json;
use aw_common::secret::SecretBytes;
use aw_keys::slip10::Ed25519Node;
use aw_keys::SecretXpriv;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};

/// Ed25519 链预先计算的账户数
pub const ED_ACCOUNTS: u32 = 20;

pub const CHAIN_BTC: u32 = 0;
pub const CHAIN_EVM: u32 = 1;
pub const CHAIN_SOL: u32 = 2;
pub const CHAIN_DOGE: u32 = 3;
pub const CHAIN_TRON: u32 = 4;
pub const CHAIN_NEAR: u32 = 5;

pub struct Addresses {
    testnet: bool,
    doge: Xpub,
    tron: Xpub,
    /// 按 `SolScheme::ALL` 的顺序，每种方案预先算好的账户公钥（主账户方案只有 1 个）
    sol: Vec<Vec<[u8; 32]>>,
    near: Vec<[u8; 32]>,
}

fn account_xpub(secp: &Secp256k1<All>, master: &SecretXpriv, coin: u32) -> Option<Xpub> {
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44).ok()?,
        ChildNumber::from_hardened_idx(coin).ok()?,
        ChildNumber::from_hardened_idx(0).ok()?,
    ]);
    let x = master.derive(secp, &path).ok()?;
    Some(Xpub::from_priv(secp, x.expose()))
}

impl Addresses {
    pub fn derive(
        secp: &Secp256k1<All>,
        master: &SecretXpriv,
        seed: &SecretBytes<64>,
        testnet: bool,
    ) -> Option<Self> {
        let ed = Ed25519Node::master(seed);
        let ed_pub = |path: &[u32]| ed.derive(path).ok()?.public_key().ok();
        Some(Self {
            testnet,
            doge: account_xpub(secp, master, aw_chain_btc::doge::coin_type(testnet))?,
            tron: account_xpub(secp, master, aw_chain_tron::COIN_TYPE)?,
            sol: SolScheme::ALL
                .iter()
                .map(|s| {
                    (0..s.account_count(ED_ACCOUNTS))
                        .map(|i| ed_pub(&s.account_path(i)))
                        .collect::<Option<Vec<_>>>()
                })
                .collect::<Option<_>>()?,
            near: (0..ED_ACCOUNTS)
                .map(|i| ed_pub(&aw_chain_near::account_path(i)))
                .collect::<Option<_>>()?,
        })
    }

    fn child(
        &self,
        xpub: &Xpub,
        secp: &Secp256k1<All>,
        index: u32,
    ) -> Option<bitcoin::secp256k1::PublicKey> {
        let path = [
            ChildNumber::from_normal_idx(0).ok()?,
            ChildNumber::from_normal_idx(index).ok()?,
        ];
        xpub.derive_pub(secp, &path).ok().map(|x| x.public_key)
    }

    /// 第 index 个地址：(链名, 路径, 地址, 附加说明)。`scheme` 是账户类型：只有 Solana 有多种（D34），其他链必须为 0
    pub fn describe(
        &self,
        secp: &Secp256k1<All>,
        btc: &aw_chain_btc::Account,
        evm: &aw_chain_evm::Account,
        chain: u32,
        scheme: u32,
        index: u32,
    ) -> Option<Json> {
        if chain != CHAIN_SOL && scheme != 0 {
            return None;
        }
        let ed = |list: &Vec<[u8; 32]>| list.get(usize::try_from(index).ok()?).copied();
        let (name, path, address, note, kind) = match chain {
            CHAIN_BTC => (
                if self.testnet {
                    "Bitcoin 测试网"
                } else {
                    "Bitcoin"
                }
                .to_owned(),
                format!("m/84'/{}'/0'/0/{index}", u32::from(self.testnet)),
                btc.address(secp, false, index).ok()?.to_string(),
                "原生隔离见证（bc1 / tb1 开头）".to_owned(),
                Chain::Btc,
            ),
            CHAIN_EVM => (
                "以太坊 / BNB Smart Chain 等 EVM 链".to_owned(),
                format!("m/44'/60'/0'/0/{index}"),
                aw_chain_evm::checksum_address(&evm.address(secp, index).ok()?),
                "所有 EVM 链共用同一个地址".to_owned(),
                Chain::Evm,
            ),
            CHAIN_SOL => {
                let which = usize::try_from(scheme).ok()?;
                let s = *SolScheme::ALL.get(which)?;
                let pk = ed(self.sol.get(which)?)?;
                (
                    format!("Solana（{}）", s.label()),
                    s.path_string(index),
                    aw_chain_sol::address(&pk),
                    s.note().to_owned(),
                    Chain::Sol,
                )
            }
            CHAIN_DOGE => (
                if self.testnet {
                    "Dogecoin 测试网"
                } else {
                    "Dogecoin"
                }
                .to_owned(),
                aw_chain_btc::doge::path_string(self.testnet, index),
                aw_chain_btc::doge::address(&self.child(&self.doge, secp, index)?, self.testnet),
                "P2PKH（D 开头；测试网 n 开头）".to_owned(),
                Chain::Doge,
            ),
            CHAIN_TRON => (
                "TRON".to_owned(),
                aw_chain_tron::path_string(index),
                aw_chain_tron::address(&self.child(&self.tron, secp, index)?),
                "与 TronLink 默认路径一致".to_owned(),
                Chain::Tron,
            ),
            CHAIN_NEAR => {
                let pk = ed(&self.near)?;
                (
                    "NEAR".to_owned(),
                    aw_chain_near::path_string(index),
                    aw_chain_near::implicit_account(&pk),
                    format!("隐式账户；公钥 {}", aw_chain_near::public_key_text(&pk)),
                    Chain::Near,
                )
            }
            _ => return None,
        };
        Some(Json::obj(vec![
            ("chain", Json::str(name)),
            ("path", Json::str(path)),
            ("address", Json::str(address.as_str())),
            ("note", Json::str(note)),
            // 只用于显示：签名机不联网，网址由用户在别的设备上输入
            (
                "explorers",
                explorer::to_json(&explorer::address_urls(kind, self.testnet, &address)),
            ),
        ]))
    }
}
