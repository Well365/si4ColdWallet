//! 区块浏览器网址（只用于显示）。
//!
//! 签名机永不联网：网址只作为文字显示，不能点击，由用户在另一台联网设备的浏览器里输入。
//! 网址只由固定前缀与地址拼成；地址必须全部是字母数字（各链地址编码都只用字母数字），
//! 否则不生成，避免被构造的"地址"把网址改成别的站点。

use crate::json::Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Btc,
    Evm,
    Sol,
    Doge,
    Tron,
    Near,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explorer {
    pub name: &'static str,
    pub url: String,
}

/// (名称, 前缀, 后缀)
type Entry = (&'static str, &'static str, &'static str);

fn entries(chain: Chain, testnet: bool) -> &'static [Entry] {
    match (chain, testnet) {
        (Chain::Btc, false) => &[("mempool.space", "https://mempool.space/address/", "")],
        (Chain::Btc, true) => &[(
            "mempool.space（testnet4）",
            "https://mempool.space/testnet4/address/",
            "",
        )],
        (Chain::Evm, false) => &[
            ("Etherscan（以太坊）", "https://etherscan.io/address/", ""),
            (
                "BscScan（BNB Smart Chain）",
                "https://bscscan.com/address/",
                "",
            ),
        ],
        (Chain::Evm, true) => &[
            (
                "Etherscan（Sepolia 测试网）",
                "https://sepolia.etherscan.io/address/",
                "",
            ),
            (
                "BscScan（测试网）",
                "https://testnet.bscscan.com/address/",
                "",
            ),
        ],
        (Chain::Sol, false) => &[(
            "Solana Explorer",
            "https://explorer.solana.com/address/",
            "",
        )],
        (Chain::Sol, true) => &[(
            "Solana Explorer（devnet）",
            "https://explorer.solana.com/address/",
            "?cluster=devnet",
        )],
        (Chain::Doge, false) => &[("Blockchair", "https://blockchair.com/dogecoin/address/", "")],
        // Dogecoin 测试网没有常用、长期可用的公共浏览器
        (Chain::Doge, true) => &[],
        (Chain::Tron, false) => &[("Tronscan", "https://tronscan.org/#/address/", "")],
        (Chain::Tron, true) => &[(
            "Tronscan（Nile 测试网）",
            "https://nile.tronscan.org/#/address/",
            "",
        )],
        (Chain::Near, false) => &[("NearBlocks", "https://nearblocks.io/address/", "")],
        (Chain::Near, true) => &[(
            "NearBlocks（测试网）",
            "https://testnet.nearblocks.io/address/",
            "",
        )],
    }
}

/// 某个地址在各区块浏览器上的网址；地址含字母数字以外的字符时返回空列表
pub fn address_urls(chain: Chain, testnet: bool, address: &str) -> Vec<Explorer> {
    if address.is_empty() || !address.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Vec::new();
    }
    entries(chain, testnet)
        .iter()
        .map(|(name, prefix, suffix)| Explorer {
            name,
            url: format!("{prefix}{address}{suffix}"),
        })
        .collect()
}

pub fn to_json(list: &[Explorer]) -> Json {
    Json::Array(
        list.iter()
            .map(|e| {
                Json::obj(vec![
                    ("name", Json::str(e.name)),
                    ("url", Json::str(e.url.as_str())),
                ])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn urls_for_each_chain() {
        let btc = address_urls(
            Chain::Btc,
            false,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        );
        assert_eq!(
            btc[0].url,
            "https://mempool.space/address/bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        let evm = address_urls(
            Chain::Evm,
            true,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        );
        assert_eq!(evm.len(), 2);
        assert_eq!(
            evm[0].url,
            "https://sepolia.etherscan.io/address/0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        let sol = address_urls(
            Chain::Sol,
            true,
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        );
        assert!(sol[0]
            .url
            .ends_with("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk?cluster=devnet"));
        assert!(address_urls(Chain::Doge, true, "nabc").is_empty());
        assert_eq!(
            address_urls(Chain::Tron, false, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH")[0].url,
            "https://tronscan.org/#/address/TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"
        );
        assert_eq!(
            to_json(&address_urls(Chain::Near, false, "abc")).to_string_compact(),
            r#"[{"name":"NearBlocks","url":"https://nearblocks.io/address/abc"}]"#
        );
    }

    #[test]
    fn refuses_non_alphanumeric_addresses() {
        for bad in ["", "a/b", "x@evil.example", "a?b", "a b", "a#b", "ａ"] {
            assert!(address_urls(Chain::Btc, false, bad).is_empty(), "{bad}");
        }
    }
}
