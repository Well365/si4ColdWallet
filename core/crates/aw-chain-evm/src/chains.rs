//! 已知 EVM 链与已知代币。未知链仍可签名，但会显示警告并标出链 ID（威胁 T11：永远显示链 ID）。
//!
//! 代币表只用于把原始数值换算成可读金额；合约地址始终完整显示，不能只凭符号判断真伪。

pub struct ChainInfo {
    pub name: &'static str,
    pub network: &'static str,
    /// 原生币符号（小数位一律 18）
    pub symbol: &'static str,
    pub testnet: bool,
}

const fn c(
    name: &'static str,
    network: &'static str,
    symbol: &'static str,
    testnet: bool,
) -> ChainInfo {
    ChainInfo {
        name,
        network,
        symbol,
        testnet,
    }
}

pub fn chain_info(id: u64) -> Option<ChainInfo> {
    Some(match id {
        1 => c("Ethereum", "主网", "ETH", false),
        11_155_111 => c("Ethereum", "Sepolia 测试网", "SepoliaETH", true),
        17_000 => c("Ethereum", "Holesky 测试网", "HoleskyETH", true),
        56 => c("BNB Smart Chain", "主网", "BNB", false),
        97 => c("BNB Smart Chain", "测试网", "tBNB", true),
        137 => c("Polygon PoS", "主网", "POL", false),
        10 => c("OP Mainnet", "主网", "ETH", false),
        42_161 => c("Arbitrum One", "主网", "ETH", false),
        8_453 => c("Base", "主网", "ETH", false),
        43_114 => c("Avalanche C-Chain", "主网", "AVAX", false),
        _ => return None,
    })
}

pub struct TokenInfo {
    pub symbol: &'static str,
    pub decimals: u32,
}

/// (链 ID, 合约地址小写十六进制) → 代币信息。只收录主流稳定币。
pub fn token_info(chain_id: u64, contract: &[u8; 20]) -> Option<TokenInfo> {
    let hex = aw_common::hex::encode(contract);
    let t = |symbol, decimals| Some(TokenInfo { symbol, decimals });
    match (chain_id, hex.as_str()) {
        (1, "dac17f958d2ee523a2206206994597c13d831ec7") => t("USDT", 6),
        (1, "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") => t("USDC", 6),
        (1, "6b175474e89094c44da98b954eedeac495271d0f") => t("DAI", 18),
        (56, "55d398326f99059ff775485246999027b3197955") => t("USDT", 18),
        (56, "8ac76a51cc950d9822d68b83fe1ad97b32cd580d") => t("USDC", 18),
        _ => None,
    }
}

/// Uniswap Permit2：对它的授权等于把代币支配权交给任何能拿到你签名许可的人
pub const PERMIT2: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xd4, 0x73, 0x03, 0x0f, 0x11, 0x6d, 0xde, 0xe9, 0xf6, 0xb4,
    0x3a, 0xc7, 0x8b, 0xa3,
];
