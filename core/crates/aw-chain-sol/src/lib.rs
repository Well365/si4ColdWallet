//! Solana（P2：先做地址）。
//!
//! 账户路径（SLIP-10 Ed25519，全部强化）有三种方案，同一助记词在不同钱包里会得到不同地址（决策 D34）：
//! - `m/44'/501'/i'/0'`：Phantom、Solflare、Trezor、Solana CLI 默认；Ledger Live 也会扫描（solanaBip44Change）
//! - `m/44'/501'/i'`：Ledger Live 添加的 Solana 账户（solanaSub）
//! - `m/44'/501'`：Ledger Live 最早建立的 Solana 主账户（solanaMain，只有一个）
//!
//! 地址 = Base58(公钥)。私钥派生在签名机的 aw-keys 中完成；本模块只处理公开信息。

pub mod message;
pub mod programs;
pub mod review;

/// Solana 审查与签名的错误
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolError {
    /// 消息无法完整、严格地解析
    Parse,
    /// v0 消息使用地址查找表：被引用的地址不在消息里，签名机离线无法核实
    LookupTable,
    /// 本账户不是这笔交易的签名者
    NotSigner,
    /// System Assign / AssignWithSeed：改变账户归属的程序
    OwnerChange,
    /// SPL Token SetAuthority：交出代币账户或 mint 的控制权
    SetAuthority,
    /// 数值溢出
    Overflow,
}

/// 派生方案（D34）。`ALL` 的顺序就是 FFI `aw_session_address` 的 scheme 编号
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `m/44'/501'/i'/0'`
    Phantom,
    /// `m/44'/501'/i'`
    LedgerLive,
    /// `m/44'/501'`
    LedgerMain,
}

impl Scheme {
    pub const ALL: [Scheme; 3] = [Scheme::Phantom, Scheme::LedgerLive, Scheme::LedgerMain];

    /// 第 i 个账户的路径（全部强化；主账户方案与 i 无关）
    pub fn account_path(self, index: u32) -> Vec<u32> {
        match self {
            Self::Phantom => vec![44, 501, index, 0],
            Self::LedgerLive => vec![44, 501, index],
            Self::LedgerMain => vec![44, 501],
        }
    }

    pub fn path_string(self, index: u32) -> String {
        match self {
            Self::Phantom => format!("m/44'/501'/{index}'/0'"),
            Self::LedgerLive => format!("m/44'/501'/{index}'"),
            Self::LedgerMain => "m/44'/501'".to_owned(),
        }
    }

    /// 这种方案有几个账户：主账户方案只有一个，其余最多 `max` 个
    pub fn account_count(self, max: u32) -> u32 {
        match self {
            Self::LedgerMain => 1,
            Self::Phantom | Self::LedgerLive => max,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Phantom => "Phantom / Solflare / Trezor",
            Self::LedgerLive => "Ledger Live",
            Self::LedgerMain => "Ledger Live 主账户",
        }
    }

    pub fn note(self) -> &'static str {
        match self {
            Self::Phantom => {
                "与 Phantom、Solflare、Trezor 默认路径一致；Ledger Live 也会扫描这条路径"
            }
            Self::LedgerLive => "Ledger Live 添加的 Solana 账户用这条路径（44'/501'/序号'）",
            Self::LedgerMain => "Ledger Live 最早建立的 Solana 主账户（44'/501'，只有这一个）",
        }
    }
}

/// 默认方案（Phantom）第 i 个账户的路径（全部强化）
pub fn account_path(index: u32) -> [u32; 4] {
    [44, 501, index, 0]
}

pub fn path_string(index: u32) -> String {
    Scheme::Phantom.path_string(index)
}

/// 地址 = Base58(32 字节 Ed25519 公钥)，没有校验和
pub fn address(pubkey: &[u8; 32]) -> String {
    base58ck::encode(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_program_and_formats() {
        // 系统程序地址是全零公钥
        assert_eq!(address(&[0; 32]), "11111111111111111111111111111111");
        assert_eq!(path_string(3), "m/44'/501'/3'/0'");
        assert_eq!(account_path(2), [44, 501, 2, 0]);
    }

    /// D34：三种方案的路径与账户数
    #[test]
    fn schemes_paths_and_counts() {
        assert_eq!(Scheme::Phantom.account_path(2).as_slice(), &account_path(2));
        assert_eq!(Scheme::Phantom.path_string(2), path_string(2));
        assert_eq!(Scheme::LedgerLive.account_path(7), vec![44, 501, 7]);
        assert_eq!(Scheme::LedgerLive.path_string(0), "m/44'/501'/0'");
        assert_eq!(Scheme::LedgerMain.account_path(5), vec![44, 501]);
        assert_eq!(Scheme::LedgerMain.path_string(5), "m/44'/501'");
        assert_eq!(Scheme::LedgerMain.account_count(20), 1);
        assert_eq!(Scheme::LedgerLive.account_count(20), 20);
        assert_eq!(Scheme::ALL.len(), 3);
        assert_eq!(Scheme::ALL[0], Scheme::Phantom);
    }
}
