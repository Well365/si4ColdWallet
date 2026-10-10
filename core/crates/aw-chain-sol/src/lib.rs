//! Solana（P2：先做地址）。
//!
//! 账户路径：SLIP-10 Ed25519 `m/44'/501'/i'/0'`（Phantom、Solflare、Solana CLI 默认）；地址 = Base58(公钥)。
//! 私钥派生在签名机的 aw-keys 中完成；本模块只处理公开信息。

/// 第 i 个账户的路径（全部强化）
pub fn account_path(index: u32) -> [u32; 4] {
    [44, 501, index, 0]
}

pub fn path_string(index: u32) -> String {
    format!("m/44'/501'/{index}'/0'")
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
}
