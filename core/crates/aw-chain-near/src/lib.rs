//! NEAR（P2：先做账户格式）。
//!
//! 账户路径：SLIP-10 Ed25519 `m/44'/397'/i'`（与 MyNearWallet / near-cli 用助记词导入时一致）。
//! 注意：NEAR 的 Ledger 应用使用 `44'/397'/0'/0'/1'`，同一助记词在 Ledger 上看到的是另一个账户。
//! 隐式账户名 = 公钥的 64 位小写十六进制；公钥文本格式 = "ed25519:" + Base58(公钥)。

pub fn account_path(index: u32) -> [u32; 3] {
    [44, 397, index]
}

pub fn path_string(index: u32) -> String {
    format!("m/44'/397'/{index}'")
}

/// 隐式账户名（向它转账即创建账户）
pub fn implicit_account(pubkey: &[u8; 32]) -> String {
    aw_common::hex::encode(pubkey)
}

/// 公钥文本（用于添加访问密钥等）
pub fn public_key_text(pubkey: &[u8; 32]) -> String {
    format!("ed25519:{}", base58ck::encode(pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let pk = [0x11; 32];
        assert_eq!(implicit_account(&pk).len(), 64);
        assert!(public_key_text(&pk).starts_with("ed25519:"));
        assert_eq!(path_string(0), "m/44'/397'/0'");
    }
}
