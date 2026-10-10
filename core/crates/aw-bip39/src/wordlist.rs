//! BIP39 英文词表。
//!
//! 文件来源：third_party/python-mnemonic（Trezor 参考实现，tag v0.21），
//! 已与 bitcoin/bips 仓库 bip-0039/english.txt 交叉核对，SHA-256 均为下方常量。
//! 运行时自检会重新计算哈希，防止词表被篡改。

use bitcoin_hashes::{sha256, Hash};
use std::sync::OnceLock;

/// 词表原文（每行一个单词，共 2048 行）。
pub(crate) const ENGLISH_TXT: &str =
    include_str!("../../../../third_party/python-mnemonic/src/mnemonic/wordlist/english.txt");

/// 词表 SHA-256（bitcoin/bips 与 python-mnemonic 一致）。
pub const ENGLISH_SHA256: &str = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

pub const WORD_COUNT: usize = 2048;

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| ENGLISH_TXT.lines().collect())
}

/// 词表是否完好：哈希正确、正好 2048 个、按字母序严格递增（`index_of` 依赖二分查找）。
pub fn verify() -> bool {
    let digest = sha256::Hash::hash(ENGLISH_TXT.as_bytes());
    if aw_common::hex::encode(digest.as_byte_array()) != ENGLISH_SHA256 {
        return false;
    }
    let w = words();
    w.len() == WORD_COUNT && w.windows(2).all(|p| matches!(p, [a, b] if a < b))
}

/// 序号 → 单词。
pub fn word(index: u16) -> Option<&'static str> {
    words().get(usize::from(index)).copied()
}

/// 单词 → 序号（精确匹配，小写）。
pub fn index_of(word: &str) -> Option<u16> {
    words()
        .binary_search(&word)
        .ok()
        .and_then(|i| u16::try_from(i).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_intact() {
        assert!(verify());
    }

    #[test]
    fn first_and_last_words() {
        assert_eq!(word(0), Some("abandon"));
        assert_eq!(word(2047), Some("zoo"));
        assert_eq!(word(2048), None);
        assert_eq!(index_of("abandon"), Some(0));
        assert_eq!(index_of("zoo"), Some(2047));
        assert_eq!(index_of("Zoo"), None);
        assert_eq!(index_of("notaword"), None);
    }
}
