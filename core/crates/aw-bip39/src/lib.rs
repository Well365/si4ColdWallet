//! BIP39 自实现（决策 D5）。
//!
//! - 熵（16/20/24/28/32 字节）↔ 助记词序号（12/15/18/21/24 个，每个 0..2048）
//! - 助记词 + passphrase → 64 字节种子（PBKDF2-HMAC-SHA512，2048 轮）
//!
//! 助记词在内部只以"单词序号"保存，不以字符串保存；离开作用域时清零。
//! passphrase 必须由调用方先做 Unicode NFKD 规范化（iOS 侧用系统
//! `decomposedStringWithCompatibilityMapping`），本模块不重复实现 Unicode 表。

pub mod wordlist;

use aw_common::secret::{wipe_bytes, wipe_u16, SecretBytes, SecretVec};
use bitcoin_hashes::{sha256, sha512, Hash, HashEngine, Hmac, HmacEngine};

const PBKDF2_ROUNDS: u32 = 2048;
const MAX_WORDS: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip39Error {
    /// 熵长度不是 16/20/24/28/32 字节
    BadEntropyLength,
    /// 单词个数不是 12/15/18/21/24
    BadWordCount,
    /// 单词序号超出 0..2048
    BadWordIndex,
    /// 单词不在词表中
    UnknownWord,
    /// 校验和不符（助记词抄错或被篡改）
    BadChecksum,
}

/// 助记词：内部只保存单词序号，离开作用域自动清零。
pub struct Mnemonic {
    indices: [u16; MAX_WORDS],
    len: usize,
}

impl Mnemonic {
    /// 由熵生成助记词。
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Bip39Error> {
        let ent_bits = entropy.len() * 8;
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(Bip39Error::BadEntropyLength);
        }
        let cs_bits = ent_bits / 32;
        let word_count = (ent_bits + cs_bits) / 11;
        let checksum = sha256::Hash::hash(entropy).to_byte_array();

        let mut m = Mnemonic {
            indices: [0; MAX_WORDS],
            len: word_count,
        };
        for (w, slot) in m.indices.iter_mut().take(word_count).enumerate() {
            let mut idx: u16 = 0;
            for bit in 0..11 {
                let pos = w * 11 + bit;
                let b = if pos < ent_bits {
                    bit_at(entropy, pos)
                } else {
                    bit_at(&checksum, pos - ent_bits)
                };
                idx = (idx << 1) | u16::from(b);
            }
            *slot = idx;
        }
        Ok(m)
    }

    /// 由单词序号恢复助记词，并校验校验和。
    pub fn from_indices(indices: &[u16]) -> Result<Self, Bip39Error> {
        if !matches!(indices.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(Bip39Error::BadWordCount);
        }
        if indices
            .iter()
            .any(|&i| usize::from(i) >= wordlist::WORD_COUNT)
        {
            return Err(Bip39Error::BadWordIndex);
        }
        let mut m = Mnemonic {
            indices: [0; MAX_WORDS],
            len: indices.len(),
        };
        m.indices.iter_mut().zip(indices).for_each(|(d, s)| *d = *s);

        // entropy 是 SecretBytes，任何返回路径上都会被清零
        let entropy = m.entropy_buf();
        let ent = entropy
            .expose()
            .get(..m.entropy_len())
            .ok_or(Bip39Error::BadWordCount)?;
        let expected = Mnemonic::from_entropy(ent)?;
        if expected.indices() != m.indices() {
            return Err(Bip39Error::BadChecksum);
        }
        Ok(m)
    }

    /// 由空格分隔的英文单词恢复（只用于测试与工具；App 中不经过字符串）。
    pub fn parse(sentence: &str) -> Result<Self, Bip39Error> {
        let mut buf = IndexBuf([0u16; MAX_WORDS]);
        let mut n = 0;
        for w in sentence.split_whitespace() {
            let slot = buf.0.get_mut(n).ok_or(Bip39Error::BadWordCount)?;
            *slot = wordlist::index_of(w).ok_or(Bip39Error::UnknownWord)?;
            n += 1;
        }
        Mnemonic::from_indices(buf.0.get(..n).ok_or(Bip39Error::BadWordCount)?)
    }

    pub fn word_count(&self) -> usize {
        self.len
    }

    pub fn indices(&self) -> &[u16] {
        self.indices.get(..self.len).unwrap_or(&[])
    }

    fn entropy_len(&self) -> usize {
        // 总位数 = 11 × 词数 = ENT + ENT/32 → ENT = 总位数 × 32 / 33
        self.len * 11 * 32 / 33 / 8
    }

    /// 取出熵（最多 32 字节，实际长度见 `entropy_len`），离开作用域自动清零。
    fn entropy_buf(&self) -> SecretBytes<32> {
        let mut out = SecretBytes::<32>::zeroed();
        let ent_bits = self.entropy_len() * 8;
        let bytes = out.expose_mut();
        for pos in 0..ent_bits {
            let word = self.indices.get(pos / 11).copied().unwrap_or(0);
            let bit = (word >> (10 - (pos % 11))) & 1;
            if let Some(byte) = bytes.get_mut(pos / 8) {
                *byte |= u8::try_from(bit).unwrap_or(0) << (7 - (pos % 8));
            }
        }
        out
    }

    /// 导出熵（用于 SeedQR / 备份），离开作用域自动清零。
    pub fn to_entropy(&self) -> SecretVec {
        let buf = self.entropy_buf();
        SecretVec::copy_from(buf.expose().get(..self.entropy_len()).unwrap_or(&[]))
    }

    /// 生成 64 字节种子。`passphrase_nfkd` 必须已做 NFKD 规范化。
    pub fn to_seed(&self, passphrase_nfkd: &str) -> Result<SecretBytes<64>, Bip39Error> {
        let mut seed = SecretBytes::<64>::zeroed();
        self.to_seed_into(passphrase_nfkd, &mut seed)?;
        Ok(seed)
    }

    /// 把种子直接写进调用方的缓冲区，避免按值返回在栈上留下副本（P1 Rust 审查 L2）。
    pub fn to_seed_into(
        &self,
        passphrase_nfkd: &str,
        out: &mut SecretBytes<64>,
    ) -> Result<(), Bip39Error> {
        // 最长单词 8 个字母 + 1 个空格，容量足够，不会扩容留下旧副本
        let mut sentence = SecretVecBuilder::with_capacity(self.len * 9);
        for (i, &idx) in self.indices().iter().enumerate() {
            if i > 0 {
                sentence.push(b' ');
            }
            let word = wordlist::word(idx).ok_or(Bip39Error::BadWordIndex)?;
            sentence.extend(word.as_bytes());
        }
        let mut salt = SecretVecBuilder::with_capacity(8 + passphrase_nfkd.len());
        salt.extend(b"mnemonic");
        salt.extend(passphrase_nfkd.as_bytes());

        pbkdf2_hmac_sha512_into(
            sentence.bytes(),
            salt.bytes(),
            PBKDF2_ROUNDS,
            out.expose_mut(),
        );
        Ok(())
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        wipe_u16(&mut self.indices);
    }
}

impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mnemonic({} words, <已隐藏>)", self.len)
    }
}

/// 解析过程中的单词序号缓冲区：任何返回路径都会清零（P1 Rust 审查 L3）。
struct IndexBuf([u16; MAX_WORDS]);

impl Drop for IndexBuf {
    fn drop(&mut self) {
        wipe_u16(&mut self.0);
    }
}

/// 预先分配容量、只追加不扩容的秘密缓冲区；离开作用域清零。
struct SecretVecBuilder(Vec<u8>);

impl SecretVecBuilder {
    fn with_capacity(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }

    fn push(&mut self, b: u8) {
        debug_assert!(self.0.len() < self.0.capacity(), "秘密缓冲区不应扩容");
        self.0.push(b);
    }

    fn extend(&mut self, bytes: &[u8]) {
        debug_assert!(
            self.0.len() + bytes.len() <= self.0.capacity(),
            "秘密缓冲区不应扩容"
        );
        self.0.extend_from_slice(bytes);
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretVecBuilder {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

fn bit_at(bytes: &[u8], pos: usize) -> u8 {
    bytes.get(pos / 8).map_or(0, |b| (b >> (7 - (pos % 8))) & 1)
}

/// PBKDF2-HMAC-SHA512，输出长度 = 一个哈希块（64 字节），所以只需计算第 1 块。
///
/// 带密钥的 HMAC 引擎只构造一次，每轮克隆（P1 Rust 审查 M1：减少 ipad/opad 栈残留）。
/// 第三方引擎类型没有 Drop，其内部状态由 FFI 层返回前的 `scrub_stack()` 清洗。
fn pbkdf2_hmac_sha512_into(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8; 64]) {
    let keyed = HmacEngine::<sha512::Hash>::new(password);
    let mut first = keyed.clone();
    first.input(salt);
    first.input(&1u32.to_be_bytes());
    let mut u = Hmac::<sha512::Hash>::from_engine(first).to_byte_array();
    out.copy_from_slice(&u);
    for _ in 1..rounds {
        let mut e = keyed.clone();
        e.input(&u);
        u = Hmac::<sha512::Hash>::from_engine(e).to_byte_array();
        out.iter_mut().zip(u.iter()).for_each(|(a, b)| *a ^= b);
    }
    wipe_bytes(&mut u);
}

#[cfg(test)]
mod tests;
