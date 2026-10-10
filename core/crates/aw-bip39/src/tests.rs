//! 官方测试向量：third_party/python-mnemonic/vectors.json（Trezor 参考实现），passphrase 为 "TREZOR"。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use super::*;
use aw_common::hex;

const VECTORS_JSON: &str = include_str!("../../../../third_party/python-mnemonic/vectors.json");

/// 官方向量：(熵, 助记词, 种子)。第 4 列 BIP32 根私钥由 aw-keys 的测试校验。
pub struct Vector {
    pub entropy: String,
    pub mnemonic: String,
    pub seed: String,
}

/// 只解析 "english" 段：取出所有双引号字符串，每 4 个一组。格式固定，不需要通用 JSON 解析器。
pub fn english_vectors() -> Vec<Vector> {
    let key = "\"english\": [";
    let start = VECTORS_JSON.find(key).expect("找不到 english 段") + key.len();
    let rest = &VECTORS_JSON[start..];
    let section = &rest[..rest.find("\n    ],").expect("找不到 english 段结尾")];
    let strings: Vec<String> = section
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    let (groups, rest) = strings.as_chunks::<4>();
    assert!(rest.is_empty(), "向量字段数不是 4 的倍数");
    groups
        .iter()
        .map(|[e, m, s, _xprv]| Vector {
            entropy: e.clone(),
            mnemonic: m.clone(),
            seed: s.clone(),
        })
        .collect()
}

fn sentence(m: &Mnemonic) -> String {
    m.indices()
        .iter()
        .map(|&i| wordlist::word(i).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn has_all_24_english_vectors() {
    assert_eq!(english_vectors().len(), 24);
}

#[test]
fn entropy_to_mnemonic_matches_official_vectors() {
    for v in english_vectors() {
        let entropy = hex::decode(&v.entropy).unwrap();
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(sentence(&m), v.mnemonic, "熵 {}", v.entropy);
    }
}

#[test]
fn mnemonic_to_entropy_matches_official_vectors() {
    for v in english_vectors() {
        let m = Mnemonic::parse(&v.mnemonic).unwrap();
        assert_eq!(hex::encode(m.to_entropy().expose()), v.entropy);
    }
}

#[test]
fn seed_matches_official_vectors() {
    for v in english_vectors() {
        let m = Mnemonic::parse(&v.mnemonic).unwrap();
        let seed = m.to_seed("TREZOR").unwrap();
        assert_eq!(hex::encode(seed.expose()), v.seed, "助记词 {}", v.mnemonic);
    }
}

#[test]
fn rejects_bad_checksum() {
    // 最后一个词从 about 改成 abandon，校验和必然不符
    let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert_eq!(Mnemonic::parse(bad).err(), Some(Bip39Error::BadChecksum));
}

#[test]
fn rejects_unknown_word_and_bad_count() {
    assert_eq!(
        Mnemonic::parse("abandon notaword").err(),
        Some(Bip39Error::UnknownWord)
    );
    assert_eq!(
        Mnemonic::parse("abandon abandon abandon").err(),
        Some(Bip39Error::BadWordCount)
    );
    let too_many = ["abandon"; 25].join(" ");
    assert_eq!(
        Mnemonic::parse(&too_many).err(),
        Some(Bip39Error::BadWordCount)
    );
}

#[test]
fn rejects_bad_entropy_length_and_index() {
    assert_eq!(
        Mnemonic::from_entropy(&[0u8; 15]).err(),
        Some(Bip39Error::BadEntropyLength)
    );
    assert_eq!(
        Mnemonic::from_entropy(&[0u8; 33]).err(),
        Some(Bip39Error::BadEntropyLength)
    );
    let mut idx = [0u16; 12];
    idx[0] = 2048;
    assert_eq!(
        Mnemonic::from_indices(&idx).err(),
        Some(Bip39Error::BadWordIndex)
    );
}

#[test]
fn debug_does_not_leak_words() {
    let m = Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    assert!(!format!("{m:?}").contains("abandon"));
}

/// 15 / 21 / 24 词与非 ASCII passphrase：由独立 Python 实现生成（tools/testvectors/bip39_extra.py）。
#[test]
fn extra_vectors_from_independent_implementation() {
    let data = include_str!("../testdata/extra_vectors.txt");
    let mut checked = 0;
    let mut lengths = Vec::new();
    for line in data
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split('|').collect();
        assert_eq!(f.len(), 4, "{line}");
        let entropy = hex::decode(f[0]).unwrap();
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(sentence(&m), f[1]);
        let parsed = Mnemonic::parse(f[1]).unwrap();
        assert_eq!(hex::encode(parsed.to_entropy().expose()), f[0]);
        assert_eq!(hex::encode(parsed.to_seed(f[2]).unwrap().expose()), f[3]);
        lengths.push(m.word_count());
        checked += 1;
    }
    assert_eq!(checked, 5);
    assert!(lengths.contains(&15) && lengths.contains(&21));
}
