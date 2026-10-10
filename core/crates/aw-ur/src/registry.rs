//! UR 类型注册表中我们用到的类型（BCR-2020-006 / 007）：
//! - PSBT：`crypto-psbt`（旧名，兼容面最广）/ `psbt`（新名）；内容是 CBOR 字节串
//! - HD 公钥：`crypto-hdkey`（标签 303/304/305）/ `hdkey`（标签 40303/40304/40305）
//!
//! - 密钥路径：`crypto-keypath`（标签 304 / 40304），供其他类型复用（如 `eth-sign-request`）
//!
//! 观察机只应收到公钥：解码 hdkey 时拒绝私钥和主密钥。

use crate::cbor::{Reader, Writer};
use crate::ur::Ur;
use crate::UrError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `crypto-*` 旧类型名与 3xx 标签：Sparrow、BlueWallet、Keystone 等广泛支持
    Legacy,
    /// 新类型名与 40xxx 标签
    V2,
}

const PSBT_LEGACY: &str = "crypto-psbt";
const PSBT_V2: &str = "psbt";
const HDKEY_LEGACY: &str = "crypto-hdkey";
const HDKEY_V2: &str = "hdkey";

fn tags(style: Style) -> (u64, u64) {
    match style {
        Style::Legacy => (304, 305),
        Style::V2 => (40304, 40305),
    }
}

pub fn encode_psbt(psbt: &[u8], style: Style) -> Result<Ur, UrError> {
    let mut w = Writer::new();
    w.bytes(psbt);
    Ur::new(
        if style == Style::Legacy {
            PSBT_LEGACY
        } else {
            PSBT_V2
        },
        w.into_bytes(),
    )
}

pub fn decode_psbt(ur: &Ur) -> Result<Vec<u8>, UrError> {
    if ur.ur_type != PSBT_LEGACY && ur.ur_type != PSBT_V2 {
        return Err(UrError::UnexpectedType);
    }
    let mut r = Reader::new(&ur.cbor);
    let b = r.bytes()?.to_vec();
    r.finish()?;
    Ok(b)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPath {
    /// (子索引, 是否强化)；子索引 < 2^31
    pub components: Vec<(u32, bool)>,
    pub source_fingerprint: Option<u32>,
    pub depth: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdKey {
    pub key_data: [u8; 33],
    pub chain_code: Option<[u8; 32]>,
    /// SLIP-44 币种：0 = BTC，60 = ETH 及其他 EVM 链
    pub coin_type: u64,
    /// 0 = 主网，1 = 测试网（BTC）
    pub network: u64,
    pub origin: Option<KeyPath>,
    pub parent_fingerprint: Option<u32>,
}

/// 写出 crypto-keypath（带标签）。
pub fn write_keypath(w: &mut Writer, kp: &KeyPath, tag: u64) {
    let n = 1 + usize::from(kp.source_fingerprint.is_some()) + usize::from(kp.depth.is_some());
    w.tag(tag).map(n).uint(1).array(kp.components.len() * 2);
    for (i, h) in &kp.components {
        w.uint(u64::from(*i)).bool(*h);
    }
    if let Some(fp) = kp.source_fingerprint {
        w.uint(2).uint(u64::from(fp));
    }
    if let Some(d) = kp.depth {
        w.uint(3).uint(u64::from(d));
    }
}

pub fn encode_hdkey(k: &HdKey, style: Style) -> Result<Ur, UrError> {
    let (tag_keypath, tag_coin) = tags(style);
    let coin_info = k.coin_type != 0 || k.network != 0;
    let n = 1
        + usize::from(k.chain_code.is_some())
        + usize::from(coin_info)
        + usize::from(k.origin.is_some())
        + usize::from(k.parent_fingerprint.is_some());
    let mut w = Writer::new();
    w.map(n).uint(3).bytes(&k.key_data);
    if let Some(cc) = &k.chain_code {
        w.uint(4).bytes(cc);
    }
    if coin_info {
        // 字段取默认值（BTC、主网）时省略
        let m = usize::from(k.coin_type != 0) + usize::from(k.network != 0);
        w.uint(5).tag(tag_coin).map(m);
        if k.coin_type != 0 {
            w.uint(1).uint(k.coin_type);
        }
        if k.network != 0 {
            w.uint(2).uint(k.network);
        }
    }
    if let Some(kp) = &k.origin {
        w.uint(6);
        write_keypath(&mut w, kp, tag_keypath);
    }
    if let Some(fp) = k.parent_fingerprint {
        w.uint(8).uint(u64::from(fp));
    }
    Ur::new(
        if style == Style::Legacy {
            HDKEY_LEGACY
        } else {
            HDKEY_V2
        },
        w.into_bytes(),
    )
}

/// 读取 crypto-keypath（带标签）：只支持"索引 + 强化"对，拒绝范围与通配。
pub fn read_keypath(r: &mut Reader<'_>, tag: u64) -> Result<KeyPath, UrError> {
    if r.tag()? != tag {
        return Err(UrError::Cbor);
    }
    let mut kp = KeyPath {
        components: vec![],
        source_fingerprint: None,
        depth: None,
    };
    let mut last = 0u64;
    for _ in 0..r.map()? {
        let key = r.uint()?;
        if key <= last {
            return Err(UrError::Cbor); // 键必须严格递增（拒绝重复）
        }
        last = key;
        match key {
            1 => {
                let n = r.array()?;
                if n % 2 != 0 || n > 2 * 32 {
                    return Err(UrError::Cbor); // 只支持"索引 + 强化"对；不支持范围/通配
                }
                for _ in 0..n / 2 {
                    let i = r.u32()?;
                    if i >= 0x8000_0000 {
                        return Err(UrError::Cbor);
                    }
                    kp.components.push((i, r.bool()?));
                }
            }
            2 => kp.source_fingerprint = Some(r.u32()?),
            3 => kp.depth = Some(u8::try_from(r.uint()?).map_err(|_| UrError::Cbor)?),
            _ => r.skip()?,
        }
    }
    Ok(kp)
}

pub fn decode_hdkey(ur: &Ur) -> Result<HdKey, UrError> {
    let style = match ur.ur_type.as_str() {
        HDKEY_LEGACY => Style::Legacy,
        HDKEY_V2 => Style::V2,
        _ => return Err(UrError::UnexpectedType),
    };
    let (tag_keypath, tag_coin) = tags(style);
    let mut r = Reader::new(&ur.cbor);
    let mut key_data = None;
    let mut k = HdKey {
        key_data: [0; 33],
        chain_code: None,
        coin_type: 0,
        network: 0,
        origin: None,
        parent_fingerprint: None,
    };
    let mut last = 0u64;
    for _ in 0..r.map()? {
        let key = r.uint()?;
        if key <= last {
            return Err(UrError::Cbor);
        }
        last = key;
        match key {
            // 主密钥或私钥：观察机绝不接收
            1 | 2 => {
                if r.bool()? {
                    return Err(UrError::Format);
                }
            }
            3 => key_data = Some(<[u8; 33]>::try_from(r.bytes()?).map_err(|_| UrError::Cbor)?),
            4 => k.chain_code = Some(<[u8; 32]>::try_from(r.bytes()?).map_err(|_| UrError::Cbor)?),
            5 => {
                if r.tag()? != tag_coin {
                    return Err(UrError::Cbor);
                }
                let mut last_c = 0u64;
                for _ in 0..r.map()? {
                    let ck = r.uint()?;
                    if ck <= last_c {
                        return Err(UrError::Cbor);
                    }
                    last_c = ck;
                    match ck {
                        1 => k.coin_type = r.uint()?, // 由调用方核对币种
                        2 => k.network = r.uint()?,
                        _ => r.skip()?,
                    }
                }
            }
            6 => k.origin = Some(read_keypath(&mut r, tag_keypath)?),
            8 => k.parent_fingerprint = Some(r.u32()?),
            _ => r.skip()?,
        }
    }
    r.finish()?;
    k.key_data = key_data.ok_or(UrError::Cbor)?;
    if !matches!(k.key_data.first(), Some(2 | 3)) {
        return Err(UrError::Format); // 只接受压缩公钥
    }
    Ok(k)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use crate::fountain::refvec::{hex, to_hex};

    const SPEC: &str =
        include_str!("../../../../third_party/bc-research/papers/bcr-2020-007-hdkey.md");

    fn spec_line(prefix: &str) -> String {
        SPEC.lines()
            .find(|l| l.trim_start().starts_with(prefix))
            .map(|l| l.trim().to_owned())
            .unwrap()
    }

    /// BCR-2020-007 测试向量 2：测试网公钥 m/44'/1'/1'/0/1
    fn vector2() -> HdKey {
        HdKey {
            key_data: hex("026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6")
                .try_into()
                .unwrap(),
            chain_code: Some(
                hex("ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85")
                    .try_into()
                    .unwrap(),
            ),
            coin_type: 0,
            network: 1,
            origin: Some(KeyPath {
                components: vec![(44, true), (1, true), (1, true), (0, false), (1, false)],
                source_fingerprint: None,
                depth: None,
            }),
            parent_fingerprint: Some(3_910_671_603),
        }
    }

    #[test]
    fn spec_vector_2_cbor_and_ur() {
        let want_hex = spec_line("a5035821026fe2355745");
        let want_ur = spec_line("ur:hdkey/onaxhdclaojlvoechgferkd");
        let ur = encode_hdkey(&vector2(), Style::V2).unwrap();
        assert_eq!(to_hex(&ur.cbor), want_hex);
        assert_eq!(crate::ur::encode(&ur), want_ur);
        assert_eq!(
            decode_hdkey(&crate::ur::decode(&want_ur).unwrap()).unwrap(),
            vector2()
        );
    }

    #[test]
    fn legacy_style_roundtrip() {
        let ur = encode_hdkey(&vector2(), Style::Legacy).unwrap();
        assert_eq!(ur.ur_type, "crypto-hdkey");
        assert_eq!(decode_hdkey(&ur).unwrap(), vector2());
    }

    #[test]
    fn rejects_private_and_master_keys() {
        // {1: true, 3: key, 4: chain} 主密钥
        let mut w = Writer::new();
        w.map(3)
            .uint(1)
            .bool(true)
            .uint(3)
            .bytes(&[2u8; 33])
            .uint(4)
            .bytes(&[0u8; 32]);
        assert!(decode_hdkey(&Ur::new("hdkey", w.into_bytes()).unwrap()).is_err());
        // {2: true, 3: key} 私钥
        let mut w = Writer::new();
        w.map(2).uint(2).bool(true).uint(3).bytes(&[0u8; 33]);
        assert!(decode_hdkey(&Ur::new("hdkey", w.into_bytes()).unwrap()).is_err());
    }

    #[test]
    fn rejects_duplicate_keys_and_wrong_type() {
        let mut w = Writer::new();
        w.map(2).uint(3).bytes(&[2u8; 33]).uint(3).bytes(&[2u8; 33]);
        assert!(decode_hdkey(&Ur::new("hdkey", w.into_bytes()).unwrap()).is_err());
        let psbt = encode_psbt(b"psbt\xff", Style::Legacy).unwrap();
        assert_eq!(decode_hdkey(&psbt), Err(UrError::UnexpectedType));
    }

    #[test]
    fn psbt_roundtrip_both_styles() {
        for style in [Style::Legacy, Style::V2] {
            let ur = encode_psbt(b"psbt\xff\x01\x02", style).unwrap();
            assert_eq!(decode_psbt(&ur).unwrap(), b"psbt\xff\x01\x02");
        }
        assert_eq!(
            decode_psbt(&Ur::new("bytes", vec![0x40]).unwrap()),
            Err(UrError::UnexpectedType)
        );
    }
}
