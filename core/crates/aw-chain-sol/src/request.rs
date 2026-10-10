//! UR 类型 `sol-sign-request` 与 `sol-signature`（P2c-T3），字段与 Keystone 的 Solana 注册表一致：
//!
//! ```text
//! sol-sign-request = {
//!   ? 1: #6.37(bytes .size 16),   ; request-id（UUID）
//!     2: bytes,                   ; sign-data：待签的消息字节
//!     3: #6.304(crypto-keypath),  ; 签名用的派生路径（D34 三种方案之一）
//!   ? 4: bytes .size 32,          ; 签名地址（公钥）
//!   ? 5: text,                    ; 来源（仅供显示）
//!   ? 6: int                      ; 类型：1 交易、2 链下消息
//! }
//! sol-signature = { ? 1: #6.37(bytes .size 16), 2: bytes .size 64 }
//! ```
//!
//! 读取严格：键必须递增、不允许未知键、长度精确。

use crate::message::MAX_MESSAGE_BYTES;
use crate::Scheme;
use aw_ur::cbor::{Reader, Writer};
use aw_ur::registry::{read_keypath, write_keypath, KeyPath};
use aw_ur::ur::Ur;
use aw_ur::UrError;

pub const SIGN_REQUEST: &str = "sol-sign-request";
pub const SIGNATURE: &str = "sol-signature";
const TAG_UUID: u64 = 37;
const TAG_KEYPATH: u64 = 304;
const MAX_ORIGIN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignType {
    Transaction = 1,
    Message = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub request_id: Option<[u8; 16]>,
    pub sign_data: Vec<u8>,
    pub path: KeyPath,
    pub address: Option<[u8; 32]>,
    pub origin: Option<String>,
    pub sign_type: Option<SignType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub request_id: Option<[u8; 16]>,
    pub signature: [u8; 64],
}

/// 派生路径 → (方案, 账户序号)。路径各级都必须强化，且只能是 D34 的三种形状之一
pub fn scheme_of(path: &KeyPath) -> Option<(Scheme, u32)> {
    let parts: Vec<u32> = path
        .components
        .iter()
        .map(|&(i, hardened)| hardened.then_some(i))
        .collect::<Option<_>>()?;
    match parts.as_slice() {
        [44, 501, i, 0] => Some((Scheme::Phantom, *i)),
        [44, 501, i] => Some((Scheme::LedgerLive, *i)),
        [44, 501] => Some((Scheme::LedgerMain, 0)),
        _ => None,
    }
}

/// 方案与序号 → 派生路径（观察机构造请求用）
pub fn keypath(scheme: Scheme, index: u32, fingerprint: Option<u32>) -> KeyPath {
    KeyPath {
        components: scheme
            .account_path(index)
            .into_iter()
            .map(|i| (i, true))
            .collect(),
        source_fingerprint: fingerprint,
        depth: None,
    }
}

fn origin_ok(s: &str) -> Result<(), UrError> {
    if s.len() > MAX_ORIGIN || s.chars().any(char::is_control) {
        return Err(UrError::Format);
    }
    Ok(())
}

pub fn encode_request(r: &SignRequest) -> Result<Ur, UrError> {
    let n = 2
        + usize::from(r.request_id.is_some())
        + usize::from(r.address.is_some())
        + usize::from(r.origin.is_some())
        + usize::from(r.sign_type.is_some());
    let mut w = Writer::new();
    w.map(n);
    if let Some(id) = &r.request_id {
        w.uint(1).tag(TAG_UUID).bytes(id);
    }
    w.uint(2).bytes(&r.sign_data);
    w.uint(3);
    write_keypath(&mut w, &r.path, TAG_KEYPATH);
    if let Some(a) = &r.address {
        w.uint(4).bytes(a);
    }
    if let Some(o) = &r.origin {
        origin_ok(o)?;
        w.uint(5).text(o);
    }
    if let Some(t) = r.sign_type {
        w.uint(6).uint(t as u64);
    }
    Ur::new(SIGN_REQUEST, w.into_bytes())
}

/// 读取递增的键；不在 `allowed` 中的键视为格式错误
fn next_key(r: &mut Reader<'_>, last: &mut u64, allowed: &[u64]) -> Result<u64, UrError> {
    let k = r.uint()?;
    if k <= *last || !allowed.contains(&k) {
        return Err(UrError::Format);
    }
    *last = k;
    Ok(k)
}

fn uuid(r: &mut Reader<'_>) -> Result<[u8; 16], UrError> {
    if r.tag()? != TAG_UUID {
        return Err(UrError::Format);
    }
    <[u8; 16]>::try_from(r.bytes()?).map_err(|_| UrError::Format)
}

pub fn decode_request(ur: &Ur) -> Result<SignRequest, UrError> {
    if ur.ur_type != SIGN_REQUEST {
        return Err(UrError::UnexpectedType);
    }
    let mut r = Reader::new(&ur.cbor);
    let (mut id, mut data, mut path, mut addr, mut origin, mut ty) =
        (None, None, None, None, None, None);
    let mut last = 0;
    for _ in 0..r.map()? {
        match next_key(&mut r, &mut last, &[1, 2, 3, 4, 5, 6])? {
            1 => id = Some(uuid(&mut r)?),
            2 => {
                let b = r.bytes()?;
                if b.is_empty() || b.len() > MAX_MESSAGE_BYTES {
                    return Err(UrError::Format);
                }
                data = Some(b.to_vec());
            }
            3 => path = Some(read_keypath(&mut r, TAG_KEYPATH)?),
            4 => addr = Some(<[u8; 32]>::try_from(r.bytes()?).map_err(|_| UrError::Format)?),
            5 => {
                let o = r.text()?;
                origin_ok(o)?;
                origin = Some(o.to_owned());
            }
            _ => {
                ty = Some(match r.uint()? {
                    1 => SignType::Transaction,
                    2 => SignType::Message,
                    _ => return Err(UrError::Format),
                })
            }
        }
    }
    r.finish()?;
    Ok(SignRequest {
        request_id: id,
        sign_data: data.ok_or(UrError::Format)?,
        path: path.ok_or(UrError::Format)?,
        address: addr,
        origin,
        sign_type: ty,
    })
}

pub fn encode_signature(s: &Signature) -> Result<Ur, UrError> {
    let mut w = Writer::new();
    w.map(1 + usize::from(s.request_id.is_some()));
    if let Some(id) = &s.request_id {
        w.uint(1).tag(TAG_UUID).bytes(id);
    }
    w.uint(2).bytes(&s.signature);
    Ur::new(SIGNATURE, w.into_bytes())
}

pub fn decode_signature(ur: &Ur) -> Result<Signature, UrError> {
    if ur.ur_type != SIGNATURE {
        return Err(UrError::UnexpectedType);
    }
    let mut r = Reader::new(&ur.cbor);
    let (mut id, mut sig) = (None, None);
    let mut last = 0;
    for _ in 0..r.map()? {
        match next_key(&mut r, &mut last, &[1, 2])? {
            1 => id = Some(uuid(&mut r)?),
            _ => sig = Some(<[u8; 64]>::try_from(r.bytes()?).map_err(|_| UrError::Format)?),
        }
    }
    r.finish()?;
    Ok(Signature {
        request_id: id,
        signature: sig.ok_or(UrError::Format)?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn schemes_from_paths() {
        assert_eq!(
            scheme_of(&keypath(Scheme::Phantom, 3, None)),
            Some((Scheme::Phantom, 3))
        );
        assert_eq!(
            scheme_of(&keypath(Scheme::LedgerLive, 2, None)),
            Some((Scheme::LedgerLive, 2))
        );
        assert_eq!(
            scheme_of(&keypath(Scheme::LedgerMain, 0, None)),
            Some((Scheme::LedgerMain, 0))
        );
        let soft = KeyPath {
            components: vec![(44, true), (501, true), (0, false), (0, true)],
            source_fingerprint: None,
            depth: None,
        };
        assert_eq!(scheme_of(&soft), None);
        let other = KeyPath {
            components: vec![(44, true), (60, true), (0, true)],
            source_fingerprint: None,
            depth: None,
        };
        assert_eq!(scheme_of(&other), None);
    }

    #[test]
    fn request_and_signature_round_trip() {
        let req = SignRequest {
            request_id: Some([7; 16]),
            sign_data: vec![1, 2, 3],
            path: keypath(Scheme::LedgerLive, 1, Some(0xdead_beef)),
            address: Some([9; 32]),
            origin: Some("airgap-wallet".to_owned()),
            sign_type: Some(SignType::Transaction),
        };
        let ur = encode_request(&req).unwrap();
        assert_eq!(ur.ur_type, "sol-sign-request");
        assert_eq!(decode_request(&ur).unwrap(), req);
        let sig = Signature {
            request_id: Some([7; 16]),
            signature: [5; 64],
        };
        assert_eq!(
            decode_signature(&encode_signature(&sig).unwrap()).unwrap(),
            sig
        );
        // 签名长度不对
        let mut w = Writer::new();
        w.map(1).uint(2).bytes(&[0u8; 63]);
        assert!(decode_signature(&Ur::new(SIGNATURE, w.into_bytes()).unwrap()).is_err());
        // 未知键
        let mut w = Writer::new();
        w.map(3).uint(2).bytes(&[1]).uint(3);
        write_keypath(&mut w, &req.path, TAG_KEYPATH);
        w.uint(9).uint(1);
        assert!(decode_request(&Ur::new(SIGN_REQUEST, w.into_bytes()).unwrap()).is_err());
    }
}
