//! UR 类型 `eth-sign-request`（CBOR 标签 401）与 `eth-signature`（402），
//! 字段与 Keystone / MetaMask 使用的注册表一致（ERC-4527）：
//!
//! ```text
//! eth-sign-request = {
//!   ? 1: #6.37(bytes .size 16),   ; request-id（UUID）
//!     2: bytes,                   ; sign-data：待签字节
//!     3: int,                     ; data-type：1 旧式交易、2 EIP-712、3 personal_sign、4 类型化交易
//!   ? 4: int,                     ; chain-id
//!     5: #6.304(crypto-keypath),  ; 签名用的派生路径
//!   ? 6: bytes .size 20,          ; 地址
//!   ? 7: text                     ; 来源（仅供显示）
//! }
//! eth-signature = { ? 1: #6.37(bytes), 2: bytes, ? 3: text }
//! ```
//!
//! 读取严格：键必须递增、不允许未知键（未知键可能携带签名机看不到的语义）。

use aw_ur::cbor::{Reader, Writer};
use aw_ur::registry::{read_keypath, write_keypath, KeyPath};
use aw_ur::ur::Ur;
use aw_ur::UrError;

pub const SIGN_REQUEST: &str = "eth-sign-request";
pub const SIGNATURE: &str = "eth-signature";
const TAG_UUID: u64 = 37;
const TAG_KEYPATH: u64 = 304;
const MAX_ORIGIN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    LegacyTx = 1,
    TypedData = 2,
    PersonalMessage = 3,
    TypedTx = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub request_id: Option<[u8; 16]>,
    pub sign_data: Vec<u8>,
    pub data_type: DataType,
    pub chain_id: Option<u64>,
    pub path: KeyPath,
    pub address: Option<[u8; 20]>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub request_id: Option<[u8; 16]>,
    pub signature: Vec<u8>,
    pub origin: Option<String>,
}

fn origin_ok(s: &str) -> Result<(), UrError> {
    if s.len() > MAX_ORIGIN || s.chars().any(char::is_control) {
        return Err(UrError::Format);
    }
    Ok(())
}

pub fn encode_request(r: &SignRequest) -> Result<Ur, UrError> {
    let n = 3
        + usize::from(r.request_id.is_some())
        + usize::from(r.chain_id.is_some())
        + usize::from(r.address.is_some())
        + usize::from(r.origin.is_some());
    let mut w = Writer::new();
    w.map(n);
    if let Some(id) = &r.request_id {
        w.uint(1).tag(TAG_UUID).bytes(id);
    }
    w.uint(2).bytes(&r.sign_data);
    w.uint(3).uint(r.data_type as u64);
    if let Some(c) = r.chain_id {
        w.uint(4).uint(c);
    }
    w.uint(5);
    write_keypath(&mut w, &r.path, TAG_KEYPATH);
    if let Some(a) = &r.address {
        w.uint(6).bytes(a);
    }
    if let Some(o) = &r.origin {
        origin_ok(o)?;
        w.uint(7).text(o);
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
    let (mut id, mut data, mut ty, mut chain, mut path, mut addr, mut origin) =
        (None, None, None, None, None, None, None);
    let mut last = 0;
    for _ in 0..r.map()? {
        match next_key(&mut r, &mut last, &[1, 2, 3, 4, 5, 6, 7])? {
            1 => id = Some(uuid(&mut r)?),
            2 => {
                let b = r.bytes()?;
                if b.len() > crate::MAX_SIGN_DATA {
                    return Err(UrError::Format);
                }
                data = Some(b.to_vec());
            }
            3 => {
                ty = Some(match r.uint()? {
                    1 => DataType::LegacyTx,
                    2 => DataType::TypedData,
                    3 => DataType::PersonalMessage,
                    4 => DataType::TypedTx,
                    _ => return Err(UrError::Format),
                })
            }
            4 => chain = Some(r.uint()?),
            5 => path = Some(read_keypath(&mut r, TAG_KEYPATH)?),
            6 => addr = Some(<[u8; 20]>::try_from(r.bytes()?).map_err(|_| UrError::Format)?),
            _ => {
                let o = r.text()?;
                origin_ok(o)?;
                origin = Some(o.to_owned());
            }
        }
    }
    r.finish()?;
    Ok(SignRequest {
        request_id: id,
        sign_data: data.ok_or(UrError::Format)?,
        data_type: ty.ok_or(UrError::Format)?,
        chain_id: chain,
        path: path.ok_or(UrError::Format)?,
        address: addr,
        origin,
    })
}

pub fn encode_signature(s: &Signature) -> Result<Ur, UrError> {
    let n = 1 + usize::from(s.request_id.is_some()) + usize::from(s.origin.is_some());
    let mut w = Writer::new();
    w.map(n);
    if let Some(id) = &s.request_id {
        w.uint(1).tag(TAG_UUID).bytes(id);
    }
    w.uint(2).bytes(&s.signature);
    if let Some(o) = &s.origin {
        origin_ok(o)?;
        w.uint(3).text(o);
    }
    Ur::new(SIGNATURE, w.into_bytes())
}

pub fn decode_signature(ur: &Ur) -> Result<Signature, UrError> {
    if ur.ur_type != SIGNATURE {
        return Err(UrError::UnexpectedType);
    }
    let mut r = Reader::new(&ur.cbor);
    let (mut id, mut sig, mut origin) = (None, None, None);
    let mut last = 0;
    for _ in 0..r.map()? {
        match next_key(&mut r, &mut last, &[1, 2, 3])? {
            1 => id = Some(uuid(&mut r)?),
            2 => {
                let b = r.bytes()?;
                if !(65..=72).contains(&b.len()) {
                    return Err(UrError::Format);
                }
                sig = Some(b.to_vec());
            }
            _ => {
                let o = r.text()?;
                origin_ok(o)?;
                origin = Some(o.to_owned());
            }
        }
    }
    r.finish()?;
    Ok(Signature {
        request_id: id,
        signature: sig.ok_or(UrError::Format)?,
        origin,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn sample() -> SignRequest {
        SignRequest {
            request_id: Some([7; 16]),
            sign_data: vec![0x02, 0xc0],
            data_type: DataType::TypedTx,
            chain_id: Some(11_155_111),
            path: KeyPath {
                components: vec![(44, true), (60, true), (0, true), (0, false), (3, false)],
                source_fingerprint: Some(0x73c5_da0a),
                depth: None,
            },
            address: Some([9; 20]),
            origin: Some("airgap-wallet".to_owned()),
        }
    }

    #[test]
    fn roundtrip() {
        let r = sample();
        let ur = encode_request(&r).unwrap();
        assert_eq!(ur.ur_type, SIGN_REQUEST);
        assert_eq!(decode_request(&ur).unwrap(), r);
        let minimal = SignRequest {
            request_id: None,
            chain_id: None,
            address: None,
            origin: None,
            ..r
        };
        assert_eq!(
            decode_request(&encode_request(&minimal).unwrap()).unwrap(),
            minimal
        );
        let s = Signature {
            request_id: Some([7; 16]),
            signature: vec![1; 65],
            origin: None,
        };
        assert_eq!(decode_signature(&encode_signature(&s).unwrap()).unwrap(), s);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        // 在映射末尾追加一个未知键 8
        let ur = encode_request(&sample()).unwrap();
        let mut cbor = ur.cbor.clone();
        cbor[0] += 1; // 映射长度 +1（长度 < 24，单字节头）
        cbor.extend_from_slice(&[0x08, 0x00]);
        assert!(decode_request(&Ur::new(SIGN_REQUEST, cbor).unwrap()).is_err());
        // 控制字符的来源文字
        let bad = SignRequest {
            origin: Some("a\u{1b}[31m".to_owned()),
            ..sample()
        };
        assert!(encode_request(&bad).is_err());
        // 签名长度不对
        let s = Signature {
            request_id: None,
            signature: vec![1; 64],
            origin: None,
        };
        assert!(decode_signature(&encode_signature(&s).unwrap()).is_err());
        assert_eq!(
            decode_request(
                &encode_signature(&Signature {
                    request_id: None,
                    signature: vec![1; 65],
                    origin: None
                })
                .unwrap()
            ),
            Err(UrError::UnexpectedType)
        );
    }
}
