//! UR 字符串格式（BCR-2020-005）：
//! 单段 `ur:<类型>/<bytewords>`；多段 `ur:<类型>/<序号>-<总数>/<bytewords(分片 CBOR)>`。
//! 二维码里常用大写（字母数字模式更紧凑），解码时统一转小写。

use crate::bytewords;
use crate::fountain::{FountainDecoder, FountainEncoder, Part};
use crate::UrError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ur {
    pub ur_type: String,
    pub cbor: Vec<u8>,
}

/// 类型名：非空，只含小写字母、数字、连字符。
pub fn is_ur_type(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

impl Ur {
    pub fn new(ur_type: &str, cbor: Vec<u8>) -> Result<Self, UrError> {
        if !is_ur_type(ur_type) {
            return Err(UrError::Format);
        }
        Ok(Self {
            ur_type: ur_type.to_owned(),
            cbor,
        })
    }
}

/// 单段编码。
pub fn encode(ur: &Ur) -> String {
    format!("ur:{}/{}", ur.ur_type, bytewords::encode_minimal(&ur.cbor))
}

/// 解析出 (类型, 其余路径段)。
fn parse(s: &str) -> Result<(String, Vec<String>), UrError> {
    if s.len() > crate::MAX_MESSAGE_LEN * 2 + 64 {
        return Err(UrError::TooLarge);
    }
    let lower = s.trim().to_ascii_lowercase();
    let path = lower.strip_prefix("ur:").ok_or(UrError::Format)?;
    let comps: Vec<&str> = path.split('/').collect();
    if comps.len() < 2 || comps.iter().any(|c| c.is_empty()) {
        return Err(UrError::Format);
    }
    let ur_type = comps.first().copied().unwrap_or("");
    if !is_ur_type(ur_type) {
        return Err(UrError::Format);
    }
    Ok((
        ur_type.to_owned(),
        comps.iter().skip(1).map(|c| (*c).to_owned()).collect(),
    ))
}

/// 单段解码（多段请用 `UrDecoder`）。
pub fn decode(s: &str) -> Result<Ur, UrError> {
    let (ur_type, comps) = parse(s)?;
    match comps.as_slice() {
        [body] => Ur::new(&ur_type, bytewords::decode_minimal(body)?),
        _ => Err(UrError::Format),
    }
}

fn parse_sequence(s: &str) -> Result<(u32, usize), UrError> {
    let (a, b) = s.split_once('-').ok_or(UrError::Sequence)?;
    let digits = |x: &str| !x.is_empty() && x.len() <= 10 && x.bytes().all(|c| c.is_ascii_digit());
    if !digits(a) || !digits(b) {
        return Err(UrError::Sequence);
    }
    let n: u32 = a.parse().map_err(|_| UrError::Sequence)?;
    let len: usize = b.parse().map_err(|_| UrError::Sequence)?;
    if n == 0 || len == 0 {
        return Err(UrError::Sequence);
    }
    Ok((n, len))
}

/// 动画二维码编码器：反复调用 `next_part` 得到下一帧。
pub struct UrEncoder {
    ur: Ur,
    fountain: FountainEncoder,
}

impl UrEncoder {
    pub fn new(
        ur: Ur,
        max_fragment_len: usize,
        first_seq_num: u32,
        min_fragment_len: usize,
    ) -> Result<Self, UrError> {
        let fountain =
            FountainEncoder::new(&ur.cbor, max_fragment_len, first_seq_num, min_fragment_len)?;
        Ok(Self { ur, fountain })
    }

    pub fn seq_len(&self) -> usize {
        self.fountain.seq_len()
    }

    pub fn is_single_part(&self) -> bool {
        self.fountain.is_single_part()
    }

    pub fn next_part(&mut self) -> String {
        let part = self.fountain.next_part();
        if self.is_single_part() {
            encode(&self.ur)
        } else {
            format!(
                "ur:{}/{}-{}/{}",
                self.ur.ur_type,
                part.seq_num,
                part.seq_len,
                bytewords::encode_minimal(&part.to_cbor())
            )
        }
    }
}

/// 扫码解码器：每扫到一帧调用 `receive`，直到 `result()` 有值。
#[derive(Default)]
pub struct UrDecoder {
    expected_type: Option<String>,
    fountain: FountainDecoder,
    result: Option<Result<Ur, UrError>>,
}

impl UrDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn result(&self) -> Option<&Result<Ur, UrError>> {
        self.result.as_ref()
    }

    pub fn progress(&self) -> (usize, usize) {
        self.fountain.progress()
    }

    /// 收下一帧。返回 Err 表示这一帧无效（不影响已收集的进度）；
    /// `Inconsistent` / `UnexpectedType` 表示扫到了另一组二维码。
    pub fn receive(&mut self, s: &str) -> Result<(), UrError> {
        if self.result.is_some() {
            return Ok(());
        }
        let (ur_type, comps) = parse(s)?;
        match &self.expected_type {
            Some(t) if *t != ur_type => return Err(UrError::UnexpectedType),
            _ => {}
        }
        match comps.as_slice() {
            [body] => {
                let ur = Ur::new(&ur_type, bytewords::decode_minimal(body)?)?;
                self.result = Some(Ok(ur));
                Ok(())
            }
            [seq, body] => {
                let (n, len) = parse_sequence(seq)?;
                let part = Part::from_cbor(&bytewords::decode_minimal(body)?)?;
                if part.seq_num != n || part.seq_len != len {
                    return Err(UrError::Sequence);
                }
                self.expected_type = Some(ur_type.clone());
                self.fountain.receive(&part)?;
                if let Some(r) = self.fountain.result() {
                    self.result = Some(match r {
                        Ok(msg) => Ur::new(&ur_type, msg.clone()),
                        Err(e) => Err(*e),
                    });
                }
                Ok(())
            }
            _ => Err(UrError::Format),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use crate::cbor::Writer;
    use crate::fountain::refvec::*;

    /// test-utils.cpp: make_message_ur = UR("bytes", CBOR 字节串(make_message(len)))
    fn make_message_ur(len: usize) -> Ur {
        let mut w = Writer::new();
        w.bytes(&make_message(len, "Wolf"));
        Ur::new("bytes", w.into_bytes()).unwrap()
    }

    #[test]
    fn reference_single_part() {
        let ur = make_message_ur(50);
        let want = strings_after(&section("test_single_part_ur"), "string expected =")[0].clone();
        assert_eq!(encode(&ur), want);
        assert_eq!(decode(&want).unwrap(), ur);
        assert_eq!(decode(&want.to_uppercase()).unwrap(), ur);
    }

    #[test]
    fn reference_multipart_encoder() {
        let mut enc = UrEncoder::new(make_message_ur(256), 30, 0, 10).unwrap();
        let got: Vec<String> = (0..20).map(|_| enc.next_part()).collect();
        assert_eq!(
            got,
            strings_after(&section("test_ur_encoder"), "expected_parts = {")
        );
    }

    /// bc-ur test.cpp: test_multipart_ur
    #[test]
    fn reference_multipart_roundtrip() {
        let ur = make_message_ur(32767);
        let mut enc = UrEncoder::new(ur.clone(), 1000, 100, 10).unwrap();
        let mut dec = UrDecoder::new();
        while dec.result().is_none() {
            dec.receive(&enc.next_part().to_uppercase()).unwrap();
        }
        assert_eq!(dec.result().unwrap().as_ref().unwrap(), &ur);
    }

    #[test]
    fn rejects_malformed_strings() {
        for bad in [
            "",
            "ur:",
            "ur:bytes",
            "ur:bytes/",
            "ur:BYTES!/aeae",
            "xr:bytes/aeadaolazmjendeoti",
            "ur:bytes//aeadaolazmjendeoti",
            "ur:bytes/0-3/aeae",
            "ur:bytes/1-0/aeae",
            "ur:bytes/1-2-3/aeae",
            "ur:bytes/99999999999-1/aeae",
            "ur:bytes/a/b/c/d",
        ] {
            assert!(decode(bad).is_err(), "{bad}");
            assert!(UrDecoder::new().receive(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn decoder_rejects_type_switch_midstream() {
        let mut a = UrEncoder::new(make_message_ur(300), 50, 0, 10).unwrap();
        let mut dec = UrDecoder::new();
        dec.receive(&a.next_part()).unwrap();
        let other = a.next_part().replacen("ur:bytes/", "ur:crypto-psbt/", 1);
        assert_eq!(dec.receive(&other), Err(UrError::UnexpectedType));
    }
}
