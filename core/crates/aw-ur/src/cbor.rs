//! 最小 CBOR（RFC 8949）读写，只支持 UR 用到的子集：
//! 无符号整数、字节串、文本串、数组、映射、标签、布尔、null。
//!
//! 读取时严格：拒绝不定长、非最短编码、浮点、超出剩余长度的声明、过深嵌套。

use crate::UrError;

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;
const MAX_DEPTH: usize = 16;

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn head(&mut self, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => self.buf.push(m | n as u8),
            24..=0xff => self.buf.extend_from_slice(&[m | 24, n as u8]),
            0x100..=0xffff => {
                self.buf.push(m | 25);
                self.buf.extend_from_slice(&(n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.buf.push(m | 26);
                self.buf.extend_from_slice(&(n as u32).to_be_bytes());
            }
            _ => {
                self.buf.push(m | 27);
                self.buf.extend_from_slice(&n.to_be_bytes());
            }
        }
    }

    pub fn uint(&mut self, n: u64) -> &mut Self {
        self.head(MAJOR_UINT, n);
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(MAJOR_BYTES, b.len() as u64);
        self.buf.extend_from_slice(b);
        self
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.head(MAJOR_TEXT, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    pub fn array(&mut self, len: usize) -> &mut Self {
        self.head(MAJOR_ARRAY, len as u64);
        self
    }

    pub fn map(&mut self, len: usize) -> &mut Self {
        self.head(MAJOR_MAP, len as u64);
        self
    }

    pub fn tag(&mut self, t: u64) -> &mut Self {
        self.head(MAJOR_TAG, t);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(if v { 0xf5 } else { 0xf4 });
        self
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn is_end(&self) -> bool {
        self.pos == self.data.len()
    }

    /// 要求已经读完全部输入（拒绝尾随垃圾）。
    pub fn finish(&self) -> Result<(), UrError> {
        if self.is_end() {
            Ok(())
        } else {
            Err(UrError::Cbor)
        }
    }

    fn byte(&mut self) -> Result<u8, UrError> {
        let b = *self.data.get(self.pos).ok_or(UrError::Cbor)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], UrError> {
        let end = self.pos.checked_add(n).ok_or(UrError::Cbor)?;
        let s = self.data.get(self.pos..end).ok_or(UrError::Cbor)?;
        self.pos = end;
        Ok(s)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], UrError> {
        self.take(N)?.try_into().map_err(|_| UrError::Cbor)
    }

    fn peek_major(&self) -> Result<u8, UrError> {
        self.data.get(self.pos).map(|b| b >> 5).ok_or(UrError::Cbor)
    }

    /// 读取头部：(主类型, 参数)。拒绝不定长与非最短编码。
    fn head(&mut self) -> Result<(u8, u64), UrError> {
        let b = self.byte()?;
        let (major, ai) = (b >> 5, b & 0x1f);
        let v = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(UrError::Cbor);
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(self.take_array()?));
                if v <= 0xff {
                    return Err(UrError::Cbor);
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(self.take_array()?));
                if v <= 0xffff {
                    return Err(UrError::Cbor);
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take_array()?);
                if v <= 0xffff_ffff {
                    return Err(UrError::Cbor);
                }
                v
            }
            _ => return Err(UrError::Cbor),
        };
        Ok((major, v))
    }

    fn expect(&mut self, major: u8) -> Result<u64, UrError> {
        let (m, v) = self.head()?;
        if m == major {
            Ok(v)
        } else {
            Err(UrError::Cbor)
        }
    }

    fn len_of(&self, v: u64) -> Result<usize, UrError> {
        let n = usize::try_from(v).map_err(|_| UrError::Cbor)?;
        if n > self.data.len() - self.pos {
            return Err(UrError::Cbor);
        }
        Ok(n)
    }

    pub fn uint(&mut self) -> Result<u64, UrError> {
        self.expect(MAJOR_UINT)
    }

    pub fn u32(&mut self) -> Result<u32, UrError> {
        u32::try_from(self.uint()?).map_err(|_| UrError::Cbor)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], UrError> {
        let v = self.expect(MAJOR_BYTES)?;
        let n = self.len_of(v)?;
        self.take(n)
    }

    pub fn text(&mut self) -> Result<&'a str, UrError> {
        let v = self.expect(MAJOR_TEXT)?;
        let n = self.len_of(v)?;
        core::str::from_utf8(self.take(n)?).map_err(|_| UrError::Cbor)
    }

    pub fn array(&mut self) -> Result<usize, UrError> {
        let v = self.expect(MAJOR_ARRAY)?;
        // 每个元素至少 1 字节
        self.len_of(v)
    }

    pub fn map(&mut self) -> Result<usize, UrError> {
        let v = self.expect(MAJOR_MAP)?;
        let n = self.len_of(v)?;
        if n.saturating_mul(2) > self.data.len() - self.pos {
            return Err(UrError::Cbor);
        }
        Ok(n)
    }

    pub fn tag(&mut self) -> Result<u64, UrError> {
        self.expect(MAJOR_TAG)
    }

    pub fn is_tag_next(&self) -> bool {
        self.peek_major() == Ok(MAJOR_TAG)
    }

    pub fn bool(&mut self) -> Result<bool, UrError> {
        match self.byte()? {
            0xf5 => Ok(true),
            0xf4 => Ok(false),
            _ => Err(UrError::Cbor),
        }
    }

    /// 跳过一个完整的值（用于忽略映射中的可选字段）。
    pub fn skip(&mut self) -> Result<(), UrError> {
        self.skip_depth(0)
    }

    fn skip_depth(&mut self, depth: usize) -> Result<(), UrError> {
        if depth > MAX_DEPTH {
            return Err(UrError::Cbor);
        }
        match self.peek_major()? {
            MAJOR_UINT => self.uint().map(|_| ()),
            MAJOR_BYTES => self.bytes().map(|_| ()),
            MAJOR_TEXT => self.text().map(|_| ()),
            MAJOR_ARRAY => {
                for _ in 0..self.array()? {
                    self.skip_depth(depth + 1)?;
                }
                Ok(())
            }
            MAJOR_MAP => {
                for _ in 0..self.map()? {
                    self.skip_depth(depth + 1)?;
                    self.skip_depth(depth + 1)?;
                }
                Ok(())
            }
            MAJOR_TAG => {
                self.tag()?;
                self.skip_depth(depth + 1)
            }
            MAJOR_SIMPLE => match self.byte()? {
                0xf4..=0xf6 => Ok(()),
                _ => Err(UrError::Cbor),
            },
            _ => Err(UrError::Cbor),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::fountain::refvec::hex;

    fn enc(f: impl FnOnce(&mut Writer)) -> String {
        let mut w = Writer::new();
        f(&mut w);
        aw_hex(&w.into_bytes())
    }

    fn aw_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 8949 附录 A 的部分示例
    #[test]
    fn rfc8949_examples() {
        assert_eq!(
            enc(|w| {
                w.uint(0);
            }),
            "00"
        );
        assert_eq!(
            enc(|w| {
                w.uint(23);
            }),
            "17"
        );
        assert_eq!(
            enc(|w| {
                w.uint(24);
            }),
            "1818"
        );
        assert_eq!(
            enc(|w| {
                w.uint(100);
            }),
            "1864"
        );
        assert_eq!(
            enc(|w| {
                w.uint(1000);
            }),
            "1903e8"
        );
        assert_eq!(
            enc(|w| {
                w.uint(1_000_000);
            }),
            "1a000f4240"
        );
        assert_eq!(
            enc(|w| {
                w.uint(1_000_000_000_000);
            }),
            "1b000000e8d4a51000"
        );
        assert_eq!(
            enc(|w| {
                w.bytes(&[]);
            }),
            "40"
        );
        assert_eq!(
            enc(|w| {
                w.bytes(&[1, 2, 3, 4]);
            }),
            "4401020304"
        );
        assert_eq!(
            enc(|w| {
                w.text("a");
            }),
            "6161"
        );
        assert_eq!(
            enc(|w| {
                w.array(3).uint(1).uint(2).uint(3);
            }),
            "83010203"
        );
        assert_eq!(
            enc(|w| {
                w.map(2).uint(1).uint(2).uint(3).uint(4);
            }),
            "a201020304"
        );
        assert_eq!(
            enc(|w| {
                w.bool(true).bool(false);
            }),
            "f5f4"
        );
        assert_eq!(
            enc(|w| {
                w.tag(1).uint(1_363_896_240);
            }),
            "c11a514b67b0"
        );
    }

    #[test]
    fn reads_back_what_it_writes() {
        let mut w = Writer::new();
        w.array(4)
            .uint(u64::MAX)
            .bytes(b"xyz")
            .text("hi")
            .tag(40303)
            .map(1)
            .uint(2)
            .bool(true);
        let b = w.into_bytes();
        let mut r = Reader::new(&b);
        assert_eq!(r.array().unwrap(), 4);
        assert_eq!(r.uint().unwrap(), u64::MAX);
        assert_eq!(r.bytes().unwrap(), b"xyz");
        assert_eq!(r.text().unwrap(), "hi");
        assert_eq!(r.tag().unwrap(), 40303);
        assert_eq!(r.map().unwrap(), 1);
        assert_eq!(r.uint().unwrap(), 2);
        assert!(r.bool().unwrap());
        r.finish().unwrap();
    }

    #[test]
    fn rejects_non_canonical_indefinite_and_truncated() {
        for bad in [
            "1817",
            "190017",
            "1a0000ffff",
            "1b00000000ffffffff",
            "5f",
            "9f",
            "f97c00",
            "4401",
            "a2",
            "ff",
        ] {
            let b = hex(bad);
            let mut r = Reader::new(&b);
            assert!(r.skip().is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_huge_declared_lengths() {
        // 声明 2^32 个字节但只有 0 个
        let b = hex("5affffffff");
        assert!(Reader::new(&b).bytes().is_err());
        let b = hex("9affffffff");
        assert!(Reader::new(&b).array().is_err());
        let b = hex("baffffffff");
        assert!(Reader::new(&b).map().is_err());
    }

    #[test]
    fn rejects_deep_nesting() {
        let b = vec![0x81u8; 64];
        assert!(Reader::new(&b).skip().is_err());
    }
}
