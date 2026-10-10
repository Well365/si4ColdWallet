//! RLP（以太坊黄皮书附录 B）：严格解码 + 编码。
//!
//! 解码只接受规范编码：单字节 < 0x80 必须直接写；长度用最短形式；长格式只用于 > 55 字节；
//! 整数不得有前导零。这样"界面上显示的"和"被签名的字节"只有一种对应关系。

use crate::uint::U256;

const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlpError {
    /// 输入提前结束或声明长度超出剩余数据
    Truncated,
    /// 非规范编码
    NonCanonical,
    /// 解析完后还有多余字节
    Trailing,
    /// 嵌套过深
    TooDeep,
    /// 期望字节串却是列表，或相反
    WrongKind,
    /// 整数超过 256 位或有前导零
    BadInteger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item<'a> {
    Bytes(&'a [u8]),
    List(Vec<Node<'a>>),
}

/// 解码结果：内容 + 本项完整编码（拼装已签交易时原样复用）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node<'a> {
    pub item: Item<'a>,
    pub raw: &'a [u8],
}

impl<'a> Node<'a> {
    pub fn bytes(&self) -> Result<&'a [u8], RlpError> {
        match self.item {
            Item::Bytes(b) => Ok(b),
            Item::List(_) => Err(RlpError::WrongKind),
        }
    }

    pub fn list(&self) -> Result<&[Node<'a>], RlpError> {
        match &self.item {
            Item::List(l) => Ok(l),
            Item::Bytes(_) => Err(RlpError::WrongKind),
        }
    }

    /// 规范整数：≤ 32 字节、无前导零（0 编码为空串）
    pub fn uint(&self) -> Result<U256, RlpError> {
        let b = self.bytes()?;
        if b.first() == Some(&0) {
            return Err(RlpError::BadInteger);
        }
        U256::from_be_slice(b).ok_or(RlpError::BadInteger)
    }

    pub fn u64(&self) -> Result<u64, RlpError> {
        self.uint()?.to_u64().ok_or(RlpError::BadInteger)
    }
}

fn be_len(b: &[u8]) -> Result<usize, RlpError> {
    if b.first() == Some(&0) || b.len() > 4 {
        return Err(RlpError::NonCanonical);
    }
    Ok(b.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x)))
}

/// 解析一项，返回（节点，剩余数据）
fn parse(data: &[u8], depth: usize) -> Result<(Node<'_>, &[u8]), RlpError> {
    if depth > MAX_DEPTH {
        return Err(RlpError::TooDeep);
    }
    let (&first, rest) = data.split_first().ok_or(RlpError::Truncated)?;
    let (is_list, header, len) = match first {
        0x00..=0x7f => {
            let (raw, tail) = data.split_at(1);
            return Ok((
                Node {
                    item: Item::Bytes(raw),
                    raw,
                },
                tail,
            ));
        }
        0x80..=0xb7 => (false, 1, usize::from(first - 0x80)),
        0xb8..=0xbf => {
            let n = usize::from(first - 0xb7);
            let len = be_len(rest.get(..n).ok_or(RlpError::Truncated)?)?;
            if len <= 55 {
                return Err(RlpError::NonCanonical);
            }
            (false, 1 + n, len)
        }
        0xc0..=0xf7 => (true, 1, usize::from(first - 0xc0)),
        0xf8..=0xff => {
            let n = usize::from(first - 0xf7);
            let len = be_len(rest.get(..n).ok_or(RlpError::Truncated)?)?;
            if len <= 55 {
                return Err(RlpError::NonCanonical);
            }
            (true, 1 + n, len)
        }
    };
    let total = header.checked_add(len).ok_or(RlpError::Truncated)?;
    let raw = data.get(..total).ok_or(RlpError::Truncated)?;
    let payload = raw.get(header..).ok_or(RlpError::Truncated)?;
    let tail = data.get(total..).ok_or(RlpError::Truncated)?;
    if !is_list {
        if len == 1 && payload.first().is_some_and(|&b| b < 0x80) {
            return Err(RlpError::NonCanonical);
        }
        return Ok((
            Node {
                item: Item::Bytes(payload),
                raw,
            },
            tail,
        ));
    }
    let mut items = Vec::new();
    let mut cur = payload;
    while !cur.is_empty() {
        let (node, next) = parse(cur, depth + 1)?;
        items.push(node);
        cur = next;
    }
    Ok((
        Node {
            item: Item::List(items),
            raw,
        },
        tail,
    ))
}

/// 解码完整输入（不允许多余字节）
pub fn decode(data: &[u8]) -> Result<Node<'_>, RlpError> {
    let (node, rest) = parse(data, 0)?;
    if !rest.is_empty() {
        return Err(RlpError::Trailing);
    }
    Ok(node)
}

fn header(out: &mut Vec<u8>, short_base: u8, len: usize) {
    if len <= 55 {
        out.push(short_base + u8::try_from(len).unwrap_or(0));
    } else {
        let be = len.to_be_bytes();
        let start = be.iter().position(|&x| x != 0).unwrap_or(be.len() - 1);
        let n = be.get(start..).unwrap_or(&[]);
        out.push(short_base + 55 + u8::try_from(n.len()).unwrap_or(0));
        out.extend_from_slice(n);
    }
}

pub fn encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
    match b {
        [x] if *x < 0x80 => out.push(*x),
        _ => {
            header(out, 0x80, b.len());
            out.extend_from_slice(b);
        }
    }
}

pub fn encode_uint(out: &mut Vec<u8>, v: U256) {
    encode_bytes(out, &v.to_minimal_be());
}

/// `items` 是各元素已编码字节的拼接
pub fn encode_list(out: &mut Vec<u8>, items: &[u8]) {
    header(out, 0xc0, items.len());
    out.extend_from_slice(items);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use aw_common::hex;

    fn enc_bytes(b: &[u8]) -> Vec<u8> {
        let mut v = vec![];
        encode_bytes(&mut v, b);
        v
    }

    /// 以太坊 RLPTests（rlptest.json）中的代表性用例
    #[test]
    fn official_examples_roundtrip() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "80"),
            (b"dog", "83646f67"),
            (&[0x00], "00"),
            (&[0x7f], "7f"),
            (&[0x80], "8180"),
            (b"Lorem ipsum dolor sit amet, consectetur adipisicing elit", "b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747572206164697069736963696e6720656c6974"),
        ];
        for (input, want) in cases {
            assert_eq!(hex::encode(&enc_bytes(input)), *want);
            let raw = hex::decode(want).unwrap();
            assert_eq!(decode(&raw).unwrap().bytes().unwrap(), *input);
        }
        let mut v = vec![];
        encode_uint(&mut v, U256::from_u64(1024));
        assert_eq!(hex::encode(&v), "820400");
        // ["cat","dog"]
        let mut items = enc_bytes(b"cat");
        items.extend(enc_bytes(b"dog"));
        let mut l = vec![];
        encode_list(&mut l, &items);
        assert_eq!(hex::encode(&l), "c88363617483646f67");
        let n = decode(&l).unwrap();
        assert_eq!(n.list().unwrap()[1].bytes().unwrap(), b"dog");
        assert_eq!(
            n.list().unwrap()[0].raw,
            &hex::decode("83636174").unwrap()[..]
        );
        // 集合论表示 [ [], [[]], [ [], [[]] ] ]
        let set = hex::decode("c7c0c1c0c3c0c1c0").unwrap();
        assert_eq!(decode(&set).unwrap().list().unwrap().len(), 3);
    }

    /// RLPTests 的 invalidRLPTests：非规范编码与截断必须拒绝
    #[test]
    fn rejects_invalid() {
        for bad in [
            "8100", // 单字节 < 0x80 不得加长度头
            "817f",
            "b800",                   // 长格式用于 ≤ 55 字节
            "b90000",                 // 长度前导零
            "f80180",                 // 列表长格式用于 ≤ 55 字节
            "83646f",                 // 截断
            "c58363617483",           // 列表内截断
            "8080",                   // 多余字节
            "bf0f000000000000021111", // 长度大得离谱
        ] {
            assert!(decode(&hex::decode(bad).unwrap()).is_err(), "应拒绝 {bad}");
        }
        // 整数不得有前导零
        let raw = hex::decode("820004").unwrap();
        let n = decode(&raw).unwrap();
        assert_eq!(n.uint(), Err(RlpError::BadInteger));
        // 嵌套过深（10 层）
        let deep = hex::decode("c9c8c7c6c5c4c3c2c1c0").unwrap();
        assert!(decode(&deep).is_err());
    }
}
