//! Solana 交易消息的严格解析（P2c-T1）。签名的就是这串字节，所以签名机从它重新解析出全部内容，
//! 不信任请求里的任何其他说法。
//!
//! ```text
//! legacy：header(3) ‖ shortvec 账户数 ‖ 账户×32 ‖ 最近区块哈希 32 ‖ shortvec 指令数 ‖ 指令…
//! v0：    0x80 ‖ 同上 ‖ shortvec 查找表数 ‖ 查找表…
//! 指令：  程序序号 u8 ‖ shortvec 账户数 ‖ 账户序号… ‖ shortvec 数据长度 ‖ 数据
//! 查找表：表地址 32 ‖ shortvec 可写序号数 ‖ 序号… ‖ shortvec 只读序号数 ‖ 序号…
//! ```
//!
//! 严格：紧凑长度必须是最短编码；序号不得越界；账户不得重复；不得有多余字节；总长不超过 1232 字节
//! （Solana 网络包上限，再长的交易本来也发不出去）。任何一项不符都返回 `Parse`。

use crate::SolError;

/// Solana 网络包可承载的交易上限；消息只会更短
pub const MAX_MESSAGE_BYTES: usize = 1232;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Legacy,
    V0,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// 程序在账户表里的序号
    pub program: u8,
    /// 指令用到的账户序号
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// v0 消息的地址查找表引用：被引用的地址不在消息里，离线无法核实
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub table: [u8; 32],
    pub writable: Vec<u8>,
    pub readonly: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub version: Version,
    /// 需要签名的账户数（账户表前 N 个）
    pub required_signatures: u8,
    /// 其中只读的个数（排在签名账户的末尾）
    pub readonly_signed: u8,
    /// 不签名账户中只读的个数（排在账户表末尾）
    pub readonly_unsigned: u8,
    pub account_keys: Vec<[u8; 32]>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<Instruction>,
    pub lookups: Vec<Lookup>,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, SolError> {
        let b = *self.data.get(self.pos).ok_or(SolError::Parse)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SolError> {
        let end = self.pos.checked_add(n).ok_or(SolError::Parse)?;
        let s = self.data.get(self.pos..end).ok_or(SolError::Parse)?;
        self.pos = end;
        Ok(s)
    }

    fn key(&mut self) -> Result<[u8; 32], SolError> {
        self.take(32)?.try_into().map_err(|_| SolError::Parse)
    }

    /// 紧凑长度（compact-u16）：每字节 7 位、最多 3 字节、只接受最短编码
    fn shortvec(&mut self) -> Result<usize, SolError> {
        let mut v = 0u32;
        for i in 0..3u32 {
            let b = self.u8()?;
            v |= u32::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                // 最短编码：除了单字节的 0，最后一个字节不能是 0
                if i > 0 && b == 0 {
                    return Err(SolError::Parse);
                }
                return u16::try_from(v)
                    .map(usize::from)
                    .map_err(|_| SolError::Parse);
            }
        }
        Err(SolError::Parse)
    }

    fn indices(&mut self) -> Result<Vec<u8>, SolError> {
        let n = self.shortvec()?;
        Ok(self.take(n)?.to_vec())
    }
}

/// 紧凑长度编码（观察机构造与测试用）
pub fn encode_shortvec(out: &mut Vec<u8>, n: u16) {
    let mut v = n;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

impl Message {
    pub fn parse(data: &[u8]) -> Result<Message, SolError> {
        if data.is_empty() || data.len() > MAX_MESSAGE_BYTES {
            return Err(SolError::Parse);
        }
        let mut c = Cursor { data, pos: 0 };
        let first = *data.first().ok_or(SolError::Parse)?;
        let version = if first & 0x80 != 0 {
            // 版本化消息：只认 v0
            if first & 0x7f != 0 {
                return Err(SolError::Parse);
            }
            c.pos = 1;
            Version::V0
        } else {
            Version::Legacy
        };
        let required_signatures = c.u8()?;
        let readonly_signed = c.u8()?;
        let readonly_unsigned = c.u8()?;
        let n_keys = c.shortvec()?;
        let mut account_keys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            account_keys.push(c.key()?);
        }
        let recent_blockhash = c.key()?;
        let n_ix = c.shortvec()?;
        let mut instructions = Vec::new();
        for _ in 0..n_ix {
            let program = c.u8()?;
            let accounts = c.indices()?;
            let data_len = c.shortvec()?;
            let data = c.take(data_len)?.to_vec();
            instructions.push(Instruction {
                program,
                accounts,
                data,
            });
        }
        let mut lookups = Vec::new();
        if version == Version::V0 {
            let n = c.shortvec()?;
            for _ in 0..n {
                let table = c.key()?;
                let writable = c.indices()?;
                let readonly = c.indices()?;
                lookups.push(Lookup {
                    table,
                    writable,
                    readonly,
                });
            }
        }
        if c.pos != data.len() {
            return Err(SolError::Parse);
        }
        let m = Message {
            version,
            required_signatures,
            readonly_signed,
            readonly_unsigned,
            account_keys,
            recent_blockhash,
            instructions,
            lookups,
        };
        m.sanitize()?;
        Ok(m)
    }

    /// 地址查找表带来的账户数
    pub fn loaded_count(&self) -> usize {
        self.lookups
            .iter()
            .map(|l| l.writable.len() + l.readonly.len())
            .sum()
    }

    /// 与 Solana 节点相同的合法性检查（缺了任何一项，同一串字节在链上与签名机里的含义就可能不同）
    fn sanitize(&self) -> Result<(), SolError> {
        let keys = self.account_keys.len();
        let req = usize::from(self.required_signatures);
        // 至少一个签名者；手续费付款人（第一个签名者）必须可写
        if req == 0 || self.readonly_signed >= self.required_signatures {
            return Err(SolError::Parse);
        }
        if req + usize::from(self.readonly_unsigned) > keys {
            return Err(SolError::Parse);
        }
        // 账户不得重复（重复账户会让"同一个地址"在不同位置有不同权限）
        for (i, k) in self.account_keys.iter().enumerate() {
            if self.account_keys.iter().skip(i + 1).any(|o| o == k) {
                return Err(SolError::Parse);
            }
        }
        let total = keys + self.loaded_count();
        if total > 256 {
            return Err(SolError::Parse);
        }
        for ix in &self.instructions {
            let p = usize::from(ix.program);
            // 程序不能是手续费付款人，也不能来自查找表
            if p == 0 || p >= keys {
                return Err(SolError::Parse);
            }
            if ix.accounts.iter().any(|&a| usize::from(a) >= total) {
                return Err(SolError::Parse);
            }
        }
        Ok(())
    }

    /// 账户 i 是否需要签名
    pub fn is_signer(&self, i: usize) -> bool {
        i < usize::from(self.required_signatures)
    }

    /// 账户 i 是否可写（只看消息内的账户；查找表账户按其所在段判断）
    pub fn is_writable(&self, i: usize) -> bool {
        let req = usize::from(self.required_signatures);
        let keys = self.account_keys.len();
        if i < req {
            i < req - usize::from(self.readonly_signed)
        } else if i < keys {
            i < keys - usize::from(self.readonly_unsigned)
        } else {
            // 查找表：可写段在前
            let mut j = i - keys;
            for l in &self.lookups {
                if j < l.writable.len() {
                    return true;
                }
                j -= l.writable.len();
                if j < l.readonly.len() {
                    return false;
                }
                j -= l.readonly.len();
            }
            false
        }
    }

    /// 序号对应的地址；来自查找表的返回 None（离线无法知道是谁）
    pub fn key(&self, i: u8) -> Option<&[u8; 32]> {
        self.account_keys.get(usize::from(i))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn k(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// legacy：付款人 0x11 → 收款人 0x22，System Transfer 1 SOL
    pub(crate) fn transfer_message() -> Vec<u8> {
        let mut m = vec![1, 0, 1];
        encode_shortvec(&mut m, 3);
        m.extend_from_slice(&k(0x11));
        m.extend_from_slice(&k(0x22));
        m.extend_from_slice(&[0u8; 32]); // System 程序
        m.extend_from_slice(&k(0x33)); // 最近区块哈希
        encode_shortvec(&mut m, 1);
        m.push(2);
        encode_shortvec(&mut m, 2);
        m.extend_from_slice(&[0, 1]);
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        encode_shortvec(&mut m, data.len() as u16);
        m.extend_from_slice(&data);
        m
    }

    #[test]
    fn shortvec_round_trip_and_rejects_non_minimal() {
        for n in [0u16, 1, 127, 128, 255, 16383, 16384, u16::MAX] {
            let mut b = Vec::new();
            encode_shortvec(&mut b, n);
            let mut c = Cursor { data: &b, pos: 0 };
            assert_eq!(c.shortvec().unwrap(), usize::from(n));
            assert_eq!(c.pos, b.len());
        }
        for bad in [
            &[0x80, 0x00][..],
            &[0xff, 0x80, 0x00],
            &[0x80, 0x80, 0x80],
            &[0xff, 0xff, 0x04],
            &[0x80],
        ] {
            let mut c = Cursor { data: bad, pos: 0 };
            assert_eq!(c.shortvec(), Err(SolError::Parse), "{bad:?}");
        }
    }

    #[test]
    fn parses_legacy_transfer() {
        let m = Message::parse(&transfer_message()).unwrap();
        assert_eq!(m.version, Version::Legacy);
        assert_eq!(m.required_signatures, 1);
        assert_eq!(m.account_keys, vec![k(0x11), k(0x22), [0u8; 32]]);
        assert_eq!(m.recent_blockhash, k(0x33));
        assert_eq!(m.instructions.len(), 1);
        assert_eq!(m.instructions[0].program, 2);
        assert_eq!(m.instructions[0].accounts, vec![0, 1]);
        assert!(m.is_signer(0) && !m.is_signer(1));
        assert!(m.is_writable(0) && m.is_writable(1) && !m.is_writable(2));
    }

    #[test]
    fn parses_v0_with_lookup() {
        let legacy = transfer_message();
        let mut m = vec![0x80];
        m.extend_from_slice(&legacy);
        encode_shortvec(&mut m, 1);
        m.extend_from_slice(&k(0x44));
        encode_shortvec(&mut m, 1);
        m.push(5);
        encode_shortvec(&mut m, 0);
        let p = Message::parse(&m).unwrap();
        assert_eq!(p.version, Version::V0);
        assert_eq!(p.loaded_count(), 1);
        assert!(p.is_writable(3));
        assert_eq!(p.key(3), None);
    }

    #[test]
    fn rejects_malformed_messages() {
        let good = transfer_message();
        let mut cases: Vec<(&str, Vec<u8>)> = vec![];
        let mut t = good.clone();
        t.push(0);
        cases.push(("多余字节", t));
        cases.push(("截断", good[..good.len() - 1].to_vec()));
        let mut t = good.clone();
        t[0] = 0;
        cases.push(("没有签名者", t));
        let mut t = good.clone();
        t[1] = 1;
        cases.push(("付款人只读", t));
        let mut t = good.clone();
        t[2] = 3;
        cases.push(("只读计数超出", t));
        let mut t = good.clone();
        t[4..36].copy_from_slice(&k(0x22));
        cases.push(("重复账户", t));
        let ix = 4 + 32 * 3 + 32 + 1;
        let mut t = good.clone();
        t[ix] = 0;
        cases.push(("程序是付款人", t));
        let mut t = good.clone();
        t[ix] = 9;
        cases.push(("程序序号越界", t));
        let mut t = good.clone();
        t[ix + 3] = 7;
        cases.push(("账户序号越界", t));
        let mut t = vec![0x81];
        t.extend_from_slice(&good);
        cases.push(("未知版本", t));
        cases.push(("空", vec![]));
        cases.push(("超长", vec![1; MAX_MESSAGE_BYTES + 1]));
        for (name, data) in cases {
            assert_eq!(Message::parse(&data), Err(SolError::Parse), "{name}");
        }
    }

    /// 任意截断与逐字节改动都不能 panic（只能是解析成功或 Parse）
    #[test]
    fn never_panics_on_mutations() {
        let good = transfer_message();
        for cut in 0..=good.len() {
            let _ = Message::parse(&good[..cut]);
        }
        for i in 0..good.len() {
            for v in [0u8, 1, 0x7f, 0x80, 0xff] {
                let mut t = good.clone();
                t[i] = v;
                let _ = Message::parse(&t);
            }
        }
    }
}
