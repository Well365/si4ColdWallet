//! Keccak-256：以太坊用的原始 Keccak（填充字节 0x01），不是 FIPS 202 的 SHA3-256（填充 0x06）。
//!
//! 置换函数 Keccak-f[1600] 来自 `third_party/keccak`（RustCrypto keccak v0.1.2）；这里只写海绵结构。
//! 测试：以太坊公开向量 + 用同一海绵改 0x06 填充，与 Python 标准库 `hashlib.sha3_256`（独立实现）逐一比对。

/// 速率 = (1600 - 2 × 256) / 8 字节
const RATE: usize = 136;
const KECCAK_PAD: u8 = 0x01;

#[derive(Clone)]
pub struct Keccak256 {
    state: [u64; 25],
    buf: [u8; RATE],
    len: usize,
    pad: u8,
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::with_pad(KECCAK_PAD)
    }
}

impl Keccak256 {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_pad(pad: u8) -> Self {
        Self {
            state: [0; 25],
            buf: [0; RATE],
            len: 0,
            pad,
        }
    }

    fn absorb(state: &mut [u64; 25], block: &[u8; RATE]) {
        for (lane, chunk) in state.iter_mut().zip(block.as_chunks::<8>().0) {
            *lane ^= u64::from_le_bytes(*chunk);
        }
        keccak::f1600(state);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let free = RATE - self.len;
            let take = free.min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(dst) = self.buf.get_mut(self.len..self.len + take) {
                dst.copy_from_slice(head);
            }
            self.len += take;
            data = rest;
            if self.len == RATE {
                Self::absorb(&mut self.state, &self.buf);
                self.buf = [0; RATE];
                self.len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        if let Some(b) = self.buf.get_mut(self.len) {
            *b ^= self.pad;
        }
        if let Some(b) = self.buf.last_mut() {
            *b ^= 0x80;
        }
        Self::absorb(&mut self.state, &self.buf);
        let mut out = [0u8; 32];
        for (chunk, lane) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.state.iter()) {
            *chunk = lane.to_le_bytes();
        }
        out
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use aw_common::hex;

    /// 同一海绵、FIPS 202 填充（0x06）= SHA3-256，用于与 Python hashlib 做差分测试
    fn sha3_256(data: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::with_pad(0x06);
        h.update(data);
        h.finalize()
    }

    #[test]
    fn ethereum_known_vectors() {
        assert_eq!(
            hex::encode(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        // ERC-20 Transfer 事件签名
        assert_eq!(
            hex::encode(&keccak256(b"Transfer(address,address,uint256)")),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    /// testdata/sha3_256.txt 由 tools/testvectors/keccak_vectors.py 用 Python hashlib 生成：
    /// 每行"输入十六进制 期望十六进制"，覆盖 0–300 字节及速率边界（135/136/137/271/272/273）。
    #[test]
    fn matches_python_hashlib_sha3() {
        let data = include_str!("../testdata/sha3_256.txt");
        let mut n = 0;
        for line in data
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let (input, expect) = line.split_once(' ').unwrap();
            let input = if input == "-" {
                vec![]
            } else {
                hex::decode(input).unwrap()
            };
            assert_eq!(
                hex::encode(&sha3_256(&input)),
                expect,
                "len {}",
                input.len()
            );
            // 分段输入结果相同
            let mut h = Keccak256::with_pad(0x06);
            for part in input.chunks(7) {
                h.update(part);
            }
            assert_eq!(hex::encode(&h.finalize()), expect);
            n += 1;
        }
        assert!(n >= 300, "向量数量不足：{n}");
    }
}
