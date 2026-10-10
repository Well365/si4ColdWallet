//! xoshiro256**（Blackman & Vigna），按 bc-ur 参考实现的方式播种：
//! 种子字节 → SHA-256 → 4 个大端 u64 作为初始状态。只用于决定喷泉码的分片组合，与安全无关。

use bitcoin_hashes::{sha256, Hash};

pub(crate) struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    pub fn from_seed_bytes(bytes: &[u8]) -> Self {
        let d = sha256::Hash::hash(bytes).to_byte_array();
        let mut s = [0u64; 4];
        for (i, chunk) in d.as_chunks::<8>().0.iter().enumerate() {
            if let Some(slot) = s.get_mut(i) {
                *slot = u64::from_be_bytes(*chunk);
            }
        }
        Self { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = self.s;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1 << 17;
        let s2 = s2 ^ s0;
        let s3 = s3 ^ s1;
        let s1 = s1 ^ s2;
        let s0 = s0 ^ s3;
        let s2 = s2 ^ t;
        let s3 = s3.rotate_left(45);
        self.s = [s0, s1, s2, s3];
        result
    }

    /// [0, 1) 区间的双精度数；与参考实现相同：next() / (2^64)。
    pub fn next_double(&mut self) -> f64 {
        let m = u64::MAX as f64 + 1.0;
        self.next_u64() as f64 / m
    }

    /// [low, high] 闭区间整数。参考实现在 next_double()==1.0（概率约 2^-54）时会越界，这里截到 high。
    pub fn next_int(&mut self, low: u64, high: u64) -> u64 {
        let span = (high - low + 1) as f64;
        ((self.next_double() * span) as u64 + low).min(high)
    }

    #[cfg(test)]
    pub fn next_byte(&mut self) -> u8 {
        u8::try_from(self.next_int(0, 255)).unwrap_or(u8::MAX)
    }

    #[cfg(test)]
    pub fn next_data(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::fountain::refvec;

    /// bc-ur test.cpp: test_rng_1
    #[test]
    fn reference_rng_1() {
        let mut rng = Xoshiro256::from_seed_bytes(b"Wolf");
        let got: Vec<u64> = (0..100).map(|_| rng.next_u64() % 100).collect();
        let want = refvec::ints_after(&refvec::section("test_rng_1"), "expected_numbers = {");
        assert_eq!(got, want);
    }

    /// bc-ur test.cpp: test_rng_2（种子为 CRC32("Wolf") 的大端 4 字节）
    #[test]
    fn reference_rng_2() {
        let crc = crate::crc32::checksum(b"Wolf");
        let mut rng = Xoshiro256::from_seed_bytes(&crc.to_be_bytes());
        let got: Vec<u64> = (0..100).map(|_| rng.next_u64() % 100).collect();
        let want = refvec::ints_after(&refvec::section("test_rng_2"), "expected_numbers = {");
        assert_eq!(got, want);
    }

    /// bc-ur test.cpp: test_rng_3
    #[test]
    fn reference_rng_3() {
        let mut rng = Xoshiro256::from_seed_bytes(b"Wolf");
        let got: Vec<u64> = (0..100).map(|_| rng.next_int(1, 10)).collect();
        let want = refvec::ints_after(&refvec::section("test_rng_3"), "expected_numbers = {");
        assert_eq!(got, want);
    }
}
