//! 256 位无符号整数：只实现审查需要的运算（比较、加、乘、十进制显示）。全部检查溢出。

use core::cmp::Ordering;

/// 四个 64 位小端"肢"：`0` 是最低位
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct U256([u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    /// 大端字节（最多 32 字节）。调用方负责先检查是否为规范编码。
    pub fn from_be_slice(b: &[u8]) -> Option<Self> {
        if b.len() > 32 {
            return None;
        }
        let mut full = [0u8; 32];
        full.get_mut(32 - b.len()..)?.copy_from_slice(b);
        Some(Self::from_be_bytes(&full))
    }

    pub fn from_be_bytes(b: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(b.rchunks_exact(8)) {
            let mut w = [0u8; 8];
            w.copy_from_slice(chunk);
            *limb = u64::from_be_bytes(w);
        }
        U256(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, limb) in out.rchunks_exact_mut(8).zip(self.0.iter()) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// 去掉前导零的大端字节（RLP 整数的规范编码；0 为空）
    pub fn to_minimal_be(self) -> Vec<u8> {
        let b = self.to_be_bytes();
        let start = b.iter().position(|&x| x != 0).unwrap_or(32);
        b.get(start..).map_or_else(Vec::new, <[u8]>::to_vec)
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    /// 能否放进 u64
    pub fn to_u64(self) -> Option<u64> {
        match self.0 {
            [v, 0, 0, 0] => Some(v),
            _ => None,
        }
    }

    /// 最高位是否为 1（≥ 2^255）：常见的"无限额授权"写法是全 1 或接近它
    pub fn top_bit(self) -> bool {
        self.0.last().is_some_and(|&hi| hi >> 63 == 1)
    }

    pub fn checked_add(self, o: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for ((r, a), b) in out.iter_mut().zip(self.0).zip(o.0) {
            let (s1, c1) = a.overflowing_add(b);
            let (s2, c2) = s1.overflowing_add(carry);
            *r = s2;
            carry = u64::from(c1) + u64::from(c2);
        }
        (carry == 0).then_some(U256(out))
    }

    pub fn checked_mul(self, o: U256) -> Option<U256> {
        let mut out = [0u128; 8];
        for (i, a) in self.0.iter().enumerate() {
            let mut carry = 0u128;
            for (j, b) in o.0.iter().enumerate() {
                let slot = out.get_mut(i + j)?;
                let t = u128::from(*a) * u128::from(*b) + *slot + carry;
                *slot = t & u128::from(u64::MAX);
                carry = t >> 64;
            }
            *out.get_mut(i + 4)? += carry;
        }
        if out.get(4..)?.iter().any(|&x| x != 0) {
            return None;
        }
        let mut limbs = [0u64; 4];
        for (l, v) in limbs.iter_mut().zip(out.iter()) {
            *l = u64::try_from(*v).ok()?;
        }
        Some(U256(limbs))
    }

    /// 除以小整数，返回（商，余数）
    fn div_rem_u64(self, d: u64) -> (U256, u64) {
        let mut q = [0u64; 4];
        let mut rem = 0u128;
        for (qi, limb) in q.iter_mut().zip(self.0).rev() {
            let cur = (rem << 64) | u128::from(limb);
            *qi = u64::try_from(cur / u128::from(d)).unwrap_or(u64::MAX);
            rem = cur % u128::from(d);
        }
        (U256(q), u64::try_from(rem).unwrap_or(0))
    }

    /// 十进制字符串
    pub fn to_decimal(self) -> String {
        if self.is_zero() {
            return "0".to_owned();
        }
        let mut digits = Vec::new();
        let mut v = self;
        while !v.is_zero() {
            let (q, r) = v.div_rem_u64(10);
            digits.push(b'0' + u8::try_from(r).unwrap_or(0));
            v = q;
        }
        digits.reverse();
        String::from_utf8(digits).unwrap_or_default()
    }

    /// 按小数位格式化：`format_units(1500000000000000000, 18) = "1.5"`。去掉末尾的 0，不做四舍五入。
    pub fn format_units(self, decimals: u32) -> String {
        let s = self.to_decimal();
        let d = usize::try_from(decimals).unwrap_or(0);
        if d == 0 {
            return s;
        }
        let padded = if s.len() <= d {
            format!("{}{}", "0".repeat(d + 1 - s.len()), s)
        } else {
            s
        };
        let (int, frac) = padded.split_at(padded.len() - d);
        let frac = frac.trim_end_matches('0');
        if frac.is_empty() {
            int.to_owned()
        } else {
            format!("{int}.{frac}")
        }
    }
}

impl U256 {
    /// 解析十进制金额文本（如 "0.01"）为最小单位整数。只接受数字与至多一个小数点；
    /// 小数位多于 `decimals`、为空、溢出都返回 None（不做四舍五入，避免金额被悄悄改变）。
    pub fn parse_units(s: &str, decimals: u32) -> Option<U256> {
        let (int, frac) = s.split_once('.').unwrap_or((s, ""));
        let d = usize::try_from(decimals).ok()?;
        if (int.is_empty() && frac.is_empty())
            || frac.len() > d
            || !int.bytes().chain(frac.bytes()).all(|c| c.is_ascii_digit())
            || (s.contains('.') && frac.is_empty())
        {
            return None;
        }
        let mut v = U256::ZERO;
        let ten = U256::from_u64(10);
        for c in int
            .bytes()
            .chain(frac.bytes())
            .chain(core::iter::repeat_n(b'0', d - frac.len()))
        {
            v = v
                .checked_mul(ten)?
                .checked_add(U256::from_u64(u64::from(c - b'0')))?;
        }
        Some(v)
    }

    /// JSON-RPC 的十六进制数量（"0x0"、"0x1a2b"）：必须有 0x 前缀、无多余前导零、不超过 256 位
    pub fn from_hex_quantity(s: &str) -> Option<U256> {
        let h = s.strip_prefix("0x")?;
        if h.is_empty() || h.len() > 64 || (h.len() > 1 && h.starts_with('0')) {
            return None;
        }
        let padded = if h.len() % 2 == 1 {
            format!("0{h}")
        } else {
            h.to_owned()
        };
        U256::from_be_slice(&aw_common::hex::decode(&padded.to_ascii_lowercase())?)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn decimal_and_units() {
        assert_eq!(U256::ZERO.to_decimal(), "0");
        assert_eq!(
            U256::MAX.to_decimal(),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        let wei = U256::from_u64(1_500_000_000_000_000_000);
        assert_eq!(wei.format_units(18), "1.5");
        assert_eq!(U256::from_u64(1).format_units(18), "0.000000000000000001");
        assert_eq!(U256::from_u64(1_000_000).format_units(6), "1");
        assert_eq!(U256::from_u64(123).format_units(0), "123");
    }

    #[test]
    fn arithmetic_and_bytes() {
        let a = U256::from_be_slice(&[0x01, 0x00]).unwrap();
        assert_eq!(a, U256::from_u64(256));
        assert_eq!(a.to_minimal_be(), vec![0x01, 0x00]);
        assert!(U256::ZERO.to_minimal_be().is_empty());
        assert_eq!(U256::MAX.checked_add(U256::from_u64(1)), None);
        assert_eq!(U256::MAX.checked_mul(U256::from_u64(2)), None);
        let big = U256::from_u64(u64::MAX)
            .checked_mul(U256::from_u64(u64::MAX))
            .unwrap();
        assert_eq!(big.to_decimal(), "340282366920938463426481119284349108225");
        assert!(U256::MAX.top_bit() && !big.top_bit());
        assert!(U256::from_u64(2) > U256::from_u64(1) && big > U256::from_u64(u64::MAX));
        let b = U256::from_be_bytes(&U256::MAX.to_be_bytes());
        assert_eq!(b, U256::MAX);
        assert_eq!(U256::from_be_slice(&[0u8; 33]), None);
    }

    #[test]
    fn parse_amounts_and_quantities() {
        assert_eq!(
            U256::parse_units("0.01", 18),
            Some(U256::from_u64(10_000_000_000_000_000))
        );
        assert_eq!(
            U256::parse_units("12.5", 6),
            Some(U256::from_u64(12_500_000))
        );
        assert_eq!(U256::parse_units("3", 0), Some(U256::from_u64(3)));
        assert_eq!(U256::parse_units(".5", 1), Some(U256::from_u64(5)));
        for bad in ["", ".", "1.", "1.2.3", "-1", "1e3", " 1", "0.0000001", "１"] {
            assert_eq!(U256::parse_units(bad, 6), None, "{bad}");
        }
        assert_eq!(U256::parse_units(&"9".repeat(80), 0), None); // 溢出
        assert_eq!(U256::from_hex_quantity("0x0"), Some(U256::ZERO));
        assert_eq!(U256::from_hex_quantity("0x1a"), Some(U256::from_u64(26)));
        assert_eq!(
            U256::from_hex_quantity("0xABC"),
            Some(U256::from_u64(0xabc))
        );
        for bad in [
            "0x",
            "1a",
            "0x01",
            "0xzz",
            &format!("0x1{}", "0".repeat(64)),
        ] {
            assert_eq!(U256::from_hex_quantity(bad), None, "{bad}");
        }
    }
}
