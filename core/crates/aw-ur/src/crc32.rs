//! CRC-32（ISO-HDLC，即 zlib/以太网所用）：多项式 0xEDB88320（反射），初值与结果异或 0xFFFFFFFF。

const TABLE: [u32; 256] = make_table();

// 编译期求值：越界会成为编译错误而不是运行时 panic
#[allow(clippy::indexing_slicing)]
const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

pub fn checksum(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = usize::from((c as u8) ^ b);
        c = TABLE.get(idx).copied().unwrap_or(0) ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// 大端 4 字节（bytewords 校验和的形式）。
pub fn checksum_be(data: &[u8]) -> [u8; 4] {
    checksum(data).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_check_value() {
        assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
    }

    /// bc-ur test.cpp: test_crc32
    #[test]
    fn reference_vectors() {
        assert_eq!(checksum_be(b"Hello, world!"), [0xeb, 0xe6, 0xc6, 0xe6]);
        assert_eq!(checksum_be(b"Wolf"), [0x59, 0x8c, 0x84, 0xdc]);
    }
}
