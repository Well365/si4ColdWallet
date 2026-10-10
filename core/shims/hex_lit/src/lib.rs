//! `hex_lit` 的自写替代品（决策 D11）。
//!
//! crates.io 上的 hex_lit 0.1.1 记录的源码 commit（a1b61585…）在上游 git 仓库中不存在，
//! 无法追溯，按规则 R1 不使用。rust-bitcoin 只在测试和基准代码里用到 `hex!` 宏，
//! 这里提供同名同语义的实现：编译期把十六进制字符串字面量转换成 `[u8; N]`。
#![no_std]
#![forbid(unsafe_code)]

/// 返回十六进制字符串对应的字节数；长度为奇数时在编译期报错。
#[doc(hidden)]
pub const fn len(s: &str) -> usize {
    let n = s.len();
    if !n.is_multiple_of(2) {
        panic!("hex! 的输入长度必须为偶数");
    }
    n / 2
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("hex! 的输入含有非十六进制字符"),
    }
}

/// 把十六进制字符串解码为定长字节数组；在 `const` 上下文中求值。
#[doc(hidden)]
pub const fn decode<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        panic!("hex! 的输入长度与目标长度不符");
    }
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// 编译期十六进制字面量：`hex!("00ff")` → `[0x00, 0xff]`。
#[macro_export]
macro_rules! hex {
    ($s:expr) => {{
        const __AW_HEX_LEN: usize = $crate::len($s);
        const __AW_HEX_OUT: [u8; __AW_HEX_LEN] = $crate::decode::<__AW_HEX_LEN>($s);
        __AW_HEX_OUT
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn decodes_mixed_case() {
        assert_eq!(hex!("00ff10Ab"), [0x00, 0xff, 0x10, 0xab]);
    }

    #[test]
    fn empty_input_gives_empty_array() {
        let empty: [u8; 0] = hex!("");
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn genesis_script_prefix() {
        let v = hex!("4d04ffff001d0104");
        assert_eq!(v, [0x4d, 0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04]);
    }
}
