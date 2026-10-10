//! 十六进制编解码（小写）。只用于非秘密数据的显示与测试。

/// 字节 → 小写十六进制字符串。
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(digit(b >> 4));
        s.push(digit(b & 0x0f));
    }
    s
}

/// 十六进制字符串 → 字节；长度为奇数或含非法字符时返回 `None`。
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[hi, lo]| Some((nibble(hi)? << 4) | nibble(lo)?))
        .collect()
}

/// 0..16 → '0'..'9' / 'a'..'f'
fn digit(n: u8) -> char {
    match n {
        0..=9 => char::from(b'0' + n),
        _ => char::from(b'a' + (n & 0x0f) - 10),
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = [0x00, 0x01, 0x7f, 0x80, 0xff];
        assert_eq!(encode(&data), "00017f80ff");
        assert_eq!(decode("00017F80ff"), Some(data.to_vec()));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("zz"), None);
    }

    #[test]
    fn empty() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode(""), Some(vec![]));
    }

    #[test]
    fn all_byte_values_roundtrip() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)), Some(all));
    }
}
