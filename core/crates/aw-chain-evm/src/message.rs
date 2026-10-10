//! 消息签名（EIP-191 `personal_sign`）。
//!
//! 签名哈希 = Keccak-256("\x19Ethereum Signed Message:\n" ‖ 十进制长度 ‖ 消息)。
//! 能显示为文字的按文字显示；否则显示十六进制并警告。恰好 32 字节的消息很可能是某笔交易或
//! 授权的哈希——签了就等于盲签，一律拒签（`review::describe_message`，D33）。

use crate::keccak::Keccak256;

/// personal_sign 消息的上限：超过就无法在屏幕上完整核对，拒签（审查 H1）
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// 十六进制显示，每行 32 字节（64 个字符），界面不截断也能逐行核对
pub fn hex_lines(b: &[u8]) -> String {
    let lines: Vec<String> = b.chunks(32).map(aw_common::hex::encode).collect();
    format!("0x{}", lines.join("\n"))
}

pub fn personal_hash(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"\x19Ethereum Signed Message:\n");
    h.update(msg.len().to_string().as_bytes());
    h.update(msg);
    h.finalize()
}

/// 可安全显示的文本：只允许白名单字符——可打印 ASCII、换行与制表、中日韩统一表意文字、
/// 中文标点与少数全角标点。其他一切（不可见字符、方向控制符、西里尔字母等易混淆字母、
/// 组合字符、变体选择符、标签字符……）都按十六进制显示，避免"看到的文字"与"签名的字节"不一致。
pub fn as_text(msg: &[u8]) -> Option<&str> {
    let s = core::str::from_utf8(msg).ok()?;
    let ok = |c: char| {
        matches!(c, ' '..='~' | '\n' | '\t')
            || matches!(c, '\u{4e00}'..='\u{9fff}' | '\u{3400}'..='\u{4dbf}')
            || matches!(c, '\u{3001}'..='\u{3003}' | '\u{3008}'..='\u{3011}' | '\u{3014}'..='\u{301f}')
            || matches!(
                c,
                '，' | '！'
                    | '：'
                    | '；'
                    | '？'
                    | '（'
                    | '）'
                    | '“'
                    | '”'
                    | '‘'
                    | '’'
                    | '…'
                    | '—'
            )
    };
    s.chars().all(ok).then_some(s)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use aw_common::hex;

    #[test]
    fn eip191_hash() {
        // web3.js / ethers 的 hashMessage("Hello World") 公开结果
        assert_eq!(
            hex::encode(&personal_hash(b"Hello World")),
            "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
        );
    }

    #[test]
    fn text_detection() {
        assert_eq!(
            as_text(b"Sign in to example.org\nNonce: 1"),
            Some("Sign in to example.org\nNonce: 1")
        );
        assert_eq!(as_text(&[0xff, 0xfe]), None);
        assert_eq!(as_text("a\u{202e}b".as_bytes()), None); // 方向控制符可伪造显示内容
        assert_eq!(as_text(b"\x07bell"), None);
        assert_eq!(
            as_text("登录 example.org，确认身份。".as_bytes()),
            Some("登录 example.org，确认身份。")
        );
        // 审查发现的漏网字符：都必须拒绝
        for bad in [
            "\u{61c}",
            "\u{2060}",
            "\u{2064}",
            "\u{206a}",
            "\u{ad}",
            "\u{34f}",
            "\u{180e}",
            "\u{fe0f}",
            "\u{3164}",
            "\u{ffa0}",
            "\u{e0041}",
            "\u{2028}",
            "\u{2029}",
            "ex\u{430}mple.org",
            "ｅｘ",
            "\u{3000}",
        ] {
            assert_eq!(as_text(format!("Sign in{bad}").as_bytes()), None, "{bad:?}");
        }
    }
}
