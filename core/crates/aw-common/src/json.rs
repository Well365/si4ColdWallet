//! 最小 JSON 输出器（决策 D6：不用 serde）。只负责"写"，Swift 侧用系统 JSONDecoder 读。

/// JSON 值。数字只支持无符号整数（金额以聪为单位，避免浮点）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    UInt(u64),
    Str(String),
    Array(Vec<Json>),
    /// 保持插入顺序，便于测试锁定格式
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn obj(fields: Vec<(&str, Json)>) -> Json {
        Json::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn to_string_compact(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::UInt(n) => out.push_str(&n.to_string()),
            Json::Str(s) => write_str(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_nested_values() {
        let v = Json::obj(vec![
            ("a", Json::UInt(1)),
            ("b", Json::Array(vec![Json::Bool(true), Json::Null])),
            ("c", Json::str("x")),
        ]);
        assert_eq!(v.to_string_compact(), r#"{"a":1,"b":[true,null],"c":"x"}"#);
    }

    #[test]
    fn escapes_control_and_quote_characters() {
        let v = Json::str("q\"\\\n\u{1}\u{2028}中");
        assert_eq!(v.to_string_compact(), "\"q\\\"\\\\\\n\\u0001\\u2028中\"");
    }

    #[test]
    fn max_u64() {
        assert_eq!(
            Json::UInt(u64::MAX).to_string_compact(),
            "18446744073709551615"
        );
    }
}
