//! 严格 JSON 解析（RFC 8259），供 EIP-712 结构化数据使用（决策 D6：不用 serde）。
//!
//! 比常见解析器更严：拒绝重复键（不同解析器对重复键取值不同，可被用来让"显示的"与"签名的"不一致）、
//! 拒绝孤立的 UTF-16 代理项、拒绝控制字符、限制嵌套深度与条目数。数字保留原文，由调用方按类型解释。

const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// 数字的原文（已按 RFC 8259 语法校验）
    Number(String),
    Str(String),
    Array(Vec<Value>),
    /// 保持原顺序；键唯一
    Object(Vec<(String, Value)>),
}

impl Value {
    /// 对象中的字段
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// 语法错误（位置为字节偏移）
    Syntax(usize),
    /// 对象中出现重复键
    DuplicateKey,
    /// 嵌套过深或条目过多
    TooLarge,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    items: usize,
}

pub fn parse(input: &str) -> Result<Value, JsonError> {
    let mut p = Parser {
        s: input.as_bytes(),
        i: 0,
        items: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(JsonError::Syntax(p.i));
    }
    Ok(v)
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn err<T>(&self) -> Result<T, JsonError> {
        Err(JsonError::Syntax(self.i))
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, lit: &[u8]) -> Result<(), JsonError> {
        if self.s.get(self.i..self.i + lit.len()) == Some(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            self.err()
        }
    }

    fn count(&mut self) -> Result<(), JsonError> {
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(JsonError::TooLarge);
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooLarge);
        }
        self.count()?;
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.expect(b"true").map(|()| Value::Bool(true)),
            Some(b'f') => self.expect(b"false").map(|()| Value::Bool(false)),
            Some(b'n') => self.expect(b"null").map(|()| Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => self.err(),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.i += 1;
        let mut fields: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return self.err();
            }
            let k = self.string()?;
            if fields.iter().any(|(x, _)| *x == k) {
                return Err(JsonError::DuplicateKey);
            }
            self.ws();
            self.expect(b":")?;
            self.ws();
            let v = self.value(depth + 1)?;
            fields.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return self.err(),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return self.err(),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let h = self
            .s
            .get(self.i..self.i + 4)
            .ok_or(JsonError::Syntax(self.i))?;
        let t = core::str::from_utf8(h).map_err(|_| JsonError::Syntax(self.i))?;
        if !t.bytes().all(|c| c.is_ascii_hexdigit()) {
            return self.err();
        }
        self.i += 4;
        u32::from_str_radix(t, 16).map_err(|_| JsonError::Syntax(self.i))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.i += 1; // 开头的引号
        let mut out = String::new();
        loop {
            let start = self.i;
            // 快速拷贝不需要转义的连续字节（输入本身是合法 UTF-8）
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            let chunk = self.s.get(start..self.i).ok_or(JsonError::Syntax(start))?;
            out.push_str(core::str::from_utf8(chunk).map_err(|_| JsonError::Syntax(start))?);
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let esc = self.peek().ok_or(JsonError::Syntax(self.i))?;
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = match hi {
                                0xD800..=0xDBFF => {
                                    self.expect(b"\\u")?;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return self.err(); // 孤立的高代理项
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                }
                                0xDC00..=0xDFFF => return self.err(), // 孤立的低代理项
                                _ => hi,
                            };
                            out.push(char::from_u32(cp).ok_or(JsonError::Syntax(self.i))?);
                        }
                        _ => return self.err(),
                    }
                }
                _ => return self.err(), // 字符串未结束，或含控制字符
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1, // 不允许前导零
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return self.err(),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return self.err();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return self.err();
            }
        }
        let text = self.s.get(start..self.i).ok_or(JsonError::Syntax(start))?;
        Ok(Value::Number(
            core::str::from_utf8(text)
                .map_err(|_| JsonError::Syntax(start))?
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    #[test]
    fn parses_valid_documents() {
        let v = parse(r#" {"a": [1, -2, 3.5e+2, true, false, null], "b": "x\u00e9\ud83d\ude00\n\"", "c": {}} "#).unwrap();
        assert_eq!(v.get("b").and_then(Value::as_str), Some("xé😀\n\""));
        match v.get("a") {
            Some(Value::Array(items)) => {
                assert_eq!(items.len(), 6);
                assert_eq!(items[2], Value::Number("3.5e+2".to_owned()));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(parse("[]").unwrap(), Value::Array(vec![]));
        assert_eq!(parse("\"中文\"").unwrap(), Value::Str("中文".to_owned()));
    }

    #[test]
    fn rejects_invalid_or_ambiguous() {
        for bad in [
            r#"{"a":1,"a":2}"#, // 重复键
            r#"{"a":1,}"#,      // 结尾逗号
            "[1,]",
            "01", // 前导零
            "1.",
            ".5",
            "+1",
            "NaN",
            "\"\\ud800\"", // 孤立代理项
            "\"\\udc00\"",
            "\"a\u{1}b\"", // 控制字符
            "\"\\x41\"",   // 非法转义
            "[1] [2]",     // 多余内容
            "{'a':1}",
            "// c\n{}",
            "\"abc",
        ] {
            assert!(parse(bad).is_err(), "应拒绝 {bad:?}");
        }
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        assert_eq!(parse(&deep), Err(JsonError::TooLarge));
    }
}
