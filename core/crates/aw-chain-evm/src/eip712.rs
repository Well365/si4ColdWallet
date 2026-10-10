//! EIP-712 结构化数据（`eth_signTypedData_v4`）：严格解析 + 规范哈希。
//!
//! 比 MetaMask 等实现更严：
//! - 顶层只允许 `types`、`primaryType`、`domain`、`message` 四个键；JSON 不允许重复键（解析器保证）
//! - 每个结构体必须**正好**包含声明的字段：多一个（会显示却不被签名）或少一个（被当作 0 签名）都拒绝
//! - 数值必须在声明的位宽内；地址若大小写混合必须符合 EIP-55；`bytesN` 长度必须正好为 N
//! - 必须声明 `EIP712Domain`，且其字段只能是规范中的 name / version / chainId / verifyingContract / salt
//!
//! 签名哈希 = Keccak-256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct(primaryType, message))。

use crate::keccak::{keccak256, Keccak256};
use crate::uint::U256;
use crate::{parse_address, EvmError};
use aw_common::json_read::{self, Value};

/// 消息中可显示的叶子值上限：超过就拒签，避免"太长看不完"变成盲签
pub const MAX_LEAVES: usize = 256;
const MAX_ARRAY: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedData {
    /// 按 JSON 中出现的顺序
    pub types: Vec<(String, Vec<Field>)>,
    pub primary: String,
    pub domain: Value,
    pub message: Value,
}

/// 显示用的叶子：路径（如 `details.amount`、`items[0]`）、Solidity 类型、格式化后的值
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub path: String,
    pub ty: String,
    pub value: LeafValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafValue {
    Address([u8; 20]),
    Uint(U256),
    /// 有符号整数：(是否为负, 绝对值)
    Int(bool, U256),
    Bool(bool),
    Bytes(Vec<u8>),
    Str(String),
}

fn is_ident(s: &str) -> bool {
    let mut cs = s.chars();
    matches!(cs.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// 基本类型的解析结果
enum Base {
    Address,
    Bool,
    Str,
    Bytes,
    FixedBytes(usize),
    Uint(u32),
    Int(u32),
}

fn width(s: &str) -> Option<u32> {
    if s.starts_with('0') {
        return None;
    }
    let n: u32 = s.parse().ok()?;
    (n.is_multiple_of(8) && (8..=256).contains(&n)).then_some(n)
}

fn base(ty: &str) -> Option<Base> {
    Some(match ty {
        "address" => Base::Address,
        "bool" => Base::Bool,
        "string" => Base::Str,
        "bytes" => Base::Bytes,
        _ => {
            if let Some(n) = ty.strip_prefix("bytes") {
                let k: usize = n.parse().ok().filter(|_| !n.starts_with('0'))?;
                if !(1..=32).contains(&k) {
                    return None;
                }
                Base::FixedBytes(k)
            } else if let Some(n) = ty.strip_prefix("uint") {
                Base::Uint(width(n)?)
            } else {
                Base::Int(width(ty.strip_prefix("int")?)?)
            }
        }
    })
}

/// 去掉最外层数组后缀：`T[3]` → (`T`, Some(3))；`T[]` → (`T`, None)
fn split_array(ty: &str) -> Option<(&str, Option<usize>)> {
    let inner = ty.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    let (elem, len) = (inner.get(..open)?, inner.get(open + 1..)?);
    if len.is_empty() {
        return Some((elem, None));
    }
    let n: usize = len
        .parse()
        .ok()
        .filter(|n| *n > 0 && !len.starts_with('0'))?;
    Some((elem, Some(n)))
}

impl TypedData {
    pub fn parse(json: &str) -> Result<Self, EvmError> {
        let root = json_read::parse(json).map_err(|_| EvmError::Parse)?;
        let Value::Object(top) = &root else {
            return Err(EvmError::Parse);
        };
        if top.len() != 4 {
            return Err(EvmError::Parse);
        }
        let Some(Value::Object(types_json)) = root.get("types") else {
            return Err(EvmError::Parse);
        };
        let mut types = Vec::new();
        for (name, fields_json) in types_json {
            if !is_ident(name) {
                return Err(EvmError::Parse);
            }
            let Value::Array(items) = fields_json else {
                return Err(EvmError::Parse);
            };
            let mut fields: Vec<Field> = Vec::new();
            for it in items {
                let (Value::Object(kv), Some(n), Some(t)) = (
                    it,
                    it.get("name").and_then(Value::as_str),
                    it.get("type").and_then(Value::as_str),
                ) else {
                    return Err(EvmError::Parse);
                };
                if kv.len() != 2 || !is_ident(n) || fields.iter().any(|f| f.name == n) {
                    return Err(EvmError::Parse);
                }
                fields.push(Field {
                    name: n.to_owned(),
                    ty: t.to_owned(),
                });
            }
            types.push((name.clone(), fields));
        }
        let primary = root
            .get("primaryType")
            .and_then(Value::as_str)
            .ok_or(EvmError::Parse)?
            .to_owned();
        let td = TypedData {
            types,
            primary,
            domain: root.get("domain").cloned().ok_or(EvmError::Parse)?,
            message: root.get("message").cloned().ok_or(EvmError::Parse)?,
        };
        td.validate()?;
        Ok(td)
    }

    fn fields(&self, name: &str) -> Option<&[Field]> {
        self.types
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, f)| f.as_slice())
    }

    /// 类型名有效：基本类型、已声明的结构体、或它们的数组
    fn type_ok(&self, ty: &str) -> bool {
        match split_array(ty) {
            Some((elem, _)) => self.type_ok(elem),
            None => base(ty).is_some() || self.fields(ty).is_some(),
        }
    }

    fn validate(&self) -> Result<(), EvmError> {
        for (name, fields) in &self.types {
            if base(name).is_some() {
                return Err(EvmError::Parse); // 结构体不能与基本类型同名
            }
            if fields.iter().any(|f| !self.type_ok(&f.ty)) {
                return Err(EvmError::Parse);
            }
        }
        let domain = self.fields("EIP712Domain").ok_or(EvmError::Parse)?;
        for f in domain {
            let want = match f.name.as_str() {
                "name" | "version" => "string",
                "chainId" => "uint256",
                "verifyingContract" => "address",
                "salt" => "bytes32",
                _ => return Err(EvmError::Parse),
            };
            if f.ty != want {
                return Err(EvmError::Parse);
            }
        }
        if self.primary == "EIP712Domain" {
            return Err(EvmError::Unsupported); // 只签域分隔符没有意义
        }
        self.fields(&self.primary).ok_or(EvmError::Parse)?;
        Ok(())
    }

    /// 结构体及其（直接或间接）引用的所有结构体
    fn deps(&self, ty: &str, out: &mut Vec<String>) {
        let mut t = ty;
        while let Some((elem, _)) = split_array(t) {
            t = elem;
        }
        if out.iter().any(|x| x == t) {
            return;
        }
        let Some(fields) = self.fields(t) else {
            return;
        };
        out.push(t.to_owned());
        for f in fields {
            self.deps(&f.ty, out);
        }
    }

    /// encodeType：主类型在前，其余依赖按名字排序
    pub fn encode_type(&self, ty: &str) -> String {
        let mut deps = Vec::new();
        self.deps(ty, &mut deps);
        let (head, mut rest): (Vec<String>, Vec<String>) = deps.into_iter().partition(|d| d == ty);
        rest.sort();
        let mut s = String::new();
        for t in head.iter().chain(rest.iter()) {
            let fields = self.fields(t).unwrap_or(&[]);
            let list: Vec<String> = fields
                .iter()
                .map(|f| format!("{} {}", f.ty, f.name))
                .collect();
            s.push_str(&format!("{t}({})", list.join(",")));
        }
        s
    }

    pub fn type_hash(&self, ty: &str) -> [u8; 32] {
        keccak256(self.encode_type(ty).as_bytes())
    }

    /// hashStruct；同时收集显示用的叶子
    fn hash_struct(
        &self,
        ty: &str,
        v: &Value,
        path: &str,
        leaves: &mut Vec<Leaf>,
    ) -> Result<[u8; 32], EvmError> {
        let fields = self.fields(ty).ok_or(EvmError::Parse)?;
        let Value::Object(kv) = v else {
            return Err(EvmError::Parse);
        };
        if kv.len() != fields.len() {
            return Err(EvmError::Parse); // 多出或缺少字段
        }
        let mut h = Keccak256::new();
        h.update(&self.type_hash(ty));
        for f in fields {
            let val = v.get(&f.name).ok_or(EvmError::Parse)?;
            let p = if path.is_empty() {
                f.name.clone()
            } else {
                format!("{path}.{}", f.name)
            };
            h.update(&self.encode_value(&f.ty, val, &p, leaves)?);
        }
        Ok(h.finalize())
    }

    fn encode_value(
        &self,
        ty: &str,
        v: &Value,
        path: &str,
        leaves: &mut Vec<Leaf>,
    ) -> Result<[u8; 32], EvmError> {
        if let Some((elem, fixed)) = split_array(ty) {
            let Value::Array(items) = v else {
                return Err(EvmError::Parse);
            };
            if items.len() > MAX_ARRAY || fixed.is_some_and(|n| n != items.len()) {
                return Err(EvmError::Parse);
            }
            let mut h = Keccak256::new();
            for (i, it) in items.iter().enumerate() {
                h.update(&self.encode_value(elem, it, &format!("{path}[{i}]"), leaves)?);
            }
            return Ok(h.finalize());
        }
        if self.fields(ty).is_some() {
            return self.hash_struct(ty, v, path, leaves);
        }
        let (word, value) = encode_atomic(base(ty).ok_or(EvmError::Parse)?, v)?;
        leaves.push(Leaf {
            path: path.to_owned(),
            ty: ty.to_owned(),
            value,
        });
        if leaves.len() > MAX_LEAVES {
            return Err(EvmError::Unsupported);
        }
        Ok(word)
    }

    /// (签名哈希, 域分隔符, 消息结构哈希, 域叶子, 消息叶子)
    pub fn digest(&self) -> Result<Digest, EvmError> {
        let mut domain_leaves = Vec::new();
        let domain = self.hash_struct("EIP712Domain", &self.domain, "", &mut domain_leaves)?;
        let mut leaves = Vec::new();
        let message = self.hash_struct(&self.primary, &self.message, "", &mut leaves)?;
        let mut h = Keccak256::new();
        h.update(&[0x19, 0x01]);
        h.update(&domain);
        h.update(&message);
        Ok(Digest {
            hash: h.finalize(),
            domain_separator: domain,
            message_hash: message,
            domain_leaves,
            leaves,
        })
    }
}

pub struct Digest {
    pub hash: [u8; 32],
    pub domain_separator: [u8; 32],
    pub message_hash: [u8; 32],
    pub domain_leaves: Vec<Leaf>,
    pub leaves: Vec<Leaf>,
}

/// JSON 中的整数：数字字面量（不得有小数点或指数）、十进制字符串、或 "0x" 十六进制字符串。返回 (是否为负, 绝对值)
fn integer(v: &Value) -> Result<(bool, U256), EvmError> {
    let text = match v {
        Value::Number(n) => n.as_str(),
        Value::Str(s) => s.as_str(),
        _ => return Err(EvmError::Parse),
    };
    let (neg, digits) = match text.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, text),
    };
    let mag = if digits.starts_with("0x") || digits.starts_with("0X") {
        U256::from_hex_lenient(digits)
    } else {
        U256::parse_units(digits, 0).filter(|_| !digits.contains('.'))
    }
    .ok_or(EvmError::Parse)?;
    Ok((neg && !mag.is_zero(), mag))
}

fn hex_bytes(v: &Value) -> Result<Vec<u8>, EvmError> {
    let s = v.as_str().ok_or(EvmError::Parse)?;
    let h = s.strip_prefix("0x").ok_or(EvmError::Parse)?;
    aw_common::hex::decode(&h.to_ascii_lowercase()).ok_or(EvmError::Parse)
}

fn encode_atomic(b: Base, v: &Value) -> Result<([u8; 32], LeafValue), EvmError> {
    let mut w = [0u8; 32];
    match b {
        Base::Address => {
            let a = parse_address(v.as_str().ok_or(EvmError::Parse)?).ok_or(EvmError::Parse)?;
            w.get_mut(12..).ok_or(EvmError::Parse)?.copy_from_slice(&a);
            Ok((w, LeafValue::Address(a)))
        }
        Base::Bool => match v {
            Value::Bool(x) => {
                if let Some(last) = w.last_mut() {
                    *last = u8::from(*x);
                }
                Ok((w, LeafValue::Bool(*x)))
            }
            _ => Err(EvmError::Parse),
        },
        Base::Str => {
            let s = v.as_str().ok_or(EvmError::Parse)?;
            Ok((keccak256(s.as_bytes()), LeafValue::Str(s.to_owned())))
        }
        Base::Bytes => {
            let b = hex_bytes(v)?;
            Ok((keccak256(&b), LeafValue::Bytes(b)))
        }
        Base::FixedBytes(n) => {
            let b = hex_bytes(v)?;
            if b.len() != n {
                return Err(EvmError::Parse);
            }
            w.get_mut(..n).ok_or(EvmError::Parse)?.copy_from_slice(&b);
            Ok((w, LeafValue::Bytes(b)))
        }
        Base::Uint(bits) => {
            let (neg, m) = integer(v)?;
            if neg || (bits < 256 && U256::bit(bits).is_some_and(|lim| m >= lim)) {
                return Err(EvmError::Parse);
            }
            Ok((m.to_be_bytes(), LeafValue::Uint(m)))
        }
        Base::Int(bits) => {
            let (neg, m) = integer(v)?;
            let lim = U256::bit(bits - 1).ok_or(EvmError::Parse)?;
            // 范围：-2^(bits-1) ≤ v < 2^(bits-1)
            if (!neg && m >= lim) || (neg && m > lim) {
                return Err(EvmError::Parse);
            }
            let word = if neg { m.wrapping_neg() } else { m };
            Ok((word.to_be_bytes(), LeafValue::Int(neg, m)))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use aw_common::hex;

    /// EIP-712 规范自带的示例（Mail / Person）
    pub(crate) const MAIL: &str = r#"{
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
        "Mail": [
          {"name": "from", "type": "Person"},
          {"name": "to", "type": "Person"},
          {"name": "contents", "type": "string"}
        ]
      },
      "primaryType": "Mail",
      "domain": {"name": "Ether Mail", "version": "1", "chainId": 1,
                 "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
      "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!"
      }
    }"#;

    #[test]
    fn eip712_spec_example() {
        let td = TypedData::parse(MAIL).unwrap();
        assert_eq!(
            td.encode_type("Mail"),
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
        assert_eq!(
            hex::encode(&td.type_hash("Mail")),
            "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
        );
        let d = td.digest().unwrap();
        assert_eq!(
            hex::encode(&d.domain_separator),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        );
        assert_eq!(
            hex::encode(&d.message_hash),
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        );
        assert_eq!(
            hex::encode(&d.hash),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
        assert_eq!(d.leaves.len(), 5);
        assert_eq!(d.leaves[0].path, "from.name");
    }

    /// 规范示例的签名（私钥 = keccak256("cow")）：v = 28，r、s 见 EIP-712 Example.js
    #[test]
    fn eip712_spec_signature() {
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&keccak256(b"cow")).unwrap();
        let d = TypedData::parse(MAIL).unwrap().digest().unwrap();
        let (recid, rs) = secp
            .sign_ecdsa_recoverable(&Message::from_digest(d.hash), &sk)
            .serialize_compact();
        assert_eq!(
            hex::encode(&rs[..32]),
            "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d"
        );
        assert_eq!(
            hex::encode(&rs[32..]),
            "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562"
        );
        assert_eq!(27 + recid.to_i32(), 28);
    }

    fn with_message(msg: &str) -> String {
        MAIL.replace(r#""contents": "Hello, Bob!""#, msg)
    }

    #[test]
    fn strictness() {
        // 多出的字段（会显示但不被签名）
        assert!(
            TypedData::parse(&with_message(r#""contents": "x", "extra": "y""#))
                .unwrap()
                .digest()
                .is_err()
        );
        // 缺少字段、字段名不符
        let missing = MAIL.replace("},\n        \"contents\": \"Hello, Bob!\"", "}");
        assert_ne!(missing, MAIL);
        assert!(TypedData::parse(&missing).unwrap().digest().is_err());
        assert!(TypedData::parse(&with_message(r#""content": "x""#))
            .unwrap()
            .digest()
            .is_err());
        // 地址校验和错误
        assert!(TypedData::parse(&MAIL.replace(
            "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD82B"
        ))
        .unwrap()
        .digest()
        .is_err());
        // 重复键、顶层多余键、未声明的类型、主类型是域
        assert!(TypedData::parse(&MAIL.replace(
            r#""primaryType": "Mail","#,
            r#""primaryType": "Mail", "primaryType": "Mail","#
        ))
        .is_err());
        assert!(TypedData::parse(&MAIL.replace(
            r#""primaryType": "Mail","#,
            r#""primaryType": "Mail", "x": 1,"#
        ))
        .is_err());
        assert!(TypedData::parse(&MAIL.replace(
            r#"{"name": "to", "type": "Person"}"#,
            r#"{"name": "to", "type": "Nobody"}"#
        ))
        .is_err());
        assert_eq!(
            TypedData::parse(&MAIL.replace(
                r#""primaryType": "Mail""#,
                r#""primaryType": "EIP712Domain""#
            ))
            .map(|_| ()),
            Err(EvmError::Unsupported)
        );
        // 域里出现非规范字段
        assert!(TypedData::parse(&MAIL.replace(
            r#"{"name": "version", "type": "string"},"#,
            r#"{"name": "version", "type": "string"}, {"name": "x", "type": "uint8"},"#
        ))
        .is_err());
        // 链 ID 写成小数
        assert!(
            TypedData::parse(&MAIL.replace(r#""chainId": 1,"#, r#""chainId": 1.0,"#))
                .unwrap()
                .digest()
                .is_err()
        );
    }

    /// 与独立 Python 实现（tools/testvectors/eip712_vectors.py）逐个比对：规范示例、MetaMask v4 数组示例、
    /// 全部基本类型与负数、Permit、Permit2、递归类型
    #[test]
    fn matches_independent_python_implementation() {
        let data = include_str!("../testdata/eip712_vectors.txt");
        let mut n = 0;
        let mut lines = data.lines().filter(|l| !l.starts_with('#'));
        while let Some(h) = lines.next() {
            let expect = h.strip_prefix("=== ").unwrap();
            let json = lines.next().unwrap();
            let d = TypedData::parse(json).unwrap().digest().unwrap();
            assert_eq!(hex::encode(&d.hash), expect, "用例 {n}");
            n += 1;
        }
        assert_eq!(n, 6);
    }

    #[test]
    fn integer_ranges_and_bytes() {
        let td = |ty: &str, val: &str| {
            let j = format!(
                r#"{{"types": {{"EIP712Domain": [], "T": [{{"name": "v", "type": "{ty}"}}]}},
                   "primaryType": "T", "domain": {{}}, "message": {{"v": {val}}}}}"#
            );
            TypedData::parse(&j).and_then(|t| t.digest().map(|d| d.leaves))
        };
        assert!(td("uint8", "255").is_ok());
        assert!(td("uint8", "256").is_err());
        assert!(td("uint8", "-1").is_err());
        assert!(td("int8", "-128").is_ok());
        assert!(td("int8", "-129").is_err());
        assert!(td("int8", "127").is_ok());
        assert!(td("int8", "128").is_err());
        assert!(td("uint256", "\"0x00ff\"").is_ok());
        assert!(td("uint256", "\"123456789012345678901234567890\"").is_ok());
        assert!(td("uint7", "1").is_err());
        assert!(td("bytes4", "\"0x01020304\"").is_ok());
        assert!(td("bytes4", "\"0x010203\"").is_err());
        assert!(td("bytes33", "\"0x00\"").is_err());
        assert!(td("bool", "1").is_err());
        assert!(td("uint256[2]", "[1, 2]").is_ok());
        assert!(td("uint256[2]", "[1]").is_err());
        assert!(td("string[]", "[\"a\", \"b\"]").is_ok());
    }
}
