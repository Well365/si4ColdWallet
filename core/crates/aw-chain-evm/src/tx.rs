//! 交易解析（待签）与拼装（已签）。
//!
//! 待签数据就是被哈希的字节：签名哈希 = Keccak-256(待签数据)。所以这里的严格解析
//! 同时保证了"显示给用户的字段"与"实际被签名的字节"一一对应。
//!
//! - 旧式交易（数据类型 1）：EIP-155 未签形式 `rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])`；
//!   没有 chainId 的 6 字段旧格式可跨链重放，拒签
//! - 类型化交易（数据类型 4）：`0x01 ‖ rlp(EIP-2930)`、`0x02 ‖ rlp(EIP-1559)`；
//!   `0x04`（EIP-7702 授权）默认拒签；其他类型（如 blob）不支持

use crate::rlp::{self, Node};
use crate::uint::U256;
use crate::EvmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    Legacy,
    AccessList,
    DynamicFee,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTx {
    pub kind: TxKind,
    pub chain_id: u64,
    pub nonce: u64,
    /// 旧式 / EIP-2930：gasPrice；EIP-1559：maxFeePerGas
    pub gas_price: U256,
    /// 仅 EIP-1559：maxPriorityFeePerGas
    pub max_priority_fee: Option<U256>,
    pub gas_limit: u64,
    /// None = 部署合约
    pub to: Option<[u8; 20]>,
    pub value: U256,
    pub data: Vec<u8>,
    /// 访问列表条目数（EIP-2930 / 1559）
    pub access_list_entries: usize,
}

impl UnsignedTx {
    /// 最高手续费 = gasLimit × gasPrice（或 maxFeePerGas）
    pub fn max_fee(&self) -> Result<U256, EvmError> {
        self.gas_price
            .checked_mul(U256::from_u64(self.gas_limit))
            .ok_or(EvmError::Overflow)
    }
}

fn address_field(n: &Node<'_>) -> Result<Option<[u8; 20]>, EvmError> {
    let b = n.bytes()?;
    match b.len() {
        0 => Ok(None),
        20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(b);
            Ok(Some(a))
        }
        _ => Err(EvmError::Parse),
    }
}

fn access_list(n: &Node<'_>) -> Result<usize, EvmError> {
    let entries = n.list()?;
    for e in entries {
        match e.list()? {
            [addr, keys] => {
                if addr.bytes()?.len() != 20 {
                    return Err(EvmError::Parse);
                }
                for k in keys.list()? {
                    if k.bytes()?.len() != 32 {
                        return Err(EvmError::Parse);
                    }
                }
            }
            _ => return Err(EvmError::Parse),
        }
    }
    Ok(entries.len())
}

/// 解析未签的 EIP-155 旧式交易
pub fn parse_legacy(bytes: &[u8]) -> Result<UnsignedTx, EvmError> {
    let root = rlp::decode(bytes)?;
    match root.list()? {
        [nonce, gas_price, gas, to, value, data, chain_id, r, s] => {
            let chain_id = chain_id.u64()?;
            if chain_id == 0 || !r.bytes()?.is_empty() || !s.bytes()?.is_empty() {
                return Err(EvmError::Parse);
            }
            // EIP-155 的 v = chainId × 2 + 36 必须放得进 u64，否则签完无法写出签名
            v_value(VStyle::Eip155(chain_id), 1)?;
            Ok(UnsignedTx {
                kind: TxKind::Legacy,
                chain_id,
                nonce: nonce.u64()?,
                gas_price: gas_price.uint()?,
                max_priority_fee: None,
                gas_limit: gas.u64()?,
                to: address_field(to)?,
                value: value.uint()?,
                data: data.bytes()?.to_vec(),
                access_list_entries: 0,
            })
        }
        [_, _, _, _, _, _] => Err(EvmError::NoReplayProtection),
        _ => Err(EvmError::Parse),
    }
}

/// 解析未签的类型化交易（类型字节 + RLP 列表）
pub fn parse_typed(bytes: &[u8]) -> Result<UnsignedTx, EvmError> {
    let (&ty, payload) = bytes.split_first().ok_or(EvmError::Parse)?;
    match ty {
        0x01 | 0x02 => {}
        0x04 => return Err(EvmError::Eip7702),
        0x03 | 0x05..=0x7f => return Err(EvmError::Unsupported),
        _ => return Err(EvmError::Parse),
    }
    let root = rlp::decode(payload)?;
    match (ty, root.list()?) {
        (0x01, [chain_id, nonce, gas_price, gas, to, value, data, al]) => Ok(UnsignedTx {
            kind: TxKind::AccessList,
            chain_id: nonzero(chain_id.u64()?)?,
            nonce: nonce.u64()?,
            gas_price: gas_price.uint()?,
            max_priority_fee: None,
            gas_limit: gas.u64()?,
            to: address_field(to)?,
            value: value.uint()?,
            data: data.bytes()?.to_vec(),
            access_list_entries: access_list(al)?,
        }),
        (0x02, [chain_id, nonce, prio, max_fee, gas, to, value, data, al]) => {
            let prio = prio.uint()?;
            let max_fee = max_fee.uint()?;
            if prio > max_fee {
                return Err(EvmError::Parse); // 节点也会拒绝
            }
            Ok(UnsignedTx {
                kind: TxKind::DynamicFee,
                chain_id: nonzero(chain_id.u64()?)?,
                nonce: nonce.u64()?,
                gas_price: max_fee,
                max_priority_fee: Some(prio),
                gas_limit: gas.u64()?,
                to: address_field(to)?,
                value: value.uint()?,
                data: data.bytes()?.to_vec(),
                access_list_entries: access_list(al)?,
            })
        }
        _ => Err(EvmError::Parse),
    }
}

fn nonzero(id: u64) -> Result<u64, EvmError> {
    if id == 0 {
        Err(EvmError::Parse)
    } else {
        Ok(id)
    }
}

/// 一个可恢复的 secp256k1 签名
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthSig {
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// 0 或 1
    pub recid: u8,
}

/// 签名在 `eth-signature` 中的写法：r ‖ s ‖ v
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VStyle {
    /// 旧式交易：v = chainId × 2 + 35 + recid（EIP-155），最短大端字节
    Eip155(u64),
    /// 类型化交易：v = recid（yParity）
    Parity,
    /// 消息签名（EIP-191 / EIP-712）：v = 27 + recid
    Legacy27,
}

fn v_value(style: VStyle, recid: u8) -> Result<U256, EvmError> {
    let r = u64::from(recid);
    match style {
        VStyle::Eip155(chain_id) => chain_id
            .checked_mul(2)
            .and_then(|x| x.checked_add(35 + r))
            .map(U256::from_u64)
            .ok_or(EvmError::Overflow),
        VStyle::Parity => Ok(U256::from_u64(r)),
        VStyle::Legacy27 => Ok(U256::from_u64(27 + r)),
    }
}

pub fn encode_sig(sig: &EthSig, style: VStyle) -> Result<Vec<u8>, EvmError> {
    let mut out = Vec::with_capacity(72);
    out.extend_from_slice(&sig.r);
    out.extend_from_slice(&sig.s);
    let v = v_value(style, sig.recid)?.to_minimal_be();
    if v.is_empty() {
        out.push(0); // recid 0 的 yParity 写成一个 0 字节
    } else {
        out.extend_from_slice(&v);
    }
    Ok(out)
}

pub fn decode_sig(bytes: &[u8], style: VStyle) -> Result<EthSig, EvmError> {
    if bytes.len() < 65 || bytes.len() > 72 {
        return Err(EvmError::BadSignature);
    }
    let (r, rest) = bytes.split_at(32);
    let (s, v) = rest.split_at(32);
    for recid in 0..2u8 {
        let mut want = v_value(style, recid)?.to_minimal_be();
        if want.is_empty() {
            want.push(0);
        }
        if v == want.as_slice() {
            let mut sig = EthSig {
                r: [0; 32],
                s: [0; 32],
                recid,
            };
            sig.r.copy_from_slice(r);
            sig.s.copy_from_slice(s);
            return Ok(sig);
        }
    }
    Err(EvmError::BadSignature)
}

/// 由待签交易与签名拼出可广播的原始交易
pub fn assemble(
    sign_data: &[u8],
    typed: bool,
    chain_id: u64,
    sig: &EthSig,
) -> Result<Vec<u8>, EvmError> {
    let mut items = Vec::new();
    let push_sig = |items: &mut Vec<u8>, v: U256| {
        rlp::encode_uint(items, v);
        rlp::encode_uint(items, U256::from_be_bytes(&sig.r));
        rlp::encode_uint(items, U256::from_be_bytes(&sig.s));
    };
    if typed {
        let (&ty, payload) = sign_data.split_first().ok_or(EvmError::Parse)?;
        let root = rlp::decode(payload)?;
        for n in root.list()? {
            items.extend_from_slice(n.raw);
        }
        push_sig(&mut items, v_value(VStyle::Parity, sig.recid)?);
        let mut out = vec![ty];
        rlp::encode_list(&mut out, &items);
        Ok(out)
    } else {
        let root = rlp::decode(sign_data)?;
        let fields = root.list()?;
        for n in fields.get(..6).ok_or(EvmError::Parse)? {
            items.extend_from_slice(n.raw);
        }
        push_sig(&mut items, v_value(VStyle::Eip155(chain_id), sig.recid)?);
        let mut out = Vec::new();
        rlp::encode_list(&mut out, &items);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::keccak::keccak256;
    use aw_common::hex;

    /// EIP-155 规范中的示例交易（nonce 9、20 gwei、21000 gas、转 1 ETH，chainId 1）
    pub(crate) const EIP155_UNSIGNED: &str = "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";
    const EIP155_HASH: &str = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
    const EIP155_SIGNED: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

    #[test]
    fn eip155_spec_example() {
        let raw = hex::decode(EIP155_UNSIGNED).unwrap();
        let tx = parse_legacy(&raw).unwrap();
        assert_eq!((tx.chain_id, tx.nonce, tx.gas_limit), (1, 9, 21000));
        assert_eq!(tx.gas_price, U256::from_u64(20_000_000_000));
        assert_eq!(tx.value.format_units(18), "1");
        assert_eq!(tx.to, Some([0x35; 20]));
        assert_eq!(hex::encode(&keccak256(&raw)), EIP155_HASH);
        // 规范给出的签名：v = 37（chainId 1，recid 0）
        let signed = hex::decode(EIP155_SIGNED).unwrap();
        let mut sig = EthSig {
            r: [0; 32],
            s: [0; 32],
            recid: 0,
        };
        sig.r
            .copy_from_slice(&signed[signed.len() - 65..signed.len() - 33]);
        sig.s.copy_from_slice(&signed[signed.len() - 32..]);
        assert_eq!(assemble(&raw, false, 1, &sig).unwrap(), signed);
        let wire = encode_sig(&sig, VStyle::Eip155(1)).unwrap();
        assert_eq!(wire.len(), 65);
        assert_eq!(wire[64], 37);
        assert_eq!(decode_sig(&wire, VStyle::Eip155(1)).unwrap(), sig);
        assert!(decode_sig(&wire, VStyle::Eip155(56)).is_err());
    }

    #[test]
    fn rejects_dangerous_or_malformed() {
        // 6 字段旧格式：无重放保护
        let mut items = vec![];
        for _ in 0..6 {
            rlp::encode_bytes(&mut items, &[]);
        }
        let mut l = vec![];
        rlp::encode_list(&mut l, &items);
        assert_eq!(parse_legacy(&l), Err(EvmError::NoReplayProtection));
        assert_eq!(parse_typed(&[0x04, 0xc0]), Err(EvmError::Eip7702));
        assert_eq!(parse_typed(&[0x03, 0xc0]), Err(EvmError::Unsupported));
        assert_eq!(parse_typed(&[0xc0]), Err(EvmError::Parse));
        // 多余字节
        let mut raw = hex::decode(EIP155_UNSIGNED).unwrap();
        raw.push(0);
        assert!(parse_legacy(&raw).is_err());
    }

    #[test]
    fn eip1559_roundtrip_and_v_styles() {
        // 手工构造：chainId 11155111、nonce 0、prio 1 gwei、max 30 gwei、21000、to 0x11…、0.01 ETH
        let mut f = vec![];
        rlp::encode_uint(&mut f, U256::from_u64(11_155_111));
        rlp::encode_uint(&mut f, U256::ZERO);
        rlp::encode_uint(&mut f, U256::from_u64(1_000_000_000));
        rlp::encode_uint(&mut f, U256::from_u64(30_000_000_000));
        rlp::encode_uint(&mut f, U256::from_u64(21_000));
        rlp::encode_bytes(&mut f, &[0x11; 20]);
        rlp::encode_uint(&mut f, U256::from_u64(10_000_000_000_000_000));
        rlp::encode_bytes(&mut f, &[]);
        rlp::encode_list(&mut f, &[]);
        let mut raw = vec![0x02];
        rlp::encode_list(&mut raw, &f);
        let tx = parse_typed(&raw).unwrap();
        assert_eq!(tx.kind, TxKind::DynamicFee);
        assert_eq!(tx.max_fee().unwrap(), U256::from_u64(630_000_000_000_000));
        let sig = EthSig {
            r: [1; 32],
            s: [2; 32],
            recid: 1,
        };
        let signed = assemble(&raw, true, tx.chain_id, &sig).unwrap();
        assert_eq!(signed[0], 0x02);
        let back = rlp::decode(&signed[1..]).unwrap();
        assert_eq!(back.list().unwrap().len(), 12);
        assert_eq!(back.list().unwrap()[9].bytes().unwrap(), &[1]);
        assert_eq!(encode_sig(&sig, VStyle::Parity).unwrap()[64], 1);
        assert_eq!(
            encode_sig(&EthSig { recid: 0, ..sig }, VStyle::Parity).unwrap()[64],
            0
        );
        assert_eq!(encode_sig(&sig, VStyle::Legacy27).unwrap()[64], 28);
        // Sepolia 的 EIP-155 v 需要多字节
        assert_eq!(
            encode_sig(&sig, VStyle::Eip155(11_155_111)).unwrap().len(),
            68
        );
        // maxPriorityFee > maxFee：拒绝
        let mut g = vec![];
        rlp::encode_uint(&mut g, U256::from_u64(1));
        rlp::encode_uint(&mut g, U256::ZERO);
        rlp::encode_uint(&mut g, U256::from_u64(5));
        rlp::encode_uint(&mut g, U256::from_u64(4));
        for _ in 0..3 {
            rlp::encode_uint(&mut g, U256::ZERO);
        }
        rlp::encode_bytes(&mut g, &[]);
        rlp::encode_list(&mut g, &[]);
        let mut bad = vec![0x02];
        rlp::encode_list(&mut bad, &g);
        assert_eq!(parse_typed(&bad), Err(EvmError::Parse));
    }
}
