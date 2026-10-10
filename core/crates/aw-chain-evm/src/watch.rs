//! 观察机（feature `watch`）：构造 EIP-1559 交易与签名请求；核对签名机返回的签名，拼出可广播交易。
//!
//! 观察机不持有私钥，同样不完全信任签名机：签名必须对应自己发出的请求（请求号一致），
//! 能恢复出本账户该地址，且 s 为低值（EIP-2，否则节点拒收）。

use crate::eip712::TypedData;
use crate::keccak::keccak256;
use crate::message::personal_hash;
use crate::request::{DataType, SignRequest, Signature};
use crate::rlp;
use crate::tx::{assemble, decode_sig, parse_legacy, parse_typed, VStyle};
use crate::uint::U256;
use crate::{address_of, Account, EvmError};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature as EcdsaSig};
use bitcoin::secp256k1::{Message, Secp256k1, Verification};

/// 一笔 EIP-1559 交易的全部字段
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: U256,
    pub max_fee: U256,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: U256,
    pub data: Vec<u8>,
}

/// 未签 EIP-1559 交易：`0x02 ‖ rlp([...])`（访问列表为空）
pub fn build_eip1559(t: &Eip1559) -> Result<Vec<u8>, EvmError> {
    if t.chain_id == 0 || t.max_priority_fee > t.max_fee {
        return Err(EvmError::Parse);
    }
    let mut f = Vec::new();
    rlp::encode_uint(&mut f, U256::from_u64(t.chain_id));
    rlp::encode_uint(&mut f, U256::from_u64(t.nonce));
    rlp::encode_uint(&mut f, t.max_priority_fee);
    rlp::encode_uint(&mut f, t.max_fee);
    rlp::encode_uint(&mut f, U256::from_u64(t.gas_limit));
    rlp::encode_bytes(&mut f, &t.to);
    rlp::encode_uint(&mut f, t.value);
    rlp::encode_bytes(&mut f, &t.data);
    rlp::encode_list(&mut f, &[]);
    let mut out = vec![0x02];
    rlp::encode_list(&mut out, &f);
    Ok(out)
}

/// 构造前的余额核对结果（决策 D35）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Funds {
    Enough,
    /// 原生币不够付"金额 + 最高手续费"（代币转账时只算手续费）
    NativeShort,
    /// 代币余额不够
    TokenShort,
}

/// 原生币余额 ≥ 转出金额（原生币转账时）+ gas 上限 × 最高单价；代币转账还要代币余额 ≥ 数量。
/// 节点给的余额不可信：这里只用来提前提示，签名机仍会独立显示"总计最多扣除"。
pub fn check_funds(
    native: U256,
    token: Option<U256>,
    value: U256,
    gas_limit: u64,
    max_fee: U256,
) -> Funds {
    let fee = max_fee.checked_mul(U256::from_u64(gas_limit));
    let need = match token {
        Some(_) => fee,
        None => fee.and_then(|f| f.checked_add(value)),
    };
    if !need.is_some_and(|n| n <= native) {
        return Funds::NativeShort;
    }
    match token {
        Some(t) if t < value => Funds::TokenShort,
        _ => Funds::Enough,
    }
}

/// ERC-20 `transfer(to, amount)` 调用数据
pub fn erc20_transfer(to: &[u8; 20], amount: U256) -> Vec<u8> {
    let mut d = vec![0xa9, 0x05, 0x9c, 0xbb];
    d.extend_from_slice(&[0u8; 12]);
    d.extend_from_slice(to);
    d.extend_from_slice(&amount.to_be_bytes());
    d
}

/// 为地址 #index 生成签名请求
pub fn build_request<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    index: u32,
    sign_data: Vec<u8>,
    data_type: DataType,
    chain_id: Option<u64>,
    request_id: [u8; 16],
) -> Result<SignRequest, EvmError> {
    Ok(SignRequest {
        request_id: Some(request_id),
        sign_data,
        data_type,
        chain_id,
        path: account.keypath(index),
        address: Some(account.address(secp, index)?),
        origin: Some("airgap-wallet watcher".to_owned()),
    })
}

/// 核对签名并拼装：交易返回可广播的原始交易字节；消息返回 65 字节签名
pub fn finalize<C: Verification>(
    secp: &Secp256k1<C>,
    account: &Account,
    req: &SignRequest,
    sig: &Signature,
) -> Result<Vec<u8>, EvmError> {
    if req.request_id.is_none() || sig.request_id != req.request_id {
        return Err(EvmError::RequestMismatch);
    }
    let index = account
        .match_path(&req.path)
        .ok_or(EvmError::PathMismatch)?;
    let expected = account.address(secp, index)?;
    let (hash, style, chain_id) = match req.data_type {
        DataType::LegacyTx => {
            let tx = parse_legacy(&req.sign_data)?;
            (
                keccak256(&req.sign_data),
                VStyle::Eip155(tx.chain_id),
                tx.chain_id,
            )
        }
        DataType::TypedTx => {
            let tx = parse_typed(&req.sign_data)?;
            (keccak256(&req.sign_data), VStyle::Parity, tx.chain_id)
        }
        DataType::PersonalMessage => (personal_hash(&req.sign_data), VStyle::Legacy27, 0),
        DataType::TypedData => {
            let json = core::str::from_utf8(&req.sign_data).map_err(|_| EvmError::Parse)?;
            (TypedData::parse(json)?.digest()?.hash, VStyle::Legacy27, 0)
        }
    };
    let es = decode_sig(&sig.signature, style)?;
    let mut compact = [0u8; 64];
    let (r_half, s_half) = compact.split_at_mut(32);
    r_half.copy_from_slice(&es.r);
    s_half.copy_from_slice(&es.s);
    // EIP-2：s 必须是低值
    let plain = EcdsaSig::from_compact(&compact).map_err(|_| EvmError::BadSignature)?;
    let mut normalized = plain;
    normalized.normalize_s();
    if normalized != plain {
        return Err(EvmError::BadSignature);
    }
    let recid = RecoveryId::from_i32(i32::from(es.recid)).map_err(|_| EvmError::BadSignature)?;
    let rs =
        RecoverableSignature::from_compact(&compact, recid).map_err(|_| EvmError::BadSignature)?;
    let pk = secp
        .recover_ecdsa(&Message::from_digest(hash), &rs)
        .map_err(|_| EvmError::BadSignature)?;
    if address_of(&pk) != expected {
        return Err(EvmError::BadSignature);
    }
    let typed = match req.data_type {
        DataType::LegacyTx => false,
        DataType::TypedTx => true,
        _ => return Ok(sig.signature.clone()),
    };
    let raw = assemble(&req.sign_data, typed, chain_id, &es)?;
    check_assembled(&req.sign_data, &raw, typed)?;
    Ok(raw)
}

/// 加固（EVM 审查建议）：重新解析拼好的交易，除签名三个字段外必须与待签内容逐字段相同
fn check_assembled(sign_data: &[u8], raw: &[u8], typed: bool) -> Result<(), EvmError> {
    let (unsigned, signed, keep) = if typed {
        let (t1, u) = sign_data.split_first().ok_or(EvmError::Parse)?;
        let (t2, s) = raw.split_first().ok_or(EvmError::Parse)?;
        if t1 != t2 {
            return Err(EvmError::RequestMismatch);
        }
        let u = rlp::decode(u)?;
        let n = u.list()?.len();
        (u, rlp::decode(s)?, n)
    } else {
        (rlp::decode(sign_data)?, rlp::decode(raw)?, 6)
    };
    let (u, s) = (unsigned.list()?, signed.list()?);
    let same = s.len() == keep + 3
        && u.get(..keep)
            .zip(s.get(..keep))
            .is_some_and(|(a, b)| a.iter().zip(b).all(|(x, y)| x.raw == y.raw));
    if same {
        Ok(())
    } else {
        Err(EvmError::RequestMismatch)
    }
}

/// 交易哈希（用于核对节点返回的哈希是否就是这笔交易）
pub fn tx_hash(raw: &[u8]) -> [u8; 32] {
    keccak256(raw)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn funds_are_checked_including_the_maximum_fee() {
        let fee = U256::from_u64(21_000 * 2);
        let v = U256::from_u64(100);
        let exact = v.checked_add(fee).unwrap();
        assert_eq!(
            check_funds(exact, None, v, 21_000, U256::from_u64(2)),
            Funds::Enough
        );
        assert_eq!(
            check_funds(
                U256::from_u64(21_000 * 2 + 99),
                None,
                v,
                21_000,
                U256::from_u64(2)
            ),
            Funds::NativeShort
        );
        // 代币转账：原生币只需付手续费；代币不够另行报告
        assert_eq!(
            check_funds(fee, Some(v), v, 21_000, U256::from_u64(2)),
            Funds::Enough
        );
        assert_eq!(
            check_funds(fee, Some(U256::from_u64(99)), v, 21_000, U256::from_u64(2)),
            Funds::TokenShort
        );
        assert_eq!(
            check_funds(
                U256::from_u64(21_000 * 2 - 1),
                Some(v),
                v,
                21_000,
                U256::from_u64(2)
            ),
            Funds::NativeShort
        );
        // 溢出按不够处理
        assert_eq!(
            check_funds(U256::MAX, None, U256::MAX, 21_000, U256::from_u64(1)),
            Funds::NativeShort
        );
    }
}
