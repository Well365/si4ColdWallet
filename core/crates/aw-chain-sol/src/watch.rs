//! 观察机一侧（feature `watch`，P2c-T3）：构造 SOL / SPL 代币转账消息与签名请求；
//! 核对签名机返回的签名，拼出可广播的交易。观察机同样不完全信任签名机。

use crate::message::{encode_shortvec, Message};
use crate::programs::{
    associated_token_account, compile_legacy, compute_unit_limit, compute_unit_price,
    create_ata_idempotent, system_transfer, token_transfer_checked, Ix,
};
use crate::request::{keypath, SignRequest, SignType, Signature};
use crate::{Scheme, SolError};

/// 代币转账的代币信息
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenSpec {
    pub mint: [u8; 32],
    pub decimals: u8,
    /// 代币程序（SPL Token 或 Token-2022）
    pub program: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub from: [u8; 32],
    pub to: [u8; 32],
    /// lamports，或代币最小单位
    pub amount: u64,
    pub token: Option<TokenSpec>,
    pub blockhash: [u8; 32],
    pub unit_limit: Option<u32>,
    /// 计算单元价格（微 lamports）
    pub unit_price: Option<u64>,
}

/// 构造转账消息。发代币时总是带上"按需创建收款方关联代币账户"，签名机才能核对收款人（D37）
pub fn build_transfer(t: &Transfer) -> Result<Vec<u8>, SolError> {
    if t.amount == 0 || t.from == t.to {
        return Err(SolError::Parse);
    }
    let mut ixs: Vec<Ix> = Vec::new();
    if let Some(l) = t.unit_limit {
        ixs.push(compute_unit_limit(l));
    }
    if let Some(p) = t.unit_price {
        ixs.push(compute_unit_price(p));
    }
    match &t.token {
        None => ixs.push(system_transfer(&t.from, &t.to, t.amount)),
        Some(tok) => {
            let src = associated_token_account(&t.from, &tok.mint, &tok.program)
                .ok_or(SolError::Derivation)?;
            let dst = associated_token_account(&t.to, &tok.mint, &tok.program)
                .ok_or(SolError::Derivation)?;
            ixs.push(create_ata_idempotent(
                &t.from,
                &dst,
                &t.to,
                &tok.mint,
                &tok.program,
            ));
            ixs.push(token_transfer_checked(
                &tok.program,
                &src,
                &tok.mint,
                &dst,
                &t.from,
                t.amount,
                tok.decimals,
            ));
        }
    }
    let msg = compile_legacy(&t.from, &ixs, &t.blockhash).ok_or(SolError::Parse)?;
    // 构造出来的消息必须能被严格解析器原样读回
    Message::parse(&msg)?;
    Ok(msg)
}

pub fn build_request(
    msg: Vec<u8>,
    scheme: Scheme,
    index: u32,
    address: [u8; 32],
    fingerprint: Option<u32>,
    request_id: [u8; 16],
) -> SignRequest {
    SignRequest {
        request_id: Some(request_id),
        sign_data: msg,
        path: keypath(scheme, index, fingerprint),
        address: Some(address),
        origin: None,
        sign_type: Some(SignType::Transaction),
    }
}

/// 核对签名并拼出交易：请求号一致、消息只需要一个签名且签名者就是本地址、签名有效。
/// 交易 = 紧凑长度(1) ‖ 签名 64 字节 ‖ 消息
pub fn finalize(req: &SignRequest, sig: &Signature) -> Result<Vec<u8>, SolError> {
    if sig.request_id != req.request_id {
        return Err(SolError::RequestMismatch);
    }
    let m = Message::parse(&req.sign_data)?;
    let signer = *m.account_keys.first().ok_or(SolError::Parse)?;
    if m.required_signatures != 1 || req.address.is_some_and(|a| a != signer) {
        return Err(SolError::RequestMismatch);
    }
    let pk = ed25519_compact::PublicKey::new(signer);
    pk.verify(
        &req.sign_data,
        &ed25519_compact::Signature::new(sig.signature),
    )
    .map_err(|_| SolError::BadSignature)?;
    let mut tx = Vec::with_capacity(1 + 64 + req.sign_data.len());
    encode_shortvec(&mut tx, 1);
    tx.extend_from_slice(&sig.signature);
    tx.extend_from_slice(&req.sign_data);
    Ok(tx)
}

/// 标准档优先费下限（微 lamports / 计算单元）：网络空闲、样本全为 0 时也给一点优先费
pub const MIN_STANDARD_PRICE: u64 = 1_000;
/// 一档优先费最多 10⁷ 微 lamports / 单元（节点样本被操纵时的上限）
pub const MAX_PRICE: u64 = 10_000_000;

/// 优先费三档（微 lamports / 计算单元，决策 D37）：取 getRecentPrioritizationFees 样本的 25 / 50 / 75 百分位；
/// 标准档不低于 MIN_STANDARD_PRICE，快档不低于标准档的 2 倍；三档都不超过 MAX_PRICE
pub fn priority_tiers(samples: &[u64]) -> [u64; 3] {
    let mut v = samples.to_vec();
    v.sort_unstable();
    let pct = |q: usize| {
        v.get(v.len().saturating_sub(1) * q / 100)
            .copied()
            .unwrap_or(0)
    };
    let standard = pct(50).clamp(MIN_STANDARD_PRICE, MAX_PRICE);
    let slow = pct(25).min(standard);
    let fast = pct(75).max(standard.saturating_mul(2)).min(MAX_PRICE);
    [slow, standard, fast]
}

/// 交易号就是第一个签名的 Base58
pub fn transaction_id(sig: &[u8; 64]) -> String {
    base58ck::encode(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_tiers_follow_rules() {
        assert_eq!(priority_tiers(&[]), [0, 1_000, 2_000]);
        let s: Vec<u64> = (0..=100).map(|i| i * 100).collect();
        assert_eq!(priority_tiers(&s), [2_500, 5_000, 10_000]);
        assert_eq!(
            priority_tiers(&[u64::MAX; 5]),
            [MAX_PRICE, MAX_PRICE, MAX_PRICE]
        );
    }
}
