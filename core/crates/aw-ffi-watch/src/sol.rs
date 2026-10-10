//! 观察机的 Solana 接口（P2c）。头文件：`include/aw_watch.h` 的 Solana 一节。
//!
//! 观察机构造交易后，用与签名机**同一份**审查代码生成显示模型；签名回来后核对请求号、签名者与签名，
//! 才拼出可广播交易。

use crate::evm::give;
use aw_chain_sol::programs::{associated_token_account, TOKEN, TOKEN_2022};
use aw_chain_sol::request::{decode_signature, encode_request, SignRequest};
use aw_chain_sol::review::{review, sol, BASE_FEE_PER_SIGNATURE};
use aw_chain_sol::watch::{
    build_request, build_transfer, finalize, priority_tiers, transaction_id, TokenSpec, Transfer,
};
use aw_chain_sol::{address, parse_address, Scheme, SolError};
use aw_common::json::Json;
use aw_ffi_common::{
    clear_out, decoded_ur, hand_out, input, new_encoder, ur_error_code, AwUrDecoder, AwUrEncoder,
    AW_ERR_BAD_ARGUMENT, AW_ERR_NULL_POINTER, AW_ERR_SOL_REJECT_BASE, AW_OK,
};

pub struct AwSolPending {
    req: SignRequest,
}

/// 与签名机 aw-ffi-signer 的 sol_error_code 同一张表（测试固定）
pub(crate) fn sol_code(e: SolError) -> i32 {
    let n = match e {
        SolError::Parse => 1,
        SolError::LookupTable => 2,
        SolError::NotSigner => 3,
        SolError::OwnerChange => 4,
        SolError::SetAuthority => 5,
        SolError::Overflow => 6,
        SolError::Unsupported => 7,
        SolError::PathMismatch => 8,
        SolError::AddressMismatch => 9,
        SolError::Derivation => 10,
        SolError::BadSignature => 11,
        SolError::RequestMismatch => 12,
    };
    AW_ERR_SOL_REJECT_BASE - n
}

/// # Safety
/// `p` 指向 32 字节。
unsafe fn key_at(p: *const u8) -> Result<[u8; 32], i32> {
    // SAFETY: 调用方保证。
    unsafe { input(p, 32, 32) }?
        .try_into()
        .map_err(|_| AW_ERR_BAD_ARGUMENT)
}

fn token_program(kind: u8) -> Result<[u8; 32], i32> {
    match kind {
        0 => Ok(TOKEN),
        1 => Ok(TOKEN_2022),
        _ => Err(AW_ERR_BAD_ARGUMENT),
    }
}

fn scheme(n: u32) -> Result<Scheme, i32> {
    Scheme::ALL
        .get(usize::try_from(n).map_err(|_| AW_ERR_BAD_ARGUMENT)?)
        .copied()
        .ok_or(AW_ERR_BAD_ARGUMENT)
}

/// Base58 地址文本 → 32 字节（必须是规范写法）
///
/// # Safety
/// `s` 指向 `len` 字节；`out32` 指向 32 字节可写内存。
#[no_mangle]
pub unsafe extern "C" fn aw_sol_parse_address(s: *const u8, len: usize, out32: *mut u8) -> i32 {
    if out32.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 调用方保证。
    let r = unsafe { input(s, len, 64) }.and_then(|b| {
        core::str::from_utf8(b)
            .ok()
            .and_then(parse_address)
            .ok_or(AW_ERR_BAD_ARGUMENT)
    });
    match r {
        Ok(k) => {
            // SAFETY: 调用方保证 out32 指向 32 字节。
            unsafe { core::ptr::copy_nonoverlapping(k.as_ptr(), out32, 32) };
            AW_OK
        }
        Err(e) => e,
    }
}

/// 关联代币账户的地址文本（`token2022`：0 SPL Token，1 Token-2022）
///
/// # Safety
/// `owner32`、`mint32` 各指向 32 字节；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_sol_ata(
    owner32: *const u8,
    mint32: *const u8,
    token2022: u8,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out, out_len) } {
        return e;
    }
    let r = (|| -> Result<Vec<u8>, i32> {
        // SAFETY: 调用方保证。
        let owner = unsafe { key_at(owner32) }?;
        // SAFETY: 调用方保证。
        let mint = unsafe { key_at(mint32) }?;
        let ata = associated_token_account(&owner, &mint, &token_program(token2022)?)
            .ok_or_else(|| sol_code(SolError::Derivation))?;
        Ok(address(&ata).into_bytes())
    })();
    match r {
        // SAFETY: 输出指针已检查。
        Ok(v) => unsafe { hand_out(v, out, out_len) },
        Err(e) => e,
    }
}

/// 优先费三档（决策 D37）。`samples` 为 getRecentPrioritizationFees 的 prioritizationFee（微 lamports / 单元），
/// 输出 JSON 数组（慢、标准、快）：{speed, label, price, max_fee（lamports，整数）, max_fee_text}，
/// 最高手续费 = 5000 + ⌈价格 × unit_limit / 10⁶⌉（单签名交易）
///
/// # Safety
/// `samples` 指向 `n` 个 u64（n 为 0 时可为空）；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_sol_priority_tiers(
    samples: *const u64,
    n: usize,
    unit_limit: u32,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out_json, out_len) } {
        return e;
    }
    let r = (|| -> Result<Vec<u8>, i32> {
        if n > 1024 {
            return Err(AW_ERR_BAD_ARGUMENT);
        }
        let s: &[u64] = if n == 0 {
            &[]
        } else if samples.is_null() {
            return Err(AW_ERR_NULL_POINTER);
        } else {
            // SAFETY: 调用方保证 samples 指向 n 个 u64。
            unsafe { core::slice::from_raw_parts(samples, n) }
        };
        let list = priority_tiers(s)
            .iter()
            .zip([("slow", "慢"), ("standard", "标准"), ("fast", "快")])
            .map(|(&price, (key, label))| {
                let prio = (u128::from(price) * u128::from(unit_limit)).div_ceil(1_000_000);
                let fee = u64::try_from(prio)
                    .ok()
                    .and_then(|p| p.checked_add(BASE_FEE_PER_SIGNATURE))
                    .ok_or_else(|| sol_code(SolError::Overflow))?;
                Ok(Json::obj(vec![
                    ("speed", Json::str(key)),
                    ("label", Json::str(label)),
                    ("price", Json::UInt(price)),
                    ("max_fee", Json::UInt(fee)),
                    ("max_fee_text", Json::str(sol(fee))),
                ]))
            })
            .collect::<Result<Vec<_>, i32>>()?;
        Ok(Json::Array(list).to_string_compact().into_bytes())
    })();
    match r {
        // SAFETY: 输出指针已检查。
        Ok(v) => unsafe { hand_out(v, out_json, out_len) },
        Err(e) => e,
    }
}

/// 构造 SOL 或代币转账并生成签名请求。`mint32` 为空表示 SOL（`amount` 为 lamports）；否则为代币
/// （`amount` 为最小单位，`decimals` 为小数位，`token2022` 选代币程序）。`unit_limit` / `unit_price` 为 0 表示不设置。
/// `scheme`：0 Phantom、1 Ledger Live、2 Ledger Live 主账户（D34）；签名机会核对路径派生出的地址就是 `from32`。
/// 返回待签句柄与显示模型 JSON（与签名机将显示的内容相同）。
///
/// # Safety
/// 指针按长度有效；`from32`、`blockhash32` 各 32 字节，`mint32` 为 32 字节或空；`request_id16` 16 字节。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn aw_sol_build_transfer(
    from32: *const u8,
    scheme_n: u32,
    index: u32,
    to: *const u8,
    to_len: usize,
    amount: u64,
    mint32: *const u8,
    decimals: u8,
    token2022: u8,
    blockhash32: *const u8,
    unit_limit: u32,
    unit_price: u64,
    request_id16: *const u8,
    out_pending: *mut *mut AwSolPending,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out_json, out_json_len) } {
        return e;
    }
    let r = (|| -> Result<(AwSolPending, Vec<u8>), i32> {
        // SAFETY: 调用方保证。
        let from = unsafe { key_at(from32) }?;
        // SAFETY: 调用方保证。
        let to = unsafe { input(to, to_len, 64) }
            .ok()
            .and_then(|b| core::str::from_utf8(b).ok())
            .and_then(parse_address)
            .ok_or(AW_ERR_BAD_ARGUMENT)?;
        let token = if mint32.is_null() {
            None
        } else {
            Some(TokenSpec {
                // SAFETY: 调用方保证。
                mint: unsafe { key_at(mint32) }?,
                decimals,
                program: token_program(token2022)?,
            })
        };
        let msg = build_transfer(&Transfer {
            from,
            to,
            amount,
            token,
            // SAFETY: 调用方保证。
            blockhash: unsafe { key_at(blockhash32) }?,
            unit_limit: (unit_limit != 0).then_some(unit_limit),
            unit_price: (unit_price != 0).then_some(unit_price),
        })
        .map_err(sol_code)?;
        let display = review(&msg, &from).map_err(sol_code)?.display;
        // SAFETY: 调用方保证。
        let id: [u8; 16] = unsafe { input(request_id16, 16, 16) }?
            .try_into()
            .map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        let req = build_request(msg, scheme(scheme_n)?, index, from, None, id);
        Ok((
            AwSolPending { req },
            display.to_json().to_string_compact().into_bytes(),
        ))
    })();
    match r {
        Ok((p, json)) => {
            // SAFETY: 调用方保证。
            let rc = unsafe { give(out_pending, Ok(p)) };
            if rc != AW_OK {
                return rc;
            }
            // SAFETY: 输出指针已检查。
            unsafe { hand_out(json, out_json, out_json_len) }
        }
        // SAFETY: 调用方保证。
        Err(e) => unsafe { give::<AwSolPending>(out_pending, Err(e)) },
    }
}

/// 待签请求的动画二维码编码器（sol-sign-request）。
///
/// # Safety
/// `p` 有效；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_sol_pending_encoder(
    p: *const AwSolPending,
    out: *mut *mut AwUrEncoder,
) -> i32 {
    if out.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 已检查非空。
    unsafe { *out = core::ptr::null_mut() };
    // SAFETY: 调用方保证。
    let Some(p) = (unsafe { p.as_ref() }) else {
        return AW_ERR_NULL_POINTER;
    };
    match encode_request(&p.req)
        .map_err(ur_error_code)
        .and_then(new_encoder)
    {
        Ok(e) => {
            // SAFETY: 已检查非空。
            unsafe { *out = e };
            AW_OK
        }
        Err(e) => e,
    }
}

/// 核对签名机返回的 sol-signature（来自已收齐的解码器），输出 JSON：{tx_hex, txid}。
/// tx_hex 为完整交易的十六进制（Swift 转成 base64 后 sendTransaction）；txid 为第一个签名的 Base58。
///
/// # Safety
/// 指针有效；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_sol_pending_finalize(
    p: *const AwSolPending,
    d: *const AwUrDecoder,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out_json, out_len) } {
        return e;
    }
    let r = (|| -> Result<Vec<u8>, i32> {
        // SAFETY: 调用方保证。
        let p = unsafe { p.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        // SAFETY: 调用方保证。
        let sig = decode_signature(unsafe { decoded_ur(d) }?).map_err(ur_error_code)?;
        let tx = finalize(&p.req, &sig).map_err(sol_code)?;
        Ok(Json::obj(vec![
            ("tx_hex", Json::str(aw_common::hex::encode(&tx))),
            ("txid", Json::str(transaction_id(&sig.signature))),
        ])
        .to_string_compact()
        .into_bytes())
    })();
    match r {
        // SAFETY: 输出指针已检查。
        Ok(v) => unsafe { hand_out(v, out_json, out_len) },
        Err(e) => e,
    }
}

/// # Safety
/// `p` 来自 aw_sol_build_transfer，或为空。
#[no_mangle]
pub unsafe extern "C" fn aw_sol_pending_free(p: *mut AwSolPending) {
    if !p.is_null() {
        // SAFETY: 调用方保证指针来自 Box::into_raw 且只释放一次。
        drop(unsafe { Box::from_raw(p) });
    }
}
