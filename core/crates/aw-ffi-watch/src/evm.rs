//! 观察机的 EVM 接口（P2a）。头文件：`include/aw_watch.h` 的 EVM 一节。
//!
//! 观察机构造交易后，用与签名机**同一份**审查代码生成显示模型：两台设备显示的内容一致，
//! 用户可以逐行对照。签名回来后核对请求号、恢复地址与低 s 值，才拼出可广播交易。

use aw_chain_evm::account_ur::{account_from_hdkey, account_to_hdkey};
use aw_chain_evm::request::{decode_signature, encode_request, DataType, SignRequest};
use aw_chain_evm::review::review;
use aw_chain_evm::uint::U256;
use aw_chain_evm::watch::{build_eip1559, build_request, erc20_transfer, finalize, Eip1559};
use aw_chain_evm::{checksum_address, parse_address, Account, EvmError};
use aw_common::display::Display;
use aw_ffi_common::{
    clear_out, decoded_ur, hand_out, input, new_encoder, ur_error_code, AwUrDecoder, AwUrEncoder,
    AW_ERR_BAD_ARGUMENT, AW_ERR_EVM_REJECT_BASE, AW_ERR_NULL_POINTER, AW_OK,
};
use aw_ur::registry::{decode_hdkey, encode_hdkey, Style};
use bitcoin::secp256k1::{Secp256k1, VerifyOnly};

pub struct AwEvmAccount {
    account: Account,
    secp: Secp256k1<VerifyOnly>,
}

pub struct AwEvmPending {
    req: SignRequest,
}

fn evm_code(e: EvmError) -> i32 {
    let n = match e {
        EvmError::Parse => 1,
        EvmError::Unsupported => 2,
        EvmError::Eip7702 => 3,
        EvmError::NoReplayProtection => 4,
        EvmError::ChainMismatch => 5,
        EvmError::PathMismatch => 6,
        EvmError::AddressMismatch => 7,
        EvmError::DelegateCall => 8,
        EvmError::Overflow => 9,
        EvmError::Derivation => 10,
        EvmError::SelfCheck => 11,
        EvmError::BadSignature => 12,
        EvmError::RequestMismatch => 13,
        EvmError::BlindApproval => 14,
        EvmError::NeedsConfirmation => 15,
        EvmError::TooLong => 16,
    };
    AW_ERR_EVM_REJECT_BASE - n
}

/// # Safety
/// `out` 有效可写或 NULL。
unsafe fn give<T>(out: *mut *mut T, r: Result<T, i32>) -> i32 {
    if out.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    match r {
        Ok(v) => {
            // SAFETY: 已检查非空。
            unsafe { *out = Box::into_raw(Box::new(v)) };
            AW_OK
        }
        Err(e) => {
            // SAFETY: 已检查非空。
            unsafe { *out = core::ptr::null_mut() };
            e
        }
    }
}

fn account_from_ur(ur: &aw_ur::ur::Ur) -> Result<AwEvmAccount, i32> {
    let k = decode_hdkey(ur).map_err(ur_error_code)?;
    Ok(AwEvmAccount {
        account: account_from_hdkey(&k).map_err(evm_code)?,
        secp: Secp256k1::verification_only(),
    })
}

/// 从已完成扫码的解码器导入 EVM 账户（crypto-hdkey，币种 60）。
///
/// # Safety
/// `d` 为有效解码器；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_from_decoder(
    d: *const AwUrDecoder,
    out: *mut *mut AwEvmAccount,
) -> i32 {
    // SAFETY: 调用方保证。
    let r = unsafe { decoded_ur(d) }.and_then(account_from_ur);
    // SAFETY: 调用方保证。
    unsafe { give(out, r) }
}

/// 从保存的单段 UR 字符串恢复账户。
///
/// # Safety
/// `s` 指向 `len` 字节；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_from_ur(
    s: *const u8,
    len: usize,
    out: *mut *mut AwEvmAccount,
) -> i32 {
    // SAFETY: 调用方保证。
    let r = unsafe { input(s, len, 4096) }.and_then(|b| {
        let t = core::str::from_utf8(b).map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        account_from_ur(&aw_ur::ur::decode(t).map_err(ur_error_code)?)
    });
    // SAFETY: 调用方保证。
    unsafe { give(out, r) }
}

/// # Safety
/// `a` 来自本库且只释放一次；可为 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_free(a: *mut AwEvmAccount) {
    if !a.is_null() {
        // SAFETY: 调用方保证。
        drop(unsafe { Box::from_raw(a) });
    }
}

/// 单段 UR 文本（本地持久化用）。
///
/// # Safety
/// `a` 有效；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_to_ur(
    a: *const AwEvmAccount,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out, out_len) } {
        return e;
    }
    // SAFETY: 调用方保证。
    let Some(a) = (unsafe { a.as_ref() }) else {
        return AW_ERR_NULL_POINTER;
    };
    match encode_hdkey(&account_to_hdkey(&a.account), Style::Legacy) {
        // SAFETY: 输出指针已检查。
        Ok(ur) => unsafe { hand_out(aw_ur::ur::encode(&ur).into_bytes(), out, out_len) },
        Err(e) => ur_error_code(e),
    }
}

/// 根指纹（与签名机显示的一致，用于核对是同一个钱包）。
///
/// # Safety
/// `a` 有效或 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_fingerprint(a: *const AwEvmAccount) -> u32 {
    // SAFETY: 调用方保证。
    unsafe { a.as_ref() }.map_or(0, |a| {
        u32::from_be_bytes(a.account.master_fingerprint.to_bytes())
    })
}

/// 地址 m/44'/60'/0'/0/index（EIP-55 格式文本）。
///
/// # Safety
/// `a` 有效；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_address(
    a: *const AwEvmAccount,
    index: u32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out, out_len) } {
        return e;
    }
    // SAFETY: 调用方保证。
    let Some(a) = (unsafe { a.as_ref() }) else {
        return AW_ERR_NULL_POINTER;
    };
    match a.account.address(&a.secp, index) {
        // SAFETY: 输出指针已检查。
        Ok(addr) => unsafe { hand_out(checksum_address(&addr).into_bytes(), out, out_len) },
        Err(e) => evm_code(e),
    }
}

/// 十进制金额文本 → 32 字节大端整数（最小单位）。
///
/// # Safety
/// `s` 指向 `len` 字节；`out32` 指向 32 字节可写内存。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_parse_amount(
    s: *const u8,
    len: usize,
    decimals: u32,
    out32: *mut u8,
) -> i32 {
    if out32.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 调用方保证。
    let r = unsafe { input(s, len, 100) }.and_then(|b| {
        let t = core::str::from_utf8(b).map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        U256::parse_units(t, decimals).ok_or(AW_ERR_BAD_ARGUMENT)
    });
    match r {
        Ok(v) => {
            // SAFETY: 调用方保证 out32 指向 32 字节。
            unsafe { core::ptr::copy_nonoverlapping(v.to_be_bytes().as_ptr(), out32, 32) };
            AW_OK
        }
        Err(e) => e,
    }
}

/// JSON-RPC 十六进制数量（如余额 "0x1bc16d674ec80000"）→ 按小数位格式化的十进制文本。
///
/// # Safety
/// `s` 指向 `len` 字节；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_format_quantity(
    s: *const u8,
    len: usize,
    decimals: u32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out, out_len) } {
        return e;
    }
    // SAFETY: 调用方保证。
    let r = unsafe { input(s, len, 80) }.and_then(|b| {
        let t = core::str::from_utf8(b).map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        U256::from_hex_quantity(t).ok_or(AW_ERR_BAD_ARGUMENT)
    });
    match r {
        // SAFETY: 输出指针已检查。
        Ok(v) => unsafe { hand_out(v.format_units(decimals).into_bytes(), out, out_len) },
        Err(e) => e,
    }
}

/// 读取 32 字节大端整数
///
/// # Safety
/// `p` 指向 32 字节。
unsafe fn u256_at(p: *const u8) -> Result<U256, i32> {
    // SAFETY: 调用方保证。
    let b = unsafe { input(p, 32, 32) }?;
    let arr: &[u8; 32] = b.try_into().map_err(|_| AW_ERR_BAD_ARGUMENT)?;
    Ok(U256::from_be_bytes(arr))
}

/// 构造一笔 EIP-1559 转账并生成签名请求。`token_len == 0` 表示原生币；否则为 ERC-20 合约地址，
/// `value32` 为代币最小单位数量。返回待签句柄与显示模型 JSON（与签名机将显示的内容相同）。
///
/// # Safety
/// 所有指针按长度有效；金额参数各指向 32 字节；`request_id16` 指向 16 字节；输出指针有效。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn aw_evm_build_transfer(
    a: *const AwEvmAccount,
    index: u32,
    chain_id: u64,
    nonce: u64,
    max_priority_fee32: *const u8,
    max_fee32: *const u8,
    gas_limit: u64,
    to: *const u8,
    to_len: usize,
    value32: *const u8,
    token: *const u8,
    token_len: usize,
    request_id16: *const u8,
    out_pending: *mut *mut AwEvmPending,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out_json, out_json_len) } {
        return e;
    }
    let r = (|| -> Result<(AwEvmPending, Display), i32> {
        // SAFETY: 调用方保证。
        let a = unsafe { a.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        let text = |p, n| -> Result<[u8; 20], i32> {
            // SAFETY: 调用方保证。
            let b = unsafe { input(p, n, 64) }?;
            core::str::from_utf8(b)
                .ok()
                .and_then(parse_address)
                .ok_or(AW_ERR_BAD_ARGUMENT)
        };
        let recipient = text(to, to_len)?;
        // SAFETY: 调用方保证。
        let value = unsafe { u256_at(value32) }?;
        let (target, value, data) = if token_len == 0 {
            (recipient, value, Vec::new())
        } else {
            (
                text(token, token_len)?,
                U256::ZERO,
                erc20_transfer(&recipient, value),
            )
        };
        let tx = build_eip1559(&Eip1559 {
            chain_id,
            nonce,
            // SAFETY: 调用方保证。
            max_priority_fee: unsafe { u256_at(max_priority_fee32) }?,
            // SAFETY: 调用方保证。
            max_fee: unsafe { u256_at(max_fee32) }?,
            gas_limit,
            to: target,
            value,
            data,
        })
        .map_err(evm_code)?;
        // SAFETY: 调用方保证。
        let id: [u8; 16] = unsafe { input(request_id16, 16, 16) }?
            .try_into()
            .map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        let req = build_request(
            &a.secp,
            &a.account,
            index,
            tx,
            DataType::TypedTx,
            Some(chain_id),
            id,
        )
        .map_err(evm_code)?;
        let display = review(&a.secp, &a.account, &req).map_err(evm_code)?.display;
        Ok((AwEvmPending { req }, display))
    })();
    match r {
        Ok((p, d)) => {
            // SAFETY: 调用方保证。
            let rc = unsafe { give(out_pending, Ok(p)) };
            if rc != AW_OK {
                return rc;
            }
            // SAFETY: 输出指针已检查。
            unsafe {
                hand_out(
                    d.to_json().to_string_compact().into_bytes(),
                    out_json,
                    out_json_len,
                )
            }
        }
        Err(e) => {
            // SAFETY: 调用方保证。
            unsafe { give::<AwEvmPending>(out_pending, Err(e)) }
        }
    }
}

/// 待签请求的动画二维码编码器（eth-sign-request）。
///
/// # Safety
/// `p` 有效；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_pending_encoder(
    p: *const AwEvmPending,
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

/// 核对签名机返回的 eth-signature（来自已收齐的解码器），拼出可广播交易（"0x" 开头的十六进制）。
///
/// # Safety
/// 指针有效；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_pending_finalize(
    a: *const AwEvmAccount,
    p: *const AwEvmPending,
    d: *const AwUrDecoder,
    out_hex: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out_hex, out_len) } {
        return e;
    }
    let r = (|| -> Result<Vec<u8>, i32> {
        // SAFETY: 调用方保证。
        let a = unsafe { a.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        // SAFETY: 调用方保证。
        let p = unsafe { p.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        // SAFETY: 调用方保证。
        let sig = decode_signature(unsafe { decoded_ur(d) }?).map_err(ur_error_code)?;
        let raw = finalize(&a.secp, &a.account, &p.req, &sig).map_err(evm_code)?;
        Ok(format!("0x{}", aw_common::hex::encode(&raw)).into_bytes())
    })();
    match r {
        // SAFETY: 输出指针已检查。
        Ok(v) => unsafe { hand_out(v, out_hex, out_len) },
        Err(e) => e,
    }
}

/// 原始交易（"0x…" 十六进制文本）的交易哈希，用于核对节点广播后返回的哈希。
///
/// # Safety
/// `s` 指向 `len` 字节；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_tx_hash(
    s: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(e) = unsafe { clear_out(out, out_len) } {
        return e;
    }
    // SAFETY: 调用方保证。
    let r = unsafe { input(s, len, 2 * aw_chain_evm::MAX_SIGN_DATA + 1024) }.and_then(|b| {
        let t = core::str::from_utf8(b).map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        let hex = t.strip_prefix("0x").ok_or(AW_ERR_BAD_ARGUMENT)?;
        aw_common::hex::decode(hex).ok_or(AW_ERR_BAD_ARGUMENT)
    });
    match r {
        Ok(raw) => {
            let h = aw_chain_evm::watch::tx_hash(&raw);
            // SAFETY: 输出指针已检查。
            unsafe {
                hand_out(
                    format!("0x{}", aw_common::hex::encode(&h)).into_bytes(),
                    out,
                    out_len,
                )
            }
        }
        Err(e) => e,
    }
}

/// # Safety
/// `p` 来自本库且只释放一次；可为 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_evm_pending_free(p: *mut AwEvmPending) {
    if !p.is_null() {
        // SAFETY: 调用方保证。
        drop(unsafe { Box::from_raw(p) });
    }
}
