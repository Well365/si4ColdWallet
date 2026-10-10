//! 观察机 C 接口（决策 D1/D2）。头文件：`include/aw_watch.h`。
//! 本库不含任何私钥代码；`Cargo.toml` 不依赖 aw-bip39 / aw-keys（只在测试中使用）。
#![allow(unsafe_code)]

use aw_chain_btc::account_ur::{account_from_hdkey, account_to_hdkey};
use aw_chain_btc::watch::{build_payment, finalize, Utxo};
use aw_chain_btc::{Account, BtcError};
use aw_ffi_common::{
    clear_out, hand_out, input, new_encoder, ur_error_code, AwUrDecoder, AwUrEncoder,
    AW_ERR_BAD_ARGUMENT, AW_ERR_NULL_POINTER, AW_ERR_STATE, AW_ERR_TX, AW_ERR_TX_REJECT_BASE,
    AW_OK,
};
use aw_ur::registry::{decode_hdkey, encode_hdkey, encode_psbt, Style};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use bitcoin::{Address, Transaction};

aw_ffi_common::define_common_ffi!();

pub mod evm;
pub mod evm_message;

pub const AW_WATCH_ABI_VERSION: u32 = 4;
const MAX_UTXO_BLOB: usize = 4 * 1024 * 1024;
const MAX_PSBT: usize = 512 * 1024;

#[no_mangle]
pub extern "C" fn aw_watch_abi_version() -> u32 {
    AW_WATCH_ABI_VERSION
}

pub struct AwWatch {
    account: Account,
    secp: Secp256k1<VerifyOnly>,
}

pub struct AwPending {
    psbt: Psbt,
}

fn btc_code(e: BtcError) -> i32 {
    match e {
        BtcError::InsufficientFunds => AW_ERR_TX_REJECT_BASE - 19,
        BtcError::UtxoNotOurs(_) => AW_ERR_TX_REJECT_BASE - 20,
        BtcError::TxChanged => AW_ERR_TX_REJECT_BASE - 17,
        BtcError::BadSignature(_) => AW_ERR_TX_REJECT_BASE - 18,
        _ => AW_ERR_TX,
    }
}

fn new_watch(account: Account) -> *mut AwWatch {
    Box::into_raw(Box::new(AwWatch {
        account,
        secp: Secp256k1::verification_only(),
    }))
}

/// 从已完成扫码的解码器导入账户（crypto-hdkey / hdkey）。
///
/// # Safety
/// `d` 为有效解码器；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_from_decoder(
    d: *const AwUrDecoder,
    out: *mut *mut AwWatch,
) -> i32 {
    if out.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 已检查非空。
    unsafe { *out = core::ptr::null_mut() };
    // SAFETY: 调用方保证。
    let Some(dec) = (unsafe { d.as_ref() }) else {
        return AW_ERR_NULL_POINTER;
    };
    let ur = match dec.0.result() {
        Some(Ok(ur)) => ur,
        Some(Err(e)) => return ur_error_code(*e),
        None => return AW_ERR_STATE,
    };
    let account = match decode_hdkey(ur)
        .map_err(ur_error_code)
        .and_then(|k| account_from_hdkey(&k).map_err(btc_code))
    {
        Ok(a) => a,
        Err(e) => return e,
    };
    // SAFETY: 已检查非空。
    unsafe { *out = new_watch(account) };
    AW_OK
}

/// 从保存的单段 UR 字符串恢复账户（观察机本地持久化用）。
///
/// # Safety
/// `s` 指向 `len` 字节；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_from_ur(s: *const u8, len: usize, out: *mut *mut AwWatch) -> i32 {
    if out.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 已检查非空。
    unsafe { *out = core::ptr::null_mut() };
    // SAFETY: 调用方保证。
    let bytes = match unsafe { input(s, len, 4096) } {
        Ok(b) => b,
        Err(e) => return e,
    };
    let r = core::str::from_utf8(bytes)
        .map_err(|_| AW_ERR_BAD_ARGUMENT)
        .and_then(|t| aw_ur::ur::decode(t).map_err(ur_error_code))
        .and_then(|ur| decode_hdkey(&ur).map_err(ur_error_code))
        .and_then(|k| account_from_hdkey(&k).map_err(btc_code));
    match r {
        Ok(a) => {
            // SAFETY: 已检查非空。
            unsafe { *out = new_watch(a) };
            AW_OK
        }
        Err(e) => e,
    }
}

/// # Safety
/// `w` 来自本库且只释放一次；可为 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_free(w: *mut AwWatch) {
    if !w.is_null() {
        // SAFETY: 调用方保证。
        drop(unsafe { Box::from_raw(w) });
    }
}

/// 账户的单段 UR 字符串（用于本地保存）。
///
/// # Safety
/// `w` 有效；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_to_ur(
    w: *const AwWatch,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(c) = unsafe { clear_out(out_ptr, out_len) } {
        return c;
    }
    // SAFETY: 调用方保证。
    let Some(w) = (unsafe { w.as_ref() }) else {
        return AW_ERR_NULL_POINTER;
    };
    match encode_hdkey(&account_to_hdkey(&w.account), Style::Legacy) {
        // SAFETY: 输出指针已检查。
        Ok(ur) => unsafe { hand_out(aw_ur::ur::encode(&ur).into_bytes(), out_ptr, out_len) },
        Err(e) => ur_error_code(e),
    }
}

/// # Safety
/// `w` 有效或 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_fingerprint(w: *const AwWatch) -> u32 {
    // SAFETY: 调用方保证。
    unsafe { w.as_ref() }.map_or(0, |w| {
        u32::from_be_bytes(w.account.master_fingerprint.to_bytes())
    })
}

/// # Safety
/// `w` 有效或 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_is_testnet(w: *const AwWatch) -> u8 {
    // SAFETY: 调用方保证。
    unsafe { w.as_ref() }.map_or(0, |w| {
        u8::from(w.account.network != bitcoin::Network::Bitcoin)
    })
}

/// 地址：change 0=收款 1=找零。
///
/// # Safety
/// `w` 有效；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_address(
    w: *const AwWatch,
    change: u8,
    index: u32,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(c) = unsafe { clear_out(out_ptr, out_len) } {
        return c;
    }
    // SAFETY: 调用方保证。
    let Some(w) = (unsafe { w.as_ref() }) else {
        return AW_ERR_NULL_POINTER;
    };
    if change > 1 {
        return AW_ERR_BAD_ARGUMENT;
    }
    match w.account.address(&w.secp, change == 1, index) {
        // SAFETY: 输出指针已检查。
        Ok(a) => unsafe { hand_out(a.to_string().into_bytes(), out_ptr, out_len) },
        Err(e) => btc_code(e),
    }
}

/// UTXO 二进制格式（大端）：u32 个数，然后每个：u8 change、u32 index、u32 vout、u32 交易长度、交易字节。
fn parse_utxos(mut b: &[u8]) -> Result<Vec<Utxo>, i32> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], i32> {
        if b.len() < n {
            return Err(AW_ERR_BAD_ARGUMENT);
        }
        let (h, t) = b.split_at(n);
        *b = t;
        Ok(h)
    }
    fn u32_be(b: &mut &[u8]) -> Result<u32, i32> {
        let s: [u8; 4] = take(b, 4)?.try_into().map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        Ok(u32::from_be_bytes(s))
    }
    let count = u32_be(&mut b)? as usize;
    if count == 0 || count > aw_chain_btc::MAX_IO {
        return Err(AW_ERR_BAD_ARGUMENT);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let change = match take(&mut b, 1)? {
            [0] => false,
            [1] => true,
            _ => return Err(AW_ERR_BAD_ARGUMENT),
        };
        let index = u32_be(&mut b)?;
        let vout = u32_be(&mut b)?;
        let len = u32_be(&mut b)? as usize;
        let prev_tx: Transaction =
            deserialize(take(&mut b, len)?).map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        out.push(Utxo {
            prev_tx,
            vout,
            change,
            index,
        });
    }
    if !b.is_empty() {
        return Err(AW_ERR_BAD_ARGUMENT);
    }
    Ok(out)
}

/// 构造付款。成功时返回待签句柄与摘要 JSON。
///
/// # Safety
/// 所有指针按长度有效；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_watch_build_payment(
    w: *const AwWatch,
    utxos: *const u8,
    utxos_len: usize,
    to: *const u8,
    to_len: usize,
    amount_sat: u64,
    fee_rate_sat_vb: u64,
    change_index: u32,
    out_pending: *mut *mut AwPending,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    if out_pending.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 已检查非空。
    unsafe { *out_pending = core::ptr::null_mut() };
    // SAFETY: 调用方保证。
    if let Err(c) = unsafe { clear_out(out_json, out_json_len) } {
        return c;
    }
    let r = (|| -> Result<(AwPending, Vec<u8>), i32> {
        // SAFETY: 调用方保证。
        let w = unsafe { w.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        // SAFETY: 调用方保证。
        let blob = unsafe { input(utxos, utxos_len, MAX_UTXO_BLOB) }?;
        // SAFETY: 调用方保证。
        let to_bytes = unsafe { input(to, to_len, 128) }?;
        let to_str = core::str::from_utf8(to_bytes).map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        let addr = to_str
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|_| AW_ERR_BAD_ARGUMENT)?
            .require_network(w.account.network)
            .map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        let list = parse_utxos(blob)?;
        let (psbt, sum) = build_payment(
            &w.secp,
            &w.account,
            &list,
            &addr,
            amount_sat,
            fee_rate_sat_vb,
            change_index,
        )
        .map_err(btc_code)?;
        let json = aw_common::json::Json::obj(vec![
            ("inputs", aw_common::json::Json::UInt(sum.inputs as u64)),
            ("amount_sat", aw_common::json::Json::UInt(sum.amount)),
            ("fee_sat", aw_common::json::Json::UInt(sum.fee)),
            (
                "change_sat",
                sum.change
                    .map_or(aw_common::json::Json::Null, aw_common::json::Json::UInt),
            ),
            (
                "vsize_estimate",
                aw_common::json::Json::UInt(sum.vsize_estimate),
            ),
        ]);
        Ok((AwPending { psbt }, json.to_string_compact().into_bytes()))
    })();
    match r {
        Ok((p, json)) => {
            // SAFETY: 已检查非空。
            unsafe { *out_pending = Box::into_raw(Box::new(p)) };
            // SAFETY: 已检查。
            unsafe { hand_out(json, out_json, out_json_len) }
        }
        Err(e) => e,
    }
}

/// 待签交易的动画二维码。
///
/// # Safety
/// `p` 有效；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_pending_encoder(
    p: *const AwPending,
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
    match encode_psbt(&p.psbt.serialize(), Style::Legacy)
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

/// 用签名机返回的 PSBT 最终化，输出可广播交易的十六进制。
///
/// # Safety
/// `w`、`p` 有效；`signed` 指向 `len` 字节；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_pending_finalize(
    w: *const AwWatch,
    p: *const AwPending,
    signed: *const u8,
    len: usize,
    out_hex: *mut *mut u8,
    out_hex_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(c) = unsafe { clear_out(out_hex, out_hex_len) } {
        return c;
    }
    let r = (|| -> Result<Vec<u8>, i32> {
        // SAFETY: 调用方保证。
        let w = unsafe { w.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        // SAFETY: 调用方保证。
        let p = unsafe { p.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        // SAFETY: 调用方保证。
        let bytes = unsafe { input(signed, len, MAX_PSBT) }?;
        let tx = finalize(&w.secp, &w.account, &p.psbt, bytes).map_err(btc_code)?;
        Ok(aw_common::hex::encode(&serialize(&tx)).into_bytes())
    })();
    match r {
        // SAFETY: 已检查。
        Ok(v) => unsafe { hand_out(v, out_hex, out_hex_len) },
        Err(e) => e,
    }
}

/// # Safety
/// `p` 来自本库且只释放一次；可为 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_pending_free(p: *mut AwPending) {
    if !p.is_null() {
        // SAFETY: 调用方保证。
        drop(unsafe { Box::from_raw(p) });
    }
}

#[cfg(test)]
mod tests;
