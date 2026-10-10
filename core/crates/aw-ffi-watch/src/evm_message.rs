//! 观察机发起消息签名（personal_sign）与结构化签名（EIP-712）请求（P2a 第二部分）。
//!
//! 文本由用户粘贴（例如从 dApp 复制的 `eth_signTypedData_v4` JSON）。观察机先用与签名机**同一份**
//! 审查代码解析并生成显示模型：格式不严谨、链 ID 不符、超长的请求在观察机上就会被拒，不必等到签名机。
//! 签名回来后由 `aw_evm_pending_finalize` 核对签名能恢复出本地址，输出 65 字节签名的十六进制。

use crate::evm::{evm_code, hand_pending, AwEvmAccount, AwEvmPending};
use aw_chain_evm::request::DataType;
use aw_chain_evm::review::review;
use aw_chain_evm::watch::build_request;
use aw_chain_evm::MAX_SIGN_DATA;
use aw_common::display::Display;
use aw_ffi_common::{clear_out, input, AW_ERR_BAD_ARGUMENT, AW_ERR_NULL_POINTER};

/// 构造消息签名请求。`kind`：0 = personal_sign（UTF-8 文本），1 = EIP-712（JSON）。
/// `chain_id` 为 0 表示不声明链。返回待签句柄与显示模型 JSON。
///
/// # Safety
/// `a` 有效；`text` 指向 `len` 字节；`request_id16` 指向 16 字节；输出指针有效。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn aw_evm_build_message(
    a: *const AwEvmAccount,
    index: u32,
    kind: u8,
    text: *const u8,
    len: usize,
    chain_id: u64,
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
        let data_type = match kind {
            0 => DataType::PersonalMessage,
            1 => DataType::TypedData,
            _ => return Err(AW_ERR_BAD_ARGUMENT),
        };
        // SAFETY: 调用方保证。
        let bytes = unsafe { input(text, len, MAX_SIGN_DATA) }?;
        if bytes.is_empty() || core::str::from_utf8(bytes).is_err() {
            return Err(AW_ERR_BAD_ARGUMENT);
        }
        // SAFETY: 调用方保证。
        let id: [u8; 16] = unsafe { input(request_id16, 16, 16) }?
            .try_into()
            .map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        let req = build_request(
            &a.secp,
            &a.account,
            index,
            bytes.to_vec(),
            data_type,
            (chain_id != 0).then_some(chain_id),
            id,
        )
        .map_err(evm_code)?;
        let display = review(&a.secp, &a.account, &req).map_err(evm_code)?.display;
        Ok((AwEvmPending { req }, display))
    })();
    // SAFETY: 调用方保证。
    unsafe { hand_pending(r, out_pending, out_json, out_json_len) }
}
