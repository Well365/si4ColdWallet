//! FFI 公共部分（决策 D2）。所有 unsafe 只用于读取调用方指针、交接/回收缓冲区与句柄。
#![allow(unsafe_code)]

pub use aw_ur;

use aw_common::secret::wipe_bytes;
use aw_ur::ur::{Ur, UrDecoder, UrEncoder};
use aw_ur::UrError;

pub const AW_OK: i32 = 0;
pub const AW_ERR_NULL_POINTER: i32 = -1;
pub const AW_ERR_BAD_ARGUMENT: i32 = -2;
pub const AW_ERR_BAD_MNEMONIC: i32 = -3;
pub const AW_ERR_DERIVATION: i32 = -4;
pub const AW_ERR_SELFTEST: i32 = -10;
pub const AW_ERR_STATE: i32 = -11;
/// 系统随机数没有通过健康检查（全零、卡住、重复或有明显规律）
pub const AW_ERR_RNG_HEALTH: i32 = -12;
/// 纯骰子模式下骰子次数不够
pub const AW_ERR_DICE_TOO_FEW: i32 = -13;
/// 纯骰子模式下点数分布不像真实掷骰
pub const AW_ERR_DICE_POOR: i32 = -14;
/// 解锁得到的钱包指纹与用户填写的预期指纹不一致（多半是 passphrase 输错）
pub const AW_ERR_FINGERPRINT_MISMATCH: i32 = -15;
pub const AW_ERR_UR: i32 = -20;
pub const AW_ERR_UR_OTHER_SET: i32 = -21;
pub const AW_ERR_UR_TYPE: i32 = -22;
pub const AW_ERR_TX: i32 = -30;
/// 交易审查拒绝：具体原因编码为 AW_ERR_TX_REJECT_BASE - 原因序号
pub const AW_ERR_TX_REJECT_BASE: i32 = -100;
/// EVM 请求拒绝：AW_ERR_EVM_REJECT_BASE - 原因序号
pub const AW_ERR_EVM_REJECT_BASE: i32 = -300;
/// Solana 请求拒绝：AW_ERR_SOL_REJECT_BASE - 原因序号（P2c）
pub const AW_ERR_SOL_REJECT_BASE: i32 = -400;
/// 解码出的二维码不是签名机能处理的请求类型
pub const AW_ERR_UNSUPPORTED_REQUEST: i32 = -23;
/// 请求含高风险警告，调用方没有传入"用户已确认"
pub const AW_ERR_NEEDS_CONFIRMATION: i32 = -24;

/// UR 帧中二维码分片的最大字节数（约对应 25×4 字节 / 帧，适合手机屏幕动画显示）
pub const QR_MAX_FRAGMENT: usize = 120;

pub fn ur_error_code(e: UrError) -> i32 {
    match e {
        UrError::Inconsistent => AW_ERR_UR_OTHER_SET,
        UrError::UnexpectedType => AW_ERR_UR_TYPE,
        _ => AW_ERR_UR,
    }
}

/// 读取调用方给的字节切片。长度为 0 时允许 NULL。
///
/// # Safety
/// `ptr` 必须指向 `len` 个可读字节，且在调用期间有效。
pub unsafe fn input<'a>(ptr: *const u8, len: usize, max: usize) -> Result<&'a [u8], i32> {
    if len > max {
        return Err(AW_ERR_BAD_ARGUMENT);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(AW_ERR_NULL_POINTER);
    }
    // SAFETY: 调用方保证；已检查非空与长度上限。
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// 取出解码器中已经收齐的 UR。未收齐返回 `AW_ERR_STATE`。
///
/// # Safety
/// `d` 必须是有效的解码器指针或 NULL，且在返回的引用使用期间不被释放。
pub unsafe fn decoded_ur<'a>(d: *const AwUrDecoder) -> Result<&'a Ur, i32> {
    // SAFETY: 调用方保证。
    let dec = unsafe { d.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
    match dec.0.result() {
        Some(Ok(ur)) => Ok(ur),
        Some(Err(e)) => Err(ur_error_code(*e)),
        None => Err(AW_ERR_STATE),
    }
}

/// 清空输出参数；只有成功时才写入有效值。
///
/// # Safety
/// 两个指针必须有效可写或为 NULL（为 NULL 时返回错误）。
pub unsafe fn clear_out(out_ptr: *mut *mut u8, out_len: *mut usize) -> Result<(), i32> {
    if out_ptr.is_null() || out_len.is_null() {
        return Err(AW_ERR_NULL_POINTER);
    }
    // SAFETY: 已检查非空。
    unsafe {
        *out_ptr = core::ptr::null_mut();
        *out_len = 0;
    }
    Ok(())
}

/// 把缓冲区交给调用方；调用方必须用 `aw_buf_free` 归还。
///
/// # Safety
/// 两个指针必须有效可写（先调用过 `clear_out`）。
pub unsafe fn hand_out(bytes: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed).cast::<u8>();
    // SAFETY: 调用方保证两个输出指针有效。
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    AW_OK
}

/// # Safety
/// `(ptr, len)` 必须正是此前由本库交出的同一对值，且只释放一次。
pub unsafe fn buf_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: 调用方保证 (ptr, len) 来自 hand_out 的 Box<[u8]>。
    let mut boxed: Box<[u8]> =
        unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len)) };
    wipe_bytes(&mut boxed);
    drop(boxed);
}

/// dyld 的版本描述（`<mach-o/dyld_priv.h>` 中的 `dyld_build_version_t`）
#[cfg(target_vendor = "apple")]
#[repr(C)]
struct DyldBuildVersion {
    platform: u32,
    version: u32,
}

#[cfg(target_vendor = "apple")]
extern "C" {
    /// libdyld 导出（iOS 15 / macOS 11 起）；编译器运行时在新系统上也是调用它。
    fn _availability_version_check(count: u32, versions: *const DyldBuildVersion) -> bool;
}

/// 判断当前系统版本是否不低于给定版本（`__isPlatformVersionAtLeast` 的实现，见 `define_common_ffi!`）。
#[cfg(target_vendor = "apple")]
pub fn platform_version_at_least(platform: u32, major: u32, minor: u32, subminor: u32) -> i32 {
    let v = DyldBuildVersion {
        platform,
        version: ((major & 0xffff) << 16) | ((minor & 0xff) << 8) | (subminor & 0xff),
    };
    // SAFETY: 传入指向 1 个有效元素的指针；该函数只读取它。
    i32::from(unsafe { _availability_version_check(1, &v) })
}

/// 动画二维码编码器句柄
pub struct AwUrEncoder(pub UrEncoder);
/// 扫码解码器句柄
pub struct AwUrDecoder(pub UrDecoder);

pub fn new_encoder(ur: Ur) -> Result<*mut AwUrEncoder, i32> {
    let enc = UrEncoder::new(ur, QR_MAX_FRAGMENT, 0, 10).map_err(ur_error_code)?;
    Ok(Box::into_raw(Box::new(AwUrEncoder(enc))))
}

/// 生成两个 FFI 库共用的 UR / 缓冲区 extern 函数（保证实现一致）。
#[macro_export]
macro_rules! define_common_ffi {
    () => {
        /// 替代编译器运行时（compiler-rt）中的同名函数：Swift 的 `#available` 与 SwiftUI 内联代码会调用它。
        /// compiler-rt 的版本为兼容旧系统，会用 dlsym 查找 CoreFoundation 并读取 SystemVersion.plist，
        /// 使签名机不得不导入 dlsym / fopen（安全复核四 H2）。部署目标 iOS 17 必有 dyld 的
        /// `_availability_version_check`，这里只保留这一条路径；本库在链接顺序上先于 compiler-rt，
        /// 链接器因此不会再拉入 compiler-rt 的实现（C4 检查二进制中不得再出现 dlsym / fopen）。
        #[cfg(target_vendor = "apple")]
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "C" fn __isPlatformVersionAtLeast(
            platform: u32,
            major: u32,
            minor: u32,
            subminor: u32,
        ) -> i32 {
            $crate::platform_version_at_least(platform, major, minor, subminor)
        }

        /// # Safety
        /// 见 `aw_ffi_common::buf_free`。
        #[no_mangle]
        pub unsafe extern "C" fn aw_buf_free(ptr: *mut u8, len: usize) {
            // SAFETY: 透传调用方的保证。
            unsafe { $crate::buf_free(ptr, len) }
        }

        #[no_mangle]
        pub extern "C" fn aw_ur_decoder_new() -> *mut $crate::AwUrDecoder {
            Box::into_raw(Box::new($crate::AwUrDecoder(
                $crate::aw_ur::ur::UrDecoder::new(),
            )))
        }

        /// # Safety
        /// `d` 必须来自 `aw_ur_decoder_new` 且只释放一次；可为 NULL。
        #[no_mangle]
        pub unsafe extern "C" fn aw_ur_decoder_free(d: *mut $crate::AwUrDecoder) {
            if !d.is_null() {
                // SAFETY: 调用方保证来源与唯一释放。
                drop(unsafe { Box::from_raw(d) });
            }
        }

        /// 收一帧。返回 0 = 已收下尚未完成；1 = 已完成；负数 = 这一帧无效（AW_ERR_UR_OTHER_SET 表示换了另一组码）。
        ///
        /// # Safety
        /// `d` 为有效解码器；`s` 指向 `len` 字节。
        #[no_mangle]
        pub unsafe extern "C" fn aw_ur_decoder_receive(
            d: *mut $crate::AwUrDecoder,
            s: *const u8,
            len: usize,
        ) -> i32 {
            // SAFETY: 调用方保证 d 有效。
            let Some(dec) = (unsafe { d.as_mut() }) else {
                return $crate::AW_ERR_NULL_POINTER;
            };
            // SAFETY: 调用方保证。
            let bytes = match unsafe { $crate::input(s, len, 8192) } {
                Ok(b) => b,
                Err(e) => return e,
            };
            let Ok(text) = core::str::from_utf8(bytes) else {
                return $crate::AW_ERR_UR;
            };
            match dec.0.receive(text) {
                Ok(()) => i32::from(dec.0.result().is_some()),
                Err(e) => $crate::ur_error_code(e),
            }
        }

        /// # Safety
        /// `d` 为有效解码器；两个输出指针有效。
        #[no_mangle]
        pub unsafe extern "C" fn aw_ur_decoder_progress(
            d: *const $crate::AwUrDecoder,
            got: *mut usize,
            total: *mut usize,
        ) -> i32 {
            // SAFETY: 调用方保证。
            let Some(dec) = (unsafe { d.as_ref() }) else {
                return $crate::AW_ERR_NULL_POINTER;
            };
            if got.is_null() || total.is_null() {
                return $crate::AW_ERR_NULL_POINTER;
            }
            let (g, t) = dec.0.progress();
            // SAFETY: 已检查非空。
            unsafe {
                *got = g;
                *total = t;
            }
            $crate::AW_OK
        }

        /// # Safety
        /// `e` 必须来自本库创建的编码器且只释放一次；可为 NULL。
        #[no_mangle]
        pub unsafe extern "C" fn aw_ur_encoder_free(e: *mut $crate::AwUrEncoder) {
            if !e.is_null() {
                // SAFETY: 调用方保证来源与唯一释放。
                drop(unsafe { Box::from_raw(e) });
            }
        }

        /// 下一帧二维码内容（大写 ASCII，适合二维码字母数字模式）。
        ///
        /// # Safety
        /// `e` 为有效编码器；输出指针有效。
        #[no_mangle]
        pub unsafe extern "C" fn aw_ur_encoder_next(
            e: *mut $crate::AwUrEncoder,
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            // SAFETY: 调用方保证。
            if let Err(code) = unsafe { $crate::clear_out(out_ptr, out_len) } {
                return code;
            }
            // SAFETY: 调用方保证 e 有效。
            let Some(enc) = (unsafe { e.as_mut() }) else {
                return $crate::AW_ERR_NULL_POINTER;
            };
            let frame = enc.0.next_part().to_ascii_uppercase();
            // SAFETY: 输出指针已检查。
            unsafe { $crate::hand_out(frame.into_bytes(), out_ptr, out_len) }
        }

        /// 从已完成的解码器取出 PSBT（接受 crypto-psbt 与 psbt 两种类型）。
        ///
        /// # Safety
        /// `d` 为有效解码器；输出指针有效。
        #[no_mangle]
        pub unsafe extern "C" fn aw_ur_decoder_take_psbt(
            d: *const $crate::AwUrDecoder,
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            // SAFETY: 调用方保证。
            if let Err(code) = unsafe { $crate::clear_out(out_ptr, out_len) } {
                return code;
            }
            // SAFETY: 调用方保证。
            let Some(dec) = (unsafe { d.as_ref() }) else {
                return $crate::AW_ERR_NULL_POINTER;
            };
            let ur = match dec.0.result() {
                Some(Ok(ur)) => ur,
                Some(Err(e)) => return $crate::ur_error_code(*e),
                None => return $crate::AW_ERR_STATE,
            };
            match $crate::aw_ur::registry::decode_psbt(ur) {
                // SAFETY: 输出指针已检查。
                Ok(psbt) => unsafe { $crate::hand_out(psbt, out_ptr, out_len) },
                Err(e) => $crate::ur_error_code(e),
            }
        }

        /// # Safety
        /// `e` 为有效编码器。
        #[no_mangle]
        pub unsafe extern "C" fn aw_ur_encoder_seq_len(e: *const $crate::AwUrEncoder) -> usize {
            // SAFETY: 调用方保证。
            unsafe { e.as_ref() }.map_or(0, |enc| enc.0.seq_len())
        }
    };
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::platform_version_at_least;

    /// dyld 平台编号：1 = macOS（测试在 macOS 主机上运行）
    const PLATFORM_MACOS: u32 = 1;

    #[test]
    fn version_check_matches_running_system() {
        assert_eq!(platform_version_at_least(PLATFORM_MACOS, 11, 0, 0), 1);
        assert_eq!(platform_version_at_least(PLATFORM_MACOS, 999, 0, 0), 0);
    }
}
