//! 秘密数据的清零与持有（威胁 T10）。
//!
//! 编译器可能把"写完就不再读"的清零操作优化掉，所以这里用 volatile 写入，
//! 再加一道编译器屏障，确保清零真的发生。这是本 crate 唯一的 unsafe 代码。

use core::sync::atomic::{compiler_fence, Ordering};

/// 把一段内存逐字节写零，且不会被优化掉。
#[allow(unsafe_code)]
pub fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` 来自一个有效的 `&mut u8`，对齐且可写。
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// 把一段 u16 内存写零（用于助记词单词序号）。
#[allow(unsafe_code)]
pub fn wipe_u16(buf: &mut [u16]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` 来自一个有效的 `&mut u16`，对齐且可写。
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// 定长秘密字节数组：离开作用域时自动清零；`Debug` 输出不泄露内容。
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

impl<const N: usize> SecretBytes<N> {
    /// 全零缓冲区，供"由被调用方就地写入"的接口使用，避免按值返回留下栈上副本。
    pub fn zeroed() -> Self {
        Self([0u8; N])
    }

    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes<{N}>(<已隐藏>)")
    }
}

/// 变长秘密字节：离开作用域时自动清零。构造后长度不变，不会因扩容留下旧副本。
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// 拷贝一份；调用方负责清零自己的源缓冲区。
    pub fn copy_from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

impl core::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretVec({} bytes, <已隐藏>)", self.0.len())
    }
}

/// 清洗当前栈帧以下的一段栈内存（P1 Rust 审查 M1）。
///
/// 第三方代码（HMAC、BIP32）的中间变量没有清零，函数返回后仍留在栈上。
/// 在处理完秘密的 FFI 调用返回前调用本函数：它的大栈帧正好覆盖刚才被调用函数用过的区域。
#[inline(never)]
pub fn scrub_stack() {
    let mut area = [0xA5u8; SCRUB_BYTES];
    wipe_bytes(&mut area);
    core::hint::black_box(&area);
}

/// 栈清洗范围。P1 复测：一次地址派生调用实测使用约 33 KB 栈，取 64 KiB 留余量（见 P1 费曼汇报）。
pub const SCRUB_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_bytes_zeroes_everything() {
        let mut b = [0xAAu8; 37];
        wipe_bytes(&mut b);
        assert!(b.iter().all(|&x| x == 0));
    }

    #[test]
    fn wipe_u16_zeroes_everything() {
        let mut w = [2047u16; 24];
        wipe_u16(&mut w);
        assert!(w.iter().all(|&x| x == 0));
    }

    #[test]
    fn secret_vec_debug_and_expose() {
        let v = SecretVec::copy_from(&[1, 2, 3]);
        assert_eq!(v.expose(), &[1, 2, 3]);
        assert!(!format!("{v:?}").contains('1'));
    }

    #[test]
    fn scrub_stack_runs() {
        scrub_stack();
    }

    #[test]
    fn debug_does_not_leak() {
        let s = SecretBytes::new([0x42u8; 4]);
        let shown = format!("{s:?}");
        assert!(!shown.contains("42"));
        assert!(shown.contains("已隐藏"));
    }
}
