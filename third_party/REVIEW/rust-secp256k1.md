# 审查清单：rust-secp256k1

> 自动生成于 2026-10-10。以下只列出需要人工判断的位置；**结论一栏必须由审查人填写**。

## 概况

| 项目 | 数量 |
|---|---|
| 文件总数 | 216 |
| Rust 源文件 | 24 |
| C/C++/汇编文件 | 107 |
| Cargo.toml | 3 |
| build.rs（构建期执行） | 1 |
| 过程宏 crate（构建期执行） | 0 |
| `unsafe` 出现次数 | 174 |

## 构建期会执行的代码

```
secp256k1-sys/build.rs
```

## 需要人工看的位置

### 二进制嵌入（涉及 0 个文件，最多列 40 行）

无

### 网络（涉及 0 个文件，最多列 40 行）

无

### 进程与环境（涉及 1 个文件，最多列 40 行）

```
secp256k1-sys/build.rs:46:    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32" {
```

### 文件系统（涉及 0 个文件，最多列 40 行）

无

### 外部函数（涉及 6 个文件，最多列 40 行）

```
secp256k1-sys/src/types.rs:60:    extern "C" {
secp256k1-sys/src/recovery.rs:102:extern "C" {
secp256k1-sys/src/recovery.rs:120:extern "C" {
secp256k1-sys/src/lib.rs:51:pub type NonceFn = Option<unsafe extern "C" fn(
secp256k1-sys/src/lib.rs:62:pub type EcdhHashFn = Option<unsafe extern "C" fn(
secp256k1-sys/src/lib.rs:74:pub type SchnorrNonceFn = Option<unsafe extern "C" fn(
secp256k1-sys/src/lib.rs:86:pub type EllswiftEcdhHashFn = Option<unsafe extern "C" fn(
secp256k1-sys/src/lib.rs:546:extern "C" {
secp256k1-sys/src/lib.rs:664:extern "C" {
secp256k1-sys/src/lib.rs:883:pub unsafe extern "C" fn rustsecp256k1_v0_10_0_context_create(flags: c_uint) -> NonNull<Context> {
secp256k1-sys/src/lib.rs:922:pub unsafe extern "C" fn rustsecp256k1_v0_10_0_context_destroy(mut ctx: NonNull<Context>) {
secp256k1-sys/src/lib.rs:958:pub unsafe extern "C" fn rustsecp256k1_v0_10_0_default_illegal_callback_fn(message: *const c_char, _data: *mut c_void) {
secp256k1-sys/src/lib.rs:986:pub unsafe extern "C" fn rustsecp256k1_v0_10_0_default_error_callback_fn(message: *const c_char, _data: *mut c_void) {
secp256k1-sys/src/lib.rs:1094:    extern "C" {
no_std_test/src/main.rs:19://! 37 | pub extern "C" fn rust_eh_personality() {}
src/ellswift.rs:47:unsafe extern "C" fn hash_callback<F>(
src/ecdh.rs:147:unsafe extern "C" fn c_callback(
```

### C 代码中的系统调用（涉及 2 个文件，最多列 40 行）

```
secp256k1-sys/depend/secp256k1/src/precompute_ecmult_gen.c:28:    fp = fopen(outfile, "w");
secp256k1-sys/depend/secp256k1/src/precompute_ecmult.c:62:    fp = fopen(outfile, "w");
```

## 二进制文件扫描

```
```

## 许可证文件

```
secp256k1-sys/LICENSE
LICENSE
```

## 审查结论（人工填写）

| 项 | 结论 | 审查人 | 日期 |
|---|---|---|---|
| build.rs / 过程宏行为是否只做编译所需的事 | | | |
| 是否存在网络、进程、文件访问且非必要 | | | |
| 二进制文件是否全部为无害测试数据 | | | |
| 许可证是否兼容 MIT 项目 | | | |
| 是否同意引入 | | | |

## 初审记录（Claude，2026-10-10，待人工复核）

- `secp256k1-sys/build.rs`（65 行）：只用 `cc` 编译 `depend/secp256k1` 下的 4 个 C 文件，定义编译宏；无网络、无额外文件访问。**可接受。**
- 内附 C 源码已由检查 C7 核对：153 个文件 = 上游 bitcoin-core/secp256k1@1ad5185c + 仓库内 5 个公开补丁 + 统一改名，逐字节一致（上游误提交的 `util.h.orig` 也一致）。
- 编译时上游代码有 1 个 C 警告（`bip340_algo[13]` 字符串初始化不含结尾 0），是有意为之的 13 字节标签，不影响正确性。
