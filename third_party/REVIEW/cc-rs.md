# 审查清单：cc-rs

> 自动生成于 2026-10-10。以下只列出需要人工判断的位置；**结论一栏必须由审查人填写**。

## 概况

| 项目 | 数量 |
|---|---|
| 文件总数 | 84 |
| Rust 源文件 | 42 |
| C/C++/汇编文件 | 20 |
| Cargo.toml | 5 |
| build.rs（构建期执行） | 1 |
| 过程宏 crate（构建期执行） | 0 |
| `unsafe` 出现次数 | 88 |

## 构建期会执行的代码

```
dev-tools/cc-test/build.rs
```

## 需要人工看的位置

### 二进制嵌入（涉及 1 个文件，最多列 40 行）

```
src/tool.rs:187:            tmp_file.write_all(include_bytes!("detect_compiler_family.c"))?;
```

### 网络（涉及 0 个文件，最多列 40 行）

无

### 进程与环境（涉及 15 个文件，最多列 40 行）

```
tests/test.rs:697:    let output = std::process::Command::new("xcrun")
tests/test.rs:754:    let output = std::process::Command::new("xcrun")
tests/test.rs:783:    let output = std::process::Command::new("xcrun")
tests/support/mod.rs:113:        let mut path = env::split_paths(&env::var_os("PATH").unwrap()).collect::<Vec<_>>();
dev-tools/gen-windows-sys-binding/src/main.rs:22:    let manifest_dir = env!("CARGO_MANIFEST_DIR");
dev-tools/gen-target-info/src/read.rs:1:use std::process;
dev-tools/gen-target-info/src/read.rs:6:    let mut cmd = process::Command::new("rustc");
dev-tools/gen-target-info/src/read.rs:21:    let mut cmd = process::Command::new("rustc");
dev-tools/gen-target-info/src/read.rs:44:    let mut cmd = process::Command::new(rustc.clone().unwrap_or("rustc".into()));
dev-tools/gen-target-info/src/main.rs:29:    let mut target_specs = get_target_specs_from_json(std::env::var("RUSTC").ok());
dev-tools/gen-target-info/src/main.rs:31:    if std::env::var("CC_RS_MSRV")
dev-tools/gen-target-info/src/main.rs:48:    let manifest_dir = env!("CARGO_MANIFEST_DIR");
dev-tools/cc-test/tests/output.rs:6:    if env!("TEST_WARNINGS_ON") == "0" {
dev-tools/cc-test/tests/output.rs:62:    let action_dir = PathBuf::from(env!("OUT_DIR")).join(action);
dev-tools/cc-test/build.rs:6:use std::process::Command;
dev-tools/cc-test/build.rs:15:    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
dev-tools/cc-test/build.rs:52:    let target = std::env::var("TARGET").unwrap();
dev-tools/cc-test/build.rs:73:    if env::var("CARGO_FEATURE_TEST_CUDA").is_ok() {
dev-tools/cc-test/build.rs:75:        let nvcc = match env::var("NVCC") {
dev-tools/cc-test/build.rs:181:    let output = Command::new(program).arg(action).output().unwrap();
src/parallel/job_token.rs:224:        env::var,
src/bin/cc-shim.rs:11:use std::process::ExitCode;
src/bin/cc-shim.rs:19:        env::var_os("CC_SHIM_OUT_DIR")
src/target/parser.rs:22:        let target_name = env::var("TARGET").map_err(|err| {
src/target/parser.rs:39:            match env::var(name) {
src/target/parser.rs:418:    use std::process::Command;
src/target/parser.rs:526:        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
src/target/parser.rs:528:        let target_list = Command::new(&rustc)
src/target/parser.rs:537:            let cfgs = Command::new(&rustc)
src/target/llvm.rs:114:    use std::process::Command;
src/target/llvm.rs:269:        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
src/target/llvm.rs:271:        let target_list = Command::new(&rustc)
src/target/llvm.rs:280:            let spec_json = Command::new(&rustc)
src/lib.rs:234:use std::process::Child;
src/lib.rs:235:use std::process::{Command, Stdio};
src/lib.rs:650:    ///     .try_flags_from_environment(concat!(env!("CARGO_PKG_NAME"), "_CFLAGS"))
src/lib.rs:2755:        let mut cmd = Command::new(prog);
src/lib.rs:3284:                    match Command::new(&name).arg("--version").status() {
src/lib.rs:3351:                                    let status = Command::new(&target_p)
src/lib.rs:3561:            // case the user did `build.target(&env::var("TARGET").unwrap())`.
```

### 文件系统（涉及 9 个文件，最多列 40 行）

```
tests/support/mod.rs:6:use std::fs::{self, File};
tests/support/mod.rs:120:        File::open(self.td.path().join(format!("out{}", i)))
dev-tools/gen-windows-sys-binding/src/main.rs:44:    let mut f = fs::File::create(format!("{manifest_dir}/../../src/windows/windows_sys.rs"))
dev-tools/gen-target-info/src/main.rs:51:    let mut f = File::create(path).expect("failed to create src/target/generated.rs");
dev-tools/cc-test/tests/output.rs:1:use std::fs;
dev-tools/cc-test/build.rs:4:use std::fs;
src/bin/cc-shim.rs:8:use std::fs::File;
src/bin/cc-shim.rs:36:    let f = File::create(&candidate).unwrap_or_else(|e| {
src/bin/cc-shim.rs:89:    File::create(path).unwrap_or_else(|e| {
src/lib.rs:230:use std::fs;
src/lib.rs:1274:            let mut f = fs::File::create(&src)?;
src/tool.rs:170:            std::fs::create_dir_all(&out_dir).map_err(|err| Error {
src/windows/find_tools.rs:266:    use std::fs::File;
src/windows/find_tools.rs:748:        let mut version_file = if let Ok(f) = File::open(&version_path) {
src/windows/find_tools.rs:771:            File::open(version_path).ok()?
```

### 外部函数（涉及 6 个文件，最多列 40 行）

```
dev-tools/gen-windows-sys-binding/src/main.rs:63:            write!(&mut f, r#"#[link(name = "{dll_name}")]"#).unwrap();
dev-tools/gen-windows-sys-binding/src/main.rs:67:        f.write_all(r#"extern "C" {}"#.as_bytes()).unwrap();
dev-tools/cc-test/tests/all.rs:3:#[link(name = "OptLinkage", kind = "static")]
dev-tools/cc-test/tests/all.rs:4:extern "C" {
dev-tools/cc-test/tests/all.rs:63:    extern "C" {
dev-tools/cc-test/src/lib.rs:1:extern "C" {
src/lib.rs:46://! extern "C" {
src/lib.rs:191://! Remember that C++ does name mangling so `extern "C"` might be required to enable Rust linker to find your functions.
src/windows/windows_link.rs:3://! This is a simple wrapper around an `extern` block with a `#[link]` attribute.
src/windows/windows_link.rs:11:        // connected to the library given in the #[link] attribute.
src/windows/windows_link.rs:12:        #[link(name = "kernel32")]
src/windows/windows_link.rs:14:            $(#[link_name=$link_name])?
src/windows/windows_sys.rs:135:#[link(name = "advapi32")]
src/windows/windows_sys.rs:136:#[link(name = "ole32")]
src/windows/windows_sys.rs:137:#[link(name = "oleaut32")]
src/windows/windows_sys.rs:138:extern "C" {}
```

### C 代码中的系统调用（涉及 0 个文件，最多列 40 行）

无

## 二进制文件扫描

```
```

## 许可证文件

```
LICENSE-APACHE
LICENSE-MIT
```

## 审查结论（人工填写）

| 项 | 结论 | 审查人 | 日期 |
|---|---|---|---|
| build.rs / 过程宏行为是否只做编译所需的事 | | | |
| 是否存在网络、进程、文件访问且非必要 | | | |
| 二进制文件是否全部为无害测试数据 | | | |
| 许可证是否兼容 MIT 项目 | | | |
| 是否同意引入 | | | |
