# 审查清单：shlex

> 自动生成于 2026-10-10。以下只列出需要人工判断的位置；**结论一栏必须由审查人填写**。

## 概况

| 项目 | 数量 |
|---|---|
| 文件总数 | 28 |
| Rust 源文件 | 8 |
| C/C++/汇编文件 | 1 |
| Cargo.toml | 5 |
| build.rs（构建期执行） | 1 |
| 过程宏 crate（构建期执行） | 0 |
| `unsafe` 出现次数 | 6 |

## 构建期会执行的代码

```
fuzz/fuzz_quote_wordexp/build.rs
```

## 需要人工看的位置

### 二进制嵌入（涉及 0 个文件，最多列 40 行）

无

### 网络（涉及 0 个文件，最多列 40 行）

无

### 进程与环境（涉及 1 个文件，最多列 40 行）

```
fuzz/fuzz_quote_real_shell/src/fuzz.rs:7:use std::process::{Command, Stdio, ChildStdin};
fuzz/fuzz_quote_real_shell/src/fuzz.rs:29:    match std::env::var(var) {
fuzz/fuzz_quote_real_shell/src/fuzz.rs:160:                                 shlex::try_quote(env!("CARGO_MANIFEST_DIR")).unwrap(),
fuzz/fuzz_quote_real_shell/src/fuzz.rs:166:        let cmd = Command::new("/bin/sh")
```

### 文件系统（涉及 0 个文件，最多列 40 行）

无

### 外部函数（涉及 1 个文件，最多列 40 行）

```
fuzz/fuzz_quote_wordexp/src/fuzz.rs:8:extern "C" {
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
