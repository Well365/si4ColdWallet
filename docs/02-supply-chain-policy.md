# 02 · 供应链规则（强制）

状态：P0 冻结 · 2026-10-10；P1 安全审查三轮后修订 · 2026-10-10 · 任何例外都要写进 `docs/05-decisions.md` 并经两人同意

## 核心原则

> **进入 App 的每一行代码，都必须以源码形式存在于本仓库，并能追溯到上游 git 仓库的某个固定 commit。构建过程不访问任何网络。**

"开源库"通过包仓库（crates.io、SPM、CocoaPods、npm）下载下来的，是**发布包**，不一定等于它的 git 源码。我们不用发布包，只用上游 git 源码。

## R1 · 第三方代码的引入

1. 只能从**上游官方 git 仓库**取源码，固定到一个 **commit 哈希**，并证明该 commit 是某个上游 tag 或分支的祖先（防止取到 fork 网络里的同名 commit）。
2. 用 `tools/vendor/import.sh`（内部调用 `aw.py import`）导出：`git archive`，并覆盖仓库内 `.gitattributes`（禁止 export-ignore、eol、ident 等改写字节），去掉 `.git`。
3. 在 `third_party/MANIFEST.toml` 登记：名称、上游 URL、ref、commit、许可证、导出路径、目录树指纹（NUL 分隔，含文件模式、空目录、符号链接）、引入日期、审查人。
4. 引入前必须人工审查（`tools/vendor/review-scan.sh` 生成完整清单，不截断）：
   - 构建时会执行的代码：`build.rs`（含自定义 `build = "..."`）、过程宏、build-dependencies
   - 二进制嵌入：`include_bytes!`、`include!`、`#[path]`
   - 网络、文件系统、进程、`dlsym`、`extern {}`、内联汇编
5. **默认不引入**；能用 ≤200 行自己写清楚、且有官方测试向量可验证的（如 BIP39、bytewords、喷泉码），自己写。
6. **密码学底层原语不自己写**（椭圆曲线、哈希、HMAC）：用经过长期审查的上游源码（libsecp256k1、rust-bitcoin hashes）。
7. 发布前，每个条目要有两名审查人和 `third_party/REVIEW/<名称>.md` 中"同意"的结论（`verify-third-party --release` 强制）。

## R2 · 构建

1. **Cargo 只能看到仓库**：`.cargo/config.toml` 设 `net.offline = true`，并把 crates.io 替换为空目录 `core/no-registry`；所有依赖通过 `[patch.crates-io]` 指向 `third_party/` 或 `core/`。该文件的 SHA-256 固定在 `tools/awlib/cargo_checks.py`；仓库中不得有其他 `.cargo/` 目录，上级目录与 `CARGO_HOME` 中不得有任何 Cargo 配置。
2. 构建命令一律带 `--locked`；先 `source tools/env.sh`：清空所有可能改变 Cargo / rustc / 编译器 / 链接器 / Xcode 行为的环境变量，固定 PATH、时间戳、路径映射。
3. **Rust 编译一律经 `tools/cargo-sb`**（macOS 沙箱）：禁网；只能写 `target/` 与 `CARGO_HOME`；禁止 ioctl、向其他进程发信号；只能查找少数系统服务；只能执行工具链、Xcode 与 `target/` 中的程序；在新会话中运行，没有控制终端；结束后会话中若还有残留进程，全部强制结束并判构建失败（`tools/sb-session.py`）。
4. **正式构建从空的 `target/` 开始**（`tools/ios/build-*.sh` 先 `cargo clean`）。编译完立即把静态库拷到沙箱写不到的 `build/lib/`，之后的哈希核对（与 C6 独立构建结果比对）和 Xcode 链接都只用这份拷贝，链接后再核对一次。
5. 签名机库与观察机库**必须分开构建**（Cargo 会合并同一次构建中各包的 feature，见决策 D1、C3）。
6. Xcode 工程：**零 Swift Package 依赖**、零 CocoaPods、零脚本阶段；以显式 `.a` 路径链接 Rust 静态库；`xcodebuild` 在 `env -i` 下运行，构建前后核对实际生效的 `OTHER_LDFLAGS`。
7. 发布构建在专用 Mac（或专用虚拟机、专用用户）上进行：不装 IDE 扩展、不放钱包、构建时断网。

### 构建时代码：信任边界

`build.rs` 和它们的 build-dependencies 会在构建机上以当前用户身份运行。目前只有：

| 构建时代码 | 作用 |
|---|---|
| `third_party/rust-secp256k1/secp256k1-sys/build.rs`（经 cc-rs、shlex） | 编译 libsecp256k1 的 C 源码 |
| `third_party/rust-bitcoin/bitcoin/build.rs`、`.../io/build.rs` | 只运行 `$RUSTC --version` |

这个集合固定在 `tools/awlib/cargo_checks.py` 的 `BUILD_TIME_CODE`（C3），增减都会失败。**沙箱只是缩小它们能做的事，不是完整的安全边界**：同一次构建中，构建时代码仍可改写 `target/` 里其他 crate 的中间产物（安全复核三实测）。所以构建时代码必须经过人工审查，且正式发布要在专用构建环境中做，并由多人在不同机器上复现（R5）。

## R3 · 自动检查（任何一项失败即阻断）

全部由 `tools/aw.py`（实现在 `tools/awlib/`；只用 Python 标准库，`python3 -I` 隔离模式）和少量脚本实现，`tools/checks/run-all.sh` 统一运行：
`--source-only` 只查源码；`--artifacts <产物…>` 加查产物；`--release` 再加联网核对上游、C7、Xcode 完整签名校验。

| 检查 | 命令 | 内容 |
|---|---|---|
| C1 来源一致性 | `aw.py verify-third-party [--release]` | `third_party/` 每个条目（含隐藏目录）都在 MANIFEST 登记、指纹一致；`--release` 时要求两人审查且结论为"同意" |
| C2 二进制扫描 | `aw.py scan-binaries` | 遍历整个仓库（不依赖 git），任何非文本文件都必须按"路径 + SHA-256"登记在 `BINARY_ALLOWLIST`，且只能位于第三方的测试/数据/图片目录；拒绝嵌套 `.git`、gitlink |
| C3 依赖来源 | `aw.py check-cargo` | Cargo 解析出的每个包、每个目标源码都在仓库 `core/` 或 `third_party/` 下；配置文件与环境未被篡改；构建时代码集合不变；签名机/观察机依赖图隔离 |
| C4 签名机无网络 | `aw.py check-binary` | 见下方"C4 做什么、不做什么" |
| C5 框架白名单 | 同上 | `otool -L` 只允许 `signer-libs.allow` 中的系统框架 |
| C6 可复现 | `tools/repro/build-twice.sh` | 两个不同路径（单机）/ 不同机器各自从零构建，四个 Rust 静态库 SHA-256 必须一致；结果记入 `build/repro/c6.sha256`，正式构建与之比对 |
| C7 C 库核对 | `tools/vendor/verify-libsecp256k1.sh` | rust-secp256k1 内附的 libsecp256k1 = 固定的上游 commit + 固定哈希的公开补丁，逐文件一致（需联网） |
| C8 链接探针 | `tools/probe/link-probe.sh` | C 程序调用全部导出接口并真实链接（-dead_strip），对产物执行 C4/C5，并在 iOS 模拟器中运行自检 |
| C9 iOS 源码 | `aw.py check-ios-sources` | `ios/` 中只允许 Swift 源码与少数工程文件（Xcode 同步文件夹会自动编译放进去的任何 C/ObjC/C++ 文件）；签名机 Swift 源码不得使用网络、剪贴板、日志、文件等禁用 API（按标识符边界匹配）；Xcode 工程不得有脚本阶段、包引用；`ios/` 下不得有全局可写目录 |
| C10 禁用桩 | `aw.py check-stubs` | `core/stubs/` 中每个禁用桩与标准模板逐字节一致（只有 `compile_error!`） |
| C11 汇编与自定义段 | `aw.py check-asm` | 会编进 App 的源码（Rust、C/ObjC/C++ 全部扩展名、Swift）中不得有内联汇编、汇编文件、自定义段、裸函数、`@_silgen_name` 等；扫描范围与两个 App 的实际依赖图（`cargo tree`）核对，新引入的第三方漏扫即失败；登记在 `asm.allow` 的例外按 SHA-256 固定（目前 4 个，均不会为 aarch64 编译） |
| 上游核对 | `aw.py verify-upstream` | 重新从上游取每个 commit，确认本地源码与上游逐字节一致（`--release` 时执行，需联网） |

每项检查都必须有"反向对照"记录：人为制造违规，证明检查会失败（见 P1 费曼汇报）。

### C4 做什么、不做什么

C4 对链接后的可执行文件做静态检查，是**纵深防御，不是证明**：

- 导入符号必须全部在 `signer-imports.allow` 白名单内；网络类符号（socket、connect、getaddrinfo、URLSession、Network.framework 等）一律禁止。
- `dlsym`、`dlopen`、`fopen` 一律禁止。Swift `#available` 需要的系统版本检查由我们自己的 Rust 实现提供（直接调用 dyld 的 `_availability_version_check`），编译器运行时里那份会用 dlsym 的实现因此不会被链接进来（决策 D17）。
- `os_log` 是唯一的受限导入（来自 SwiftUI 内联代码）：每个调用点的格式串必须由一条字符串字面量装载指令确定且在允许集合内，装载与调用之间不得有改写、跳入，也不得有任何调用或跳转（被调函数会隐式改写参数寄存器）；它在 dyld 绑定表中只能出现在 GOT 槽位、只出现一次（数据区不得藏函数指针）。
- 按原始字节扫描所有代码节：不得有 `svc/hvc/smc`（绕过 libSystem 的直接系统调用）；直接跳转只能落在代码节内。
- `__TEXT` 的非代码节同样可执行：扫描其中 Darwin 常用的系统调用编码（`svc #0x80`、`svc #0`），以及紧跟在"设置 x16"指令之后的任何 `svc`。普通数据偶尔会恰好符合 `svc` 的编码掩码（签名机实测 11 处），所以这只是启发式。
- `__TEXT` 段只允许标准节；`__TEXT` 以外的段不得有执行权限。

**静态检查无法排除的**：把只读数据（如 `__TEXT,__const`）当作代码间接调用，或通过合法导入函数的地址推算出其他函数地址。C11 只能拦截"产生或放置机器码"的语法（内联汇编、自定义段等），拦不住"一个普通常量数组 + 一次指针转换"这种写法，所以这类情况**只能靠人工审查**发现；运行时由 iOS 本身的隔离（飞行模式、不插卡、不连 Wi-Fi、不登录 Apple ID，见 `docs/04`）兜底。

## R4 · 工具链

- Rust 用官方**独立安装包**（不用 rustup），装在项目专用目录 `~/.airgap-wallet-toolchain/v2`，不改系统、不改 shell 配置（决策 D10、D14）。
- 安装包与签名文件的 SHA-256 固定在 `toolchain/PINNED.sha256`；签名用 Rust 官方 GPG 公钥严格校验（必须 GOODSIG + VALIDSIG 指定指纹，不接受吊销/过期/错误签名）。
- 安装后的目录树指纹固定在 `toolchain/INSTALLED_TREE.sha256`，每次构建前复核（`tools/bootstrap/verify-toolchain.sh`）。
- Xcode：构建前核对 Apple 签名链与 Gatekeeper；`--release` 时做完整签名校验。

## R5 · 代码托管与发布

- 所有提交签名；`main` 受保护，合并需两人审查；账号用硬件密钥做两步验证。
- CI 不持有任何发布密钥。
- 发布 = 至少 3 人在各自机器独立复现 → 各自签名构建哈希 → 达到阈值才公布。

## R6 · 依赖升级

- 升级 = 新的一次引入：重新走 R1，审查 `git diff <旧commit> <新commit>`，记录审查结论。
- 不跟风升级；只有安全公告或功能必需才升级。
