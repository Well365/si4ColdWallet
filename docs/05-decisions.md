# 05 · 架构决策记录（ADR）

每条决策：背景 → 决定 → 代价。推翻任何一条需要新增一条记录说明原因。

---

## D1 · 两个独立 App，共用 Rust 核心（2026-10-10）

- **背景**：签名机不能有网络代码，观察机不能有私钥代码。一个 App 两种模式时，靠运行时开关隔离，开关本身就是攻击面。
- **决定**：同一仓库、两个 Xcode 工程、两个 Rust 静态库；隔离在编译期完成。
- **代价**：部分 Swift UI 代码要写两份或抽到共享目录（共享目录禁止网络调用，CI 检查）。

## D2 · 手写 C ABI，不用 UniFFI（2026-10-10）

- **背景**：UniFFI 会带入数十个构建期依赖（过程宏、模板引擎、二进制解析器），这些代码在构建机上执行。
- **决定**：Rust 侧只导出少量 `extern "C"` 函数，参数为整数/指针+长度；Swift 侧手写薄封装。
- **代价**：要自己保证内存所有权正确（Rust 分配、Rust 释放）；接口数量要控制在几十个以内。

## D3 · 第三方只取上游 git 源码（2026-10-10）

- **背景**：包仓库里的发布包可以和 git 源码不一致；发布账号会被盗；SPM 包可能是预编译二进制（已核实 bdk-swift、Trust Wallet Core 均如此）。
- **决定**：见 `02-supply-chain-policy.md`：固定 commit、整树哈希、`[patch.crates-io]` 指向本地路径、Cargo 离线。
- **代价**：引入和升级依赖都是手工活；版本冲突需要人工处理。

## D4 · 签名机默认无状态（2026-10-10）

- **背景**：Secure Enclave 不支持 secp256k1 / ed25519，只能"加密保管"种子；手机被盗后的物理攻击面无法完全评估。
- **决定**：默认每次扫描 SeedQR 加载，签完清除；"存储模式"作为可选项（SE 的 P-256 密钥做 ECIES 加密，钥匙串 `ThisDeviceOnly`）。
- **代价**：每次签名要拿出 SeedQR；SeedQR 的物理保管成为关键。

## D5 · 能自己写且有官方测试向量的，自己写；密码学原语不自己写（2026-10-10）

- **自己写**：BIP39（编码 + PBKDF2 组合）、UR（bytewords、CRC32、fountain 码、最小 CBOR）、最小 JSON 输出、十六进制。
- **用上游源码**：libsecp256k1（经 rust-secp256k1）、SHA-256/SHA-512/HMAC/RIPEMD-160（rust-bitcoin 的 hashes）、ed25519（P2 评估 curve25519-dalek / ed25519-dalek 2.x）、Keccak-256（P2 评估）。
- **代价**：自写部分必须 100% 覆盖官方测试向量，并纳入外部审计范围。

## D6 · 不用 serde / JSON 库（2026-10-10）

- **背景**：serde 派生宏是构建期执行代码，且曾夹带预编译二进制（serde_derive 1.0.172）。
- **决定**：Rust 端只需"输出"JSON（显示模型），自写最小写出器；Swift 端用系统 `JSONDecoder` 解析。
- **代价**：显示模型字段变动时两端手工同步，用测试锁定格式。

## D7 · 链解析参考 Keystone，按文件拷贝而不整体依赖（2026-10-10）

- **背景**：Keystone 3 固件的 Rust 链模块（MIT）是现成的最全实现，但其 workspace 依赖 `cryptoxide` 和 Keystone 自己的 git 分叉。
- **决定**：P2 时逐个链评估，只拷贝需要的解析源码文件进 `third_party/keystone-extract/`，保留出处与许可证头，签名改走我们自己的密码学后端。
- **代价**：上游修复不会自动同步，需要定期比对。

## D8 · 许可证 MIT，不引入 GPL（2026-10-10）

- **决定**：自有代码 MIT；第三方保持原许可证；GPL 代码（Polkadot Vault、Trezor）只读参考、不拷贝。

## D9 · Xcode 工程零第三方包，二维码用系统框架（2026-10-10）

- **决定**：二维码生成用 CoreImage，识别用 AVFoundation；不引入任何 Swift 第三方库。

## D10 · 工具链装在项目专用目录（2026-10-10）

- **背景**：当前开发机是日常用机；工具链不应污染系统，也便于在第二台机器上原样复现。
- **决定**：`RUSTUP_HOME` / `CARGO_HOME` 指向 `~/.airgap-wallet-toolchain/`，不修改 shell 配置；通过 `tools/env.sh` 进入环境。
- **代价**：每次开新终端需 `source tools/env.sh`。发布构建仍必须在专用 Mac 上进行。

## D11 · 自写 `hex_lit` 替代品（2026-10-10，P1）

- **背景**：rust-bitcoin 把 `hex_lit` 声明为普通依赖。crates.io 上 hex_lit 0.1.1 的 `.cargo_vcs_info.json` 记录源码 commit `a1b61585…`，但上游仓库 Kixunil/hex_lit 只有一个 commit（0.1.0），该 commit 不存在（`git fetch` 返回 "not our ref"）。发布包无法追溯到源码。
- **决定**：按规则 R1 不使用；在 `core/shims/hex_lit` 自写同名同版本替代（编译期十六进制字面量，约 40 行，带测试），通过 `[patch.crates-io]` 替换。rust-bitcoin 只在测试/基准代码中使用该宏。
- **代价**：无实质代价。这是"发布包 ≠ 源码"风险的真实案例，写入 P1 费曼汇报。

## D12 · 可选依赖用"禁用桩"占位（2026-10-10，P1）

- **背景**：Cargo 锁文件与 feature 无关，弱依赖特性（如 `encoding?/std`）会要求可选依赖出现在锁文件中，即使从不启用。
- **决定**：对这类依赖，在 `core/stubs/<名称>` 放同名同版本的空 crate，源码只有一行 `compile_error!`。目前只有 `bitcoin-consensus-encoding` 一个。由 `tools/vendor/make-stub.sh` 生成。
- **代价**：如果将来真的需要该依赖，必须按 R1 从上游引入并删除桩。

## D13 · 签名机 FFI crate 只产出 staticlib（2026-10-10，P1）

- **背景**：同时声明 `["staticlib", "rlib"]` 时，release + LTO 构建出的静态库中 `#[no_mangle]` 导出函数全部丢失；此时"网络符号检查"会因为库里几乎没有代码而**虚假通过**。
- **决定**：只产出 `staticlib`；并新增"链接探针"（`tools/probe/`）：用 C 程序调用全部导出函数并真实链接，少一个导出就链接失败；网络符号检查改为对链接后的可执行文件执行。
- **代价**：无。教训：每个检查都要有"反向对照"，证明它能失败。

## D14 · 工具链改用官方独立安装包，不用 rustup（2026-10-10，P1）

- **背景**：安全审查一指出：rustup 会在验证完成前先运行新装的 `rustc --version`；之后的 `component add` 只按 SHA-256 清单下载；rustup 还会改写安装记录，使逐字节核对困难。
- **决定**：用 Rust 官方独立安装包（`rust-<版本>-<平台>.tar.xz` 与各 iOS 标准库包）；安装包与签名文件的 SHA-256 固定在 `toolchain/PINNED.sha256`，GPG 严格验签（GOODSIG + VALIDSIG 指定指纹，拒绝吊销/过期）；安装后目录树指纹固定在 `toolchain/INSTALLED_TREE.sha256`，每次构建前复核。删除 `rust-toolchain.toml`，工具链只经 `tools/env.sh` 进入。
- **代价**：增加编译目标或升级版本时，要手动核对并更新固定哈希。

## D15 · 检查工具用 Python 标准库重写，Rust 编译放进沙箱（2026-10-10，P1）

- **背景**：安全审查一发现原 bash 检查脚本存在正则注入、通配符遗漏、失败被 `|| true` 吞掉等多处可绕过点；安全审查二发现构建脚本可以改写仓库里的固定哈希与白名单。
- **决定**：全部检查集中到 `tools/aw.py`（实现在 `tools/awlib/`，只用标准库，`python3 -I` 隔离运行，精确字符串比较）；Rust 编译一律经 `tools/cargo-sb`（`sandbox-exec`：禁网、只能写 `target/` 与 `CARGO_HOME`、限制 ioctl / 系统服务 / 可执行程序、脱离终端）。
- **代价**：`sandbox-exec` 是 macOS 专有且已被苹果标记为弃用，但仍可用；它不是完整的安全边界（见 `docs/02`「构建时代码：信任边界」），正式发布仍需专用构建环境与多人复现。

## D16 · 签名机 FFI 用会话句柄，秘密只在 Rust 内存（2026-10-10，P1）

- **背景**：安全审查一指出旧接口让助记词和密码短语以 Swift `String`/数组形式存在，无法可靠清零，违背威胁 T10；Rust 审查发现第三方 HMAC 与 `Xpriv` 在栈上留下可恢复助记词与根私钥的残留。
- **决定**：签名机 C 接口改为"会话句柄"（ABI v2）：Swift 只传单词在词表中的序号，助记词、种子、私钥只存在于 Rust 会话里；私钥用 `SecretXpriv` 包装（释放时擦除）；每个涉及秘密的接口返回前擦除 64 KiB 栈（`scrub_stack`）。复测：所有秘密模式在栈上命中 0 次。
- **代价**：密码短语在输入框（SecureField）中仍以 Swift 字符串短暂存在，无法清零；只能尽快交给 Rust 并清零中间字节数组。

## D17 · 自己实现系统版本检查，签名机不再导入 `dlsym` / `fopen`（2026-10-10，P1；复核四后修订）

- **背景**：Swift 的 `#available` 和 SwiftUI 内联代码会调用编译器运行时（compiler-rt）的 `__isPlatformVersionAtLeast`。为兼容旧系统，它会用 `dlsym` 查找 10 个 CoreFoundation 函数并 `fopen` 读取 `SystemVersion.plist`。把部署目标提高到 iOS 26 也去不掉（已实测，已回退）。最初的做法是保留这两个导入、约束调用点参数，安全复核四用"被调函数隐式改写参数寄存器"绕过了这个约束。
- **决定**：在 `aw-ffi-common` 中用 Rust 实现 `__isPlatformVersionAtLeast`，直接调用 dyld 的 `_availability_version_check`（iOS 15 起就有，compiler-rt 在新系统上走的也是这条路）。我们的静态库在链接顺序上先于 compiler-rt，链接器就不会再拉入原实现。`dlsym`、`fopen` 因此改为一律禁止。`os_log`（SwiftUI 的运行时提示）仍是受限导入，格式串必须是允许的字面量。
- **代价**：替换了一个编译器运行时函数，行为依赖 dyld 的私有接口（与 compiler-rt 相同）；在 macOS 主机上有单元测试。

## D18 · 签名机库与观察机库分开构建，依赖图隔离纳入 C3（2026-10-10，P1）

- **背景**：两个 FFI 库在同一次 `cargo build` 中构建时，Cargo 会合并 feature，观察机库因此带入了签名代码（`aw-chain-btc` 的 `signing`），两个库的哈希也与分开构建时不同。
- **决定**：任何构建脚本都按包分别调用 Cargo；C3 用 `cargo tree` 检查：观察机依赖图中不得出现 `aw-keys`、`aw-bip39`、`signing` 特性；签名机依赖图中不得出现 `watch` 特性。观察机构建脚本另外检查静态库中没有签名相关符号。
- **代价**：构建时间略长。

## D19 · 正式构建从空 `target/` 开始，产物拷出沙箱后与 C6 结果比对（2026-10-10，P1；复核四后补充）

- **背景**：安全复核三实测：构建时代码可以替换 `target/` 中未改动 crate 的中间产物，Cargo 不会察觉，下一次构建就把篡改带进产物。
- **决定**：`tools/ios/build-*.sh` 每次先 `cargo clean`（在沙箱内执行）；构建出的静态库哈希与 `tools/repro/build-twice.sh` 记录的独立构建结果比对，不一致即失败。
- **复核四补充**：构建脚本可以留下后台进程，等检查完再改 `target/` 里的库。现在 `cargo-sb` 结束后清理会话中的残留进程，发现残留即判失败；编译完立即把库拷到沙箱写不到的 `build/lib/`，核对与链接都只用这份拷贝，链接后再核对一次（Xcode 工程的 `OTHER_LDFLAGS` 指向 `build/lib/`）。
- **代价**：每次正式构建都是全量编译（约 1–2 分钟）；代码改动后要先重新运行 `build-twice.sh`。

## D20 · 部署目标 iOS 17.0；剪贴板只在观察机使用（2026-10-10，P1）

- **决定**：两个 App 的部署目标都是 iOS 17.0（覆盖更多旧设备；提高到 26 并不能减少受限导入，见 D17）。观察机允许从剪贴板粘贴账户二维码文本（方便在模拟器与无摄像头场景导入）；签名机禁止任何剪贴板访问（C9）。
- **代价**：无。

## D21 · Keccak 用 RustCrypto `keccak` v0.1.2，海绵结构自写（2026-10-10，P2a）

- **背景**：以太坊与 TRON 需要 Keccak-256。RustCrypto `keccak` 从 0.1.3 起在 aarch64 上无条件依赖 `cpufeatures`，后者在苹果平台依赖体量很大、带 build.rs 的 `libc`；`tiny-keccak` 依赖用 build.rs 生成代码的 `crunchy`。
- **决定**：引入 `keccak` v0.1.2（tag `keccak-v0.1.2`，零依赖、无 unsafe、无 build.rs）。0.1.3–0.1.6 只新增了 ARMv8 汇编后端和新函数，纯 Rust 置换函数没有改动（已比对 CHANGELOG 与 diff）。Keccak-256 的海绵与填充自己写（约 60 行），用以太坊公开向量和 310 组与 Python `hashlib.sha3_256` 的差分测试验证（同一海绵换成 SHA3 填充）。
- **代价**：用的是较旧版本；将来若上游修正了置换函数的问题，需要按 R6 升级。

## D22 · 通用显示模型；签名机接口 v3 统一入口（2026-10-10，P2a）

- **背景**：每条链各写一套审查界面，Swift 侧容易漏显示字段，审计面也随链数线性增长。
- **决定**：Rust 生成与链无关的显示模型（标题、若干"标签 / 值 / 样式"行、分级警告），Swift 只按行渲染；BTC 审查也迁移到这个模型。签名机 C 接口升到 v3：扫到的二维码整体交给 `aw_session_review_ur` / `aw_session_sign_ur`，由 Rust 判断是 PSBT 还是 `eth-sign-request`；Swift 不再解析任何请求内容。含"高风险"警告时，界面要求用户勾选确认；Rust 也要求调用方传入"已确认"标志（`confirm_danger = 1`），否则拒签——确认要求不依赖界面代码。
- **代价**：界面表现力受限于"行"的形式；复杂结构（如 EIP-712 嵌套对象）需要在 Rust 中展平。

## D23 · EVM 请求格式与签名约定（2026-10-10，P2a）

- **决定**：
  - 请求与返回使用 ERC-4527 的 `eth-sign-request`（CBOR 标签 401）/ `eth-signature`（402），与 Keystone、MetaMask 的注册表字段一致；读取时拒绝未知键。
  - 签名哈希一律 = Keccak-256(待签字节)（消息为 EIP-191 前缀形式），所以"严格解析待签字节"就等于"显示的就是签的"。
  - 签名中的 v：旧式交易为 EIP-155 值（链 ID × 2 + 35 + recid，可能多字节），类型化交易为 yParity，消息为 27 + recid。
  - 默认拒签：无链 ID 的旧式交易、EIP-7702（类型 4）、Safe DELEGATECALL 与 `approveHash`、请求声明的链/地址/路径与实际不符。EIP-712 结构化数据在实现前一律不签。
  - ERC-20 与 ERC-721 的 `approve` / `transferFrom` 选择器相同：对代币表以外的合约，数值按"额度或 NFT 编号"显示，授权一律高风险。
  - 消息只有白名单字符（可打印 ASCII、中文与常用中文标点）才按文字显示，其余显示十六进制。
  - 观察机核对：请求号一致、签名能恢复出本账户该地址、s 为低值（EIP-2）。
- **代价**：EIP-712 推迟到 P2a 第二部分；在此之前依赖 EIP-712 的 DApp 操作（如 Permit 签名）无法使用——这本身也是高风险操作。

## D24 · 观察机显示与签名机相同的审查结果（2026-10-10，P2a）

- **决定**：观察机构造交易后，调用与签名机**同一份** Rust 审查代码生成显示模型。用户可以把两台设备上的内容逐行对照：若观察机被篡改而签名机没有，两边显示会不同。
- **代价**：观察机库体积略增（审查代码不含私钥）。

## D25 · 未知合约调用：强警告 + 强制确认，不一律拒签（2026-10-10，P2a，用户决定）

- **背景**：威胁模型 T5 写"解析不完整就拒签"，而"各链危险操作"表对 EVM 写的是"未知合约调用：强警告"，两处有张力。一律拒签更安全，但大量 DeFi 操作将无法使用。
- **决定**（用户确认）：保持强警告。签名机显示合约地址、函数选择器与调用数据，标为高风险；必须在界面勾选确认，Rust 侧同时要求"已确认"标志（D22）。T5 的"拒签"适用于**能解析但结构不合法**的数据；"无法识别语义"的合约调用与 EIP-712 结构化数据按强警告处理。
- **代价**：用户可能在确认疲劳下签下恶意调用；缓解手段是逐步扩大可识别的调用与结构化数据类型，并保持危险操作的默认拒签清单。

## D26 · Ed25519 用 `ed25519-compact` v2.4.2，不用最新版（2026-10-10，P2b）

- **背景**：Solana、NEAR 需要 Ed25519。`ed25519-dalek` 依赖链长（含过程宏 `curve25519-dalek-derive`）；`ed25519-compact`（libsodium 作者维护）关闭可选依赖后零依赖、无 build.rs，只有一处用于清零内存的 `unsafe`。
- **决定**：取 tag `2.4.2`（commit `eb269493`，2026-08-19 发布）。2.5.0 / 2.6.0 是两周前发布的，改动集中在"签名验证"的严格化与 PEM 格式，不涉及密钥生成与签名；供应链上优先选择已发布一段时间的版本。`default-features = false`。
- **约束**：该库遇到全零私钥会中止程序，`aw-keys::slip10` 在调用前先拒绝全零私钥。将来观察机需要验证 Ed25519 签名时，重新评估是否升级到带严格验证的版本（按 R6）。
- **代价**：没有用到最新的验证强化。

## D27 · 严格的熵：健康检查 + 可独立验证的纯骰子模式（2026-10-10，P2b，用户要求"严格的随机数生成机制"）

- **决定**：
  - 混合模式（默认）：系统随机数先过健康检查——不同字节值 ≤ 15 种、连续 5 个相同字节、等差数列、与本会话上一次相同，任一条件成立即拒绝生成（对真随机数，每条误报概率 < 1e-8）；再与骰子点数按 `SHA-256(标签 ‖ 系统随机数 ‖ 次数 ‖ 点数)` 混合。
  - 纯骰子模式：熵 = `SHA-256(骰子点数字符串)` 的前 16 / 32 字节，12 词至少 50 次、24 词至少 100 次（≥ 129 / 258 位），且点数须通过"像真实掷骰"检查（卡方、连续相同、周期，审查后加入）；完全不用设备随机数，用户可用 `tools/testvectors/verify_dice.py`（只用 Python 标准库）在离线电脑上复算，与 Coldcard 的做法一致。
  - 健康检查只能发现"坏掉"的随机数，不能证明随机（对 Milk Sad 类小种子伪随机数生成器无效）；真正的保障是足够多的骰子。
  - 解锁成功后会话中的助记词与 passphrase 立即清除。
  - 签名不需要随机数：ECDSA 用 RFC 6979、Ed25519 本身确定性；系统随机数只用于生成助记词和 secp256k1 上下文的侧信道防护。
- **代价**：纯骰子模式要掷 50 / 100 次骰子。

## D28 · 签名机直接显示各链收款地址（2026-10-10，P2b）

- **决定**：解锁时派生并只保存公开信息：BTC（BIP84）、EVM（m/44'/60'/0'）、DOGE（m/44'/3'/0'，测试网 m/44'/1'/0'）、TRON（m/44'/195'/0'）保存账户公钥，按需派生任意序号；Solana（m/44'/501'/i'/0'）、NEAR（m/44'/397'/i'）的 SLIP-10 路径全部强化、不能由公钥派生，解锁时预先算好前 20 个账户的公钥，派生用的私钥随即清零。地址格式与 Phantom、TronLink、NEAR 钱包等默认路径一致；每条链都由独立 Python 实现（`tools/testvectors/chain_addresses.py`）交叉核对。
- **代价**：Solana / NEAR 只能显示前 20 个账户；这些链的交易签名在 P2c / P2d 实现时再按需派生私钥。

## D29 · EIP-712 结构化签名：严格解析、完整显示、一律高风险（2026-10-10，P2a 第二部分）

- **决定**：
  - 解析比 MetaMask 更严：JSON 不允许重复键；顶层只允许四个键；每个结构体必须正好包含声明的字段；数值在声明位宽内；混合大小写的地址必须符合 EIP-55；`EIP712Domain` 只允许规范中的五个字段。
  - 域里有链 ID 而与请求不一致：拒签。域里没有链 ID：提醒"可在任何链上使用"。
  - 认得的类型给出摘要：EIP-2612 Permit、DAI 式 permit、Permit2（PermitSingle / PermitBatch / 各种 TransferFrom）、Seaport 挂单（"给出 / 收到 / 支付给别人"逐项列出，自己一项也收不到时标为钓鱼挂单）。摘要只是帮助阅读，下面逐项列出被签名的**全部字段**。
  - 按 D25，所有结构化签名（认得的和认不得的）都是高风险，必须勾选确认才签。
  - 编码与哈希与独立的纯 Python 实现（`tools/testvectors/eip712_vectors.py`）及规范示例逐字节核对。
  - 审查后加固：被签名的字段一律完整显示、不截断；单个字符串 / bytes 超过 1024 字节、personal_sign 消息超过 4096 字节拒签（看不完就是盲签）；结构体类型 ≤ 64 个、每个 ≤ 64 个字段、总共 ≤ 512 个字段（防止构造的数据让签名机长时间计算）；Seaport 摘要只给官方部署地址（1.1–1.6）且结构完全一致的订单，Permit2 摘要只给它的六种已知结构，其余按"无法识别"；字符串含换行、制表符、引号时按十六进制显示（防止伪造"另一行"）。
  - 观察机也能发起：粘贴 dApp 给出的消息或 JSON，观察机先用同一份审查代码检查，再生成二维码；签名回来后核对确实由本地址签出。
- **代价**：登录类的结构化签名也要多勾一次确认；超长的合法请求（少见）无法在本钱包签名。

## D30 · passphrase 模式：两次输入 + 预期指纹由 Rust 核对（2026-10-10，用户要求）

- **背景**：passphrase 输错不会报错，而是静默得到另一个钱包；用户可能往错误的地址收款。
- **决定**：
  - 解锁时明确选择"标准钱包 / passphrase 钱包"；passphrase 钱包必须输入两次且一致。
  - 可填写上次记录的 8 位钱包指纹。核对在 **Rust 侧**进行（`aw_session_expect_fingerprint`）：不符就拒绝解锁，清除 passphrase，**保留助记词**，用户重输 passphrase 即可，不必再输 24 个单词。
  - 含非 ASCII 字符、首尾空格、少于 8 个字符时提醒（不阻止）。
  - 解锁后每一页顶部显示"钱包类型 · 指纹"。
  - 签名机接口版本升为 4。
- **代价**：多一次输入。

## D31 · 区块浏览器网址：签名机只显示文字，观察机可点（2026-10-10，用户决定）

- **决定**：签名机地址页在地址下方显示各链区块浏览器的网址（`Text(verbatim:)`，不解析成链接、不能点击、不调用任何打开网址的接口——C9 继续禁止 `openURL`）。网址只由固定前缀与全字母数字的地址拼成。观察机的 BTC / EVM 地址下方给出可点的链接。网址表：BTC mempool.space、ETH Etherscan、BNB BscScan、SOL Solana Explorer、DOGE Blockchair（测试网没有常用浏览器，不显示）、TRON Tronscan、NEAR NearBlocks。
- **代价**：签名机上的网址要在别的设备上手动输入。

## D32 · BTC 手续费判定：5% 比例、绝对上限、转给自己同样检查、0 聪输出不改变判定（2026-10-10，审计 P0-3 与复审）

- **决定**：`aw-chain-btc` 的手续费告警按三条规则给出，命中任一条都是高风险（`Level::Danger`），FFI 必须带 `confirm_danger=1` 才会签：
  1. **比例**：`fee × 20 > 比例基数`（即超过 5%）。比例基数 = 对外付款总额；对外付款总额为 0 时（全部转回本钱包，或对外输出全是 0 聪）按全部输出总额计；基数为 0 时只要 `fee > 0` 就算超比例（手续费占 100%）。
  2. **绝对值**：`fee > HIGH_FEE_ABSOLUTE_SAT = 100 000 聪（0.001 BTC）`，与比例无关。
  3. **费率**：原有的 `HighFeeRate` 规则不变。
- **"转给自己"的判定**改为"没有任何一个对外（External）输出"，而不是"对外金额为 0"：带 0 聪对外输出的交易既不算"转给自己"，也照样进比例检查。标题"转给自己"与 `SelfTransferOnly` 告警用同一判定。
- **阈值的适用范围**：这些常量只为 BTC 主网/测试网设定。DOGE 的手续费单位与数量级完全不同（约 0.01 DOGE/kB ≈ 1 000 000 koinu），接入 DOGE 时绝对阈值必须按币种单独给出，不得复用 100 000 这个数。
- **代价**：大额自转（例如整理 UTXO）手续费只要超过输出的 5% 就要多点一次确认；高费率时段 0.001 BTC 以上的手续费也会要求确认。这是有意为之：多确认一次比少看一次便宜。
- 测试：`aw-e2e/tests/btc_roundtrip.rs`（5% 告警、自转比例、绝对上限、0 聪输出不绕过）。

## D33 · Safe 多签：内层调用同规则审查，管理调用与盲签一律拒签（2026-10-10，审计 P0-1/P0-2、复审与第二次复审）

- **背景**：Safe（原 Gnosis Safe）的签名有三条路：链上 `execTransaction`（选择器 `0x6a761202`）、模块入口 `execTransactionFromModule` / `…ReturnData`（`0x468721a7` / `0x5229073f`）、以及 EIP-712 `SafeTx` 签名（真正起授权作用的那一份）。首轮修复只拒了 `operation=1` 并显示了内层目标；复审指出仍有四条绕过：对 safeTxHash 的 personal_sign、对多签自身的管理调用、`SafeTx.data` 没有展开、退款参数被忽略。第二轮实现再经独立复审，补上了编码不规范、模块入口 `operation=0`、可打印的 32 字节消息、`baseGas` 放大器、内层 transferFrom / permit 不逐项、SafeTx 字段默认成零这几处。
- **决定**（三条路完全同一套规则，代码共用 `review::inner_call_rows` / `safe_exec_rows` / `safe_refund_rows`）：
  1. `operation ≠ 0`（DELEGATECALL）→ 拒签 `DelegateCall`。**编码不规范**的执行入口（头部不完整、地址字高位非零、偏移或长度越界）→ 拒签 `Parse`：Safe 1.3/1.4 由 solc 0.7（ABI 编码器 v1）编译，会把地址字的高位截掉照常执行，签名机不能把它当作"未知调用"放过。
  2. 内层 `approveHash(bytes32)` → 拒签 `BlindApproval`；personal_sign 的消息**恰好 32 字节一律**拒签 `BlindApproval`——不只拒"不能显示为文字"的：攻击者可以调整 SafeTx 的 `baseGas` 等自由字段把 safeTxHash 凑成全部可打印字符（约 2^45 次尝试，单张显卡几小时）。Safe 接受 eth_sign 风格的签名，这是 approveHash 的链下等价物。
  3. 内层目标是多签合约自身、且选择器属于 11 个管理函数（`enableModule`、`disableModule`、`addOwnerWithThreshold`、`removeOwner`、`swapOwner`、`changeThreshold`、`setGuard`、`setFallbackHandler`、`setModuleGuard`，以及旧版 ≤ 1.1.1 的 `changeMasterCopy`、`signMessage`）→ 拒签 `SafeAdmin`（错误码 `AW_ERR_EVM_REJECT_BASE - 17`）；对自身的其他调用保留高风险告警。选择器由单测与 keccak 计算结果比对；每一个都有端到端拒签用例。
  4. `gasPrice ≠ 0` → 显示退款 gas 单价、`safeTxGas`、`baseGas`、退款代币（ERC-20 时显示合约标签；零地址为原生币）、退款接收方（零地址时标明付给交易发起者 tx.origin）、以及"最多退款 = (safeTxGas + baseGas) × gasPrice"，并给高风险告警；`safeTxGas` 为 0 时注明实际用气不受限、该数不是上限。用 ERC-20 退款不受链上 gas 价限制，`baseGas` 可以任意放大，可以抽干该代币。
  5. 模块入口 `operation = 0` 也按同一规则展开，并标明"模块入口（不经过多签阈值）：若本账户就是模块，这笔调用会直接执行"。
  6. 内层调用数据完整显示（每行 32 字节，与消息签名一致），不截断；内层再套执行入口时递归展开，嵌套层的"多签"就是这一层的目标，深度上限 3，超过按 `TooLong` 拒签。
  7. 内层调用套用与顶层相同的识别与告警：已知代币转账/授权、`transferFrom`、EIP-2612 `permit`、DAI `permit`、Permit2 `approve`、`setApprovalForAll`、未知合约 `transfer`（高风险）、未知选择器（高风险）；行名加"内层"前缀。
  8. `SafeTx` 必须是 Safe 的完整结构：域里有 `verifyingContract`，`to / value / data / operation / safeTxGas / baseGas / gasPrice / gasToken / refundReceiver` 九个字段齐全且类型正确；缺任何一项或类型不对 → 拒签 `Parse`，不默认成零。
  9. 顶层标题为"疑似 Safe 多签执行"并显示入口名：签名机只能按选择器识别，无法核实目标合约真的是 Safe。
- **未覆盖**（明确告知）：Safe 的 4337 模块 `SafeOp`、EIP-1271 合约签名流程、其他模块的自定义入口、`SafeMessage` 类型数据。它们目前走"一切 EIP-712 结构化签名都是高风险"的通用规则（D29），不做语义解析。
- 测试：`aw-chain-evm/src/{abi,review,typed_review}.rs` 单测（选择器与 keccak 比对、畸形编码、模块入口、结构不完整）；`aw-e2e/tests/evm_roundtrip.rs::{safe_bypass_paths_are_closed, safe_second_review_gaps_are_closed}`；两个 FFI crate 各有错误码序号固定测试。

## D34 · Solana 地址支持 Ledger Live 的两种路径方案（2026-10-11，用户要求）

- **背景**：用户用 Ledger 生成的助记词恢复后，Solana 地址与 Ledger Live 里的对不上。Ledger Live 的派生表（`libs/ledger-wallet-framework/src/derivation.ts`）为 Solana 列了三种方案并全部扫描：`solanaMain` = `44'/501'`（不可迭代，只有一个）、`solanaBip44Change` = `44'/501'/<account>'/0'`、`solanaSub` = `44'/501'/<account>'`。本机原来只实现 `m/44'/501'/i'/0'`（Phantom / Solflare / Trezor / Solana CLI 默认），所以在 Ledger Live 主账户或 `solanaSub` 下建的账户看不到。
- **决定**：`aw-chain-sol` 增加 `Scheme { Phantom, LedgerLive, LedgerMain }`，三种路径全部强化；解锁时每种方案都预先派生（Phantom 与 Ledger Live 各 20 个账户，主账户 1 个），私钥随即清零。FFI `aw_session_address` 增加 `scheme` 参数（0 Phantom、1 Ledger Live、2 Ledger Live 主账户；其他链必须为 0，主账户方案 index 必须为 0），签名机地址页在选 SOL 时多一个"账户类型"选择，`chain` 字段带方案名，`note` 说明来源。默认仍是 Phantom 方案。
- **验证**：独立 Python 实现 `tools/testvectors/chain_addresses.py` 增加两种方案的向量；`aw-e2e/tests/addresses.rs`、`aw-ffi-signer` 测试与之逐字比对；越界、未知方案、其他链带非零方案均返回 `AW_ERR_BAD_ARGUMENT`。
- **未做**：Solana 交易签名（P2c）实现时，签名请求里的路径必须能表达三种方案，签名机按完整路径匹配；EVM 的 Ledger Live 方案 `m/44'/60'/N'/0/0`（第 1 个地址与本机相同，第 2 个起不同）与 MEW 旧方案 `m/44'/60'/0'/N` 暂不支持，需要时同样加"账户类型"。

## D35 · 观察机发送体系：节点登记簿、手续费档位、构造前核对余额（2026-10-11，用户要求）

- **背景**：用户要求观察机"列出发送的节点和 gas 选择，是一个可以发送的成型体系"。原来每条 EVM 链只有一个内置节点加一个"链ID=URL"文本框，手续费全自动（2 × 基础费 + 节点建议优先费、gas 上限写死 21 000 / 100 000）；比特币只有一个 Esplora 地址框和一个费率框。
- **决定**：
  1. **节点登记簿**（`ios/Watcher/Watcher/Nodes.swift`）：每个网络一组内置公共节点（无需密钥，2026-10-11 实测可用：ETH PublicNode / dRPC / Flashbots Protect（标为"建议只用于广播"）；BSC BNB Chain 官方 / Defibit / Ninicoin / PublicNode / dRPC；Sepolia PublicNode / dRPC；BSC 测试网 PublicNode / BNB Chain 官方 / dRPC；BTC mempool.space / Blockstream；testnet4 mempool.space）+ 用户添加的节点（只许 https、不许带用户名密码，添加前先体检）。节点页逐个体检：EVM 核对链 ID 并取区块高度与延迟，Esplora 核对创世区块（主网 / testnet4）并取区块高度；比最高的落后 5 个区块以上标橙色。旧设置一次性迁入。
  2. **广播可另选节点**：签名回来后可以选任何一个节点广播，失败可换节点重试；广播前再核对一次链 ID / 创世区块；EVM 仍核对节点返回的交易哈希。
  3. **EVM 手续费三档**（Rust `aw-chain-evm::fees`，FFI `aw_evm_fee_tiers`，全部检查算术）：取 `eth_feeHistory`（10 个区块，10/50/90 百分位优先费）与 `eth_maxPriorityFeePerGas`；慢 = 基础费 × 5/4 + p10 中位数（不超过标准档）、标准 = 基础费 × 3/2 + max(p50 中位数, 节点建议值)、快 = 基础费 × 2 + max(p90 中位数, 标准档)；中位数偶数个取较高者；基础费与慢档优先费都为 0（BNB 链）时慢档取标准档；全为 0 报错。节点不支持 `eth_feeHistory` 时退回最新区块基础费 + 节点建议值；没有基础费的链按 `eth_gasPrice` × 1、5/4、3/2。另可"自定义"（最高单价、优先费，gwei，由 Rust 解析，优先费不得高于最高单价）。
  4. **gas 上限**：转给普通地址的原生币转账用 21 000；代币或合约按 `eth_estimateGas` × 1.2；估算失败用默认值并提示；可以手填。
  5. **构造前核对余额**（Rust `watch::check_funds`，FFI `aw_evm_check_funds`）：原生币 ≥ 金额（原生币转账时）+ gas 上限 × 最高单价；代币转账还要代币余额 ≥ 数量。不够就不生成签名请求，直接说明差在哪（`AW_ERR_TX_REJECT_BASE - 19 / - 21`）。
  6. **显示"总计最多扣除"**（审计 P1-11）：签名机与观察机的交易显示都加一行"总计最多扣除（金额 + 最高手续费）"，代币转账为"最多扣除（仅手续费）"——金额与手续费分行，另给总数，不会把 gas 当成金额。
  7. **比特币费率档位**：mempool.space 用 `v1/fees/recommended`（快 / 标准 / 慢 / 经济），其他 Esplora 用 `fee-estimates`（1 / 3 / 6 / 144 个区块），一律向上取整到整数 sat/vB 且至少 1；可自定义。构造后显示实际手续费、交易大小与"总计扣除"。
  8. 手动 nonce（替换或加速卡住的交易）放在"高级"里。
- **安全边界**：节点仍然不可信——它给的余额、nonce、手续费只用于构造与提示；交易内容（含手续费）由签名机独立审查，单价、优先费、手续费占比异常有告警，"总计最多扣除"给出最坏情况。公共节点能看到查询的地址，要隐私就加自建节点。
- **ABI**：`aw-ffi-watch` 加两个函数，ABI 版本 3 → 4；`aw-ffi-signer` 的 `aw_session_address` 在 D34 增加了 `scheme` 参数，ABI 版本 4 → 5（Swift 侧同步）。
- **未做**：SOL / NEAR / TRON 的发送要等签名机实现这些链的签名（P2c / P2d）；EIP-1559 以外的旧式交易格式（观察机只构造 type-2 交易）；多节点交叉核对余额（目前单节点 + 用户可手动换节点对照）。

## D36 · 签名机产物检查接受 Xcode 27 / Swift 6.3 的新符号（2026-10-11，用户决定：审查后加白名单）

- **背景**：用 Xcode 27.0 构建时，签名机的 C4/C5 产物检查失败（审计 P1-7）：48 个导入不在白名单、`__TEXT` 中出现新节 `__swift_as_cont`、自动链接了 `libswiftCoreLocation.dylib`。用户选择逐项审查后加入白名单，而不是改装 Xcode 26.6。
- **审查结论**（来源库用 `xcrun dyld_info -imports` 逐个核对）：
  - libswiftCore 的 30 个：按寄存器拆分的 `swift_retain_xN` / `swift_release_xN`（编译器优化，语义同 retain/release）、访问独占检查 `swift_beginAccess/endAccess`、`swift_initStackObject`、`swift_getExistentialTypeMetadata`、`()` 的值见证表。
  - SwiftUI 的 15 个：新 SDK 中 `@State` 的实现 `LazyState`，以及 `Binding / ForEach / Section / EmptyView` 的元数据与构造函数（3 个为弱导入）。
  - libSystem 的 `___chkstk_darwin`：大栈帧的栈探测。
  - `__swift_FORCE_LOAD_$_swiftCoreLocation` 与 `libswiftCoreLocation.dylib`（弱链接）：Xcode 27 SDK 中 SwiftUI 传递导入 CoreLocation，Swift 自动链接其覆盖层。签名机二进制中没有任何 CoreLocation API，Info.plist 没有定位权限键，系统不会给它定位能力。
  - `__swift_as_cont`：与已允许的 `__swift_as_entry` / `__swift_as_ret` 结构相同（节属性 0、32 位相对指针），是异步函数续体表，不是代码。
  - 以上都不含网络、剪贴板、动态加载等禁用能力；禁用符号与子串规则不变。
- **新增检查**：`__swift_as_entry / __swift_as_ret / __swift_as_cont` 必须是长度为 4 的倍数的相对指针表，每一项都指向 `__text` 内部（防止借这些"白名单节"夹带数据或指向别处）。用篡改过一项的副本验证过会报错。
- **结果**：Xcode 27 构建的真机签名机 C4/C5 全部通过（799 个导入、27 个链接库）。
- **代价**：白名单随工具链变大；`TOOLCHAIN.lock` 仍写着 Xcode 26.6，版本强制检查（审计 P1-7 的另一半）仍未做——换 Xcode 版本时需要重新审查新增符号。

## D37 · Solana 交易审查与签名（2026-10-11，P2c）

- **范围**：SOL 转账与 SPL 代币（含 Token-2022）`TransferChecked`；签名机支持 D34 的三种派生方案；观察机构造、核对、广播。链下消息签名暂不支持（拒签）。
- **消息解析**：legacy 与 v0；紧凑长度只接受最短编码；头部、重复账户、程序序号、账户序号、总长（≤ 1232 字节）与 Solana 节点同样检查；独立 Python 实现生成 600 条差分向量逐条一致。
- **默认拒签**：无法严格解析；v0 地址查找表（被引用的地址离线无法核实——威胁模型原为强警告，此处改为拒签）；本账户不是签名者；System `Assign` / `AssignWithSeed`；SPL `SetAuthority`；"按需创建关联代币账户"指令里的账户地址与 (钱包, 代币程序, mint) 推导不符；ComputeBudget 指令重复或不认识。
- **强警告**：未知程序；未知代币、小数位与已知代币不符；代币授权；关闭代币账户（押金退给别人时）；durable nonce；`CreateAccount` 归属未知程序；不常见的系统 / 代币指令；最高手续费超过 0.01 SOL。
- **收款人核对**：观察机发代币时总是带上"按需创建收款方关联代币账户"（已存在时不做任何事），签名机从中取出收款钱包，用 PDA 推导核对它确实是收款代币账户的主人，才显示"收款人（已核对归属）"；没有这条指令时只显示代币账户地址并提醒无法核对。PDA 的"不在曲线上"判断借用 ed25519-compact 的公开校验；推导与独立 Python 实现 60 组向量一致。
- **手续费**：5000 lamports × 签名数 + ⌈计算单元价格 × 上限 / 10⁶⌉，没有设置上限时按每条指令 20 万、最多 140 万；显示"最高手续费"（单独样式）、"总计最多扣除（金额 + 最高手续费）"与可能的建账户押金。观察机的优先费三档取 `getRecentPrioritizationFees` 的 25 / 50 / 75 百分位，标准档至少 1000、快档至少标准档 2 倍、都不超过 10⁷ 微 lamports；可自定义。构造前核对余额。
- **签名**：会话只保存 m/44'/501' 节点，签名时临时派生子节点；Ed25519 确定性签名，签完自验；与 RFC 8032 官方向量一致。签名机核对请求声明的地址就是路径派生出的地址（账户类型或序号选错会拒签，错误码 `AW_ERR_SOL_REJECT_BASE - 9`）。
- **观察机**：导入时扫签名机地址页的二维码并选同样的账户类型与序号；节点登记簿按创世区块哈希核对主网 / devnet；广播后核对节点返回的签名就是这笔交易的签名。
- **错误码**：`AW_ERR_SOL_REJECT_BASE = -400`，序号 1–12 在两个 FFI crate 中由测试固定；观察机 ABI 4 → 5。
- **独立复审后的修改**（复审结论 BLOCK：2 HIGH、2 MEDIUM、6 LOW 与 17 处测试缺口，全部处理）：
  - 指令数据按前缀解析（节点会忽略多余字节），多余字节给提醒；没有完全解析、又用到本账户的指令（未知程序、少见的系统 / 代币指令）会把"最多扣除"标成"无法确定"并给高风险告警，同时列出它用到的全部账户。
  - System `Allocate` / `AllocateWithSeed` 作用于本账户 → 拒签（新错误码 13：账户带上数据后 SOL 再也转不出去）。
  - "是否在曲线上"改为与 Solana（curve25519-dalek）完全相同的语义（忽略符号位、y 按模 p），独立实现同步修正，并加 50 个边界向量。
  - 手续费计入预编译签名程序（Ed25519 / Secp256k1 / Secp256r1）的签名数；Token-2022 账户押金单独计；本账户不付手续费时总额不含手续费；押金计入"总计最多扣除"。
  - 每笔交易都提醒"签名机无法判断主网还是测试网，请核对最近区块哈希"；观察机切换网络或查询失败时清空旧余额。
  - 新增真实主网数据：8 笔真实交易（legacy 与 v0）的解析结果与节点一致，21 个真实关联代币账户的推导与链上一致。主网已出现 v1 版本交易，本解析器一律拒绝（安全方向）。
  - 已知局限：ed25519-compact 的 `KeyPair::from_seed` 会复制一份私钥种子到它自己的结构里，无法从外部清零；由 FFI 层每次签名后的栈清理兜底。
- **未做**：链下消息签名、多签名者交易、地址查找表、v1 交易、质押与 dApp 交易；devnet 以外的测试网；真机上的实际广播（需要 devnet 测试币）。

## D38 · App 图标：si4 家族风格，按哈希登记的 PNG（2026-10-11，用户要求）

- **设计**：沿用 Si4iMsg 的风格——绿色方底（#2E7F47）、45° 斜放的蓝 / 浅绿双色胶囊；胶囊从中间断开，留出一道"空气间隙"（air gap），中间放白色图形：签名机是挂锁，观察机是眼睛（只看不签）。不含任何商标或他人标志。
- **规格**：1024×1024、不透明 sRGB PNG（无 alpha、无预先圆角），由 `tools/ios/make_icons.swift`（纯文本源码，CoreGraphics 绘制）生成；Xcode 从这一张生成各尺寸。
- **供应链规则的例外**：C2 原本只允许 third_party 下登记的测试数据是二进制。现在另外允许 `ios/<App>/<App>/Assets.xcassets/<名>.appiconset/<名>.png`，条件是文件头为 PNG、并在 `third_party/BINARY_ALLOWLIST` 按 SHA-256 登记；改图标必须重新生成并更新登记的哈希。
- **代价**：仓库里多了两个二进制文件；它们只是图像，不参与 Rust 构建，也不影响签名机的产物检查（C4/C5 通过）。

## D39 · 签名机本机保存钱包：6 位解锁密码，输错一次就清除（2026-10-11，用户要求）

- **背景**：原来签名机完全无状态（D4），每次打开都要重新输入 12/24 个助记词，太难用。用户要求：重新启动必须输入密码；密码只要错一次，就把本机保存的钱包清除。
- **用户的选择**：密码是 6 位数字（App 自带数字键盘，不经过系统键盘）；App 每次启动、每次切到后台再回来都要输入；passphrase 是否一起保存由用户在设置密码时决定（不保存的话，输完密码再输一次 passphrase）。
- **加密方式**（`ios/Signer/Signer/WalletVault.swift`）：
  - Secure Enclave 里生成一把 P-256 密钥，不可导出、只属于这台手机；钥匙串里只存它的加密句柄。
  - 每次保存生成一个临时 P-256 密钥，与 Secure Enclave 密钥做 ECDH；用 HKDF-SHA256 混入 16 字节随机盐与 PIN，得到 256 位密钥；AES-256-GCM 加密，附加数据是格式标识。
  - 加密的内容：单词序号、网络、钱包指纹、（用户选择时）passphrase。助记词原文不出现在 Swift 里。
  - 两个钥匙串项都是"设置了锁屏密码时才可用、仅本机"（`WhenPasscodeSetThisDeviceOnly`），不进 iCloud 备份与同步；手机取消锁屏密码时系统会删除它们。
- **输错一次就清除**：解密失败（GCM 校验不过）一律当作密码错误，立即删除两个钥匙串项；句柄删掉后那把 Secure Enclave 密钥再也用不到。界面提示"本机钱包已清除，请用助记词恢复"。passphrase 输错不清除：用保存的指纹核对，对不上就让用户重输。
- **锁定**：App 一进入后台就丢弃会话（Rust 侧清零密钥），回来要重新输入密码；还在设置密码那一页时进入后台，也丢弃已解锁的会话。
- **可以不保存**：设置密码页有"不保存，下次重新输入助记词"，保留原来的无状态用法；钱包页可以"从本机删除保存的钱包"；解锁页有"忘记密码"（清除后用助记词恢复）。
- **签名机产物检查**：新增 CryptoKit（Secure Enclave、HKDF、AES-GCM）、钥匙串 `SecItem*` 与新界面用到的 SwiftUI 符号，逐项审查后加入 `tools/checks/signer-imports.allow`；链接库白名单加入 `CryptoKit.framework`。均不涉及网络、文件、剪贴板、日志。
- **代价 / 残余风险**：
  - 6 位数字只有一百万种。"输错一次就清除"只在 App 里生效：能在这台手机上执行任意代码的攻击者（越狱、系统漏洞）可以先复制钥匙串里的密文与句柄，再借 Secure Enclave 逐个试密码（ECDH 没有次数限制）。所以真正的屏障是手机锁屏密码与系统完整性，与 D4 的"存储模式依赖 SE + 设备密码"一致。
  - 选择同时保存 passphrase，就等于去掉了 passphrase 的"第二道锁"：拿到手机且破解了上面那一层的人可以直接得到 passphrase 钱包。大额资产建议不保存 passphrase。
  - 密码与 passphrase 在 Swift 里是普通字符串，无法保证从内存中清零（与原来 passphrase 输入框相同）。
  - 模拟器没有 Secure Enclave，只能验证界面流程（保存失败会提示）；保存、解锁、输错清除必须在真机上验证。
