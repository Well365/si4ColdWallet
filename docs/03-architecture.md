# 03 · 架构

状态：P0 冻结 · 2026-10-10

## 总览

```
┌──── 签名机 iPhone ────────────────┐      动画二维码（UR）       ┌──── 观察机 iPhone ─────────────────┐
│ Signer.app (SwiftUI)              │  ←── 未签名交易 / 请求 ───  │ Watcher.app (SwiftUI)              │
│   └─ libaw_signer.a (Rust)        │  ─── 已签名交易 / 公钥 ──→  │   └─ libaw_watch.a (Rust)          │
│      种子 · 派生 · 解析 · 签名     │                            │      地址 · 构造交易 · 解析回执      │── HTTPS ─→ 节点 / RPC
│   无任何网络代码（CI 检查）         │                            │   无任何私钥类型（编译期隔离）        │
└───────────────────────────────────┘                            └────────────────────────────────────┘
```

## 仓库结构

```
airgap-wallet/
├── Cargo.toml              # Rust workspace；所有第三方依赖通过 [patch.crates-io] 指向 third_party/
├── .cargo/config.toml      # net.offline = true；crates.io 替换为空目录 core/no-registry
├── core/crates/
│   ├── aw-common/          # 秘密清零、栈清洗、最小 JSON 输出、十六进制（零依赖）
│   ├── aw-bip39/           # BIP39 自实现（官方测试向量）
│   ├── aw-keys/            # BIP32（secp256k1）/ SLIP-10（ed25519）派生
│   ├── aw-ur/              # UR：bytewords、CRC32、fountain、最小 CBOR（自实现，官方测试向量）
│   ├── aw-chain-btc/       # BTC/DOGE：PSBT 解析、显示模型、签名
│   ├── aw-chain-evm/       # ETH/BNB/EVM（P2a）：Keccak、RLP、交易审查/签名、ERC-20、EIP-191、EIP-712、eth-sign-request
│   ├── aw-chain-sol/       # SOL（P2）
│   ├── aw-chain-near/      # NEAR（P2）
│   ├── aw-chain-tron/      # TRON（P2）
│   ├── aw-ffi-common/      # 两边共用的 C ABI（缓冲区释放、动画二维码编解码）
│   ├── aw-ffi-signer/      # 签名机 C ABI（会话句柄，D16）→ staticlib
│   ├── aw-ffi-watch/       # 观察机 C ABI → staticlib（不依赖 aw-keys / aw-bip39 / 签名代码，C3 检查）
│   └── aw-e2e/             # 端到端测试：观察机 ↔ 签名机经动画二维码往返
├── core/shims/、core/stubs/ # 自写替代品（D11）与禁用桩（D12）
├── ios/
│   ├── Signer/             # Xcode 工程，零 SPM 依赖
│   ├── Watcher/            # Xcode 工程，零 SPM 依赖
│   └── Shared/             # 两边共用的二维码显示与扫描界面、C 模块映射
├── third_party/            # 上游 git 源码 + MANIFEST.toml
├── toolchain/              # 固定的安装包哈希、安装目录指纹、版本记录（D14）
├── tools/                  # aw.py + awlib/（检查 C1–C5、C9–C11）、cargo-sb（沙箱）、bootstrap / vendor / probe / repro / ios 脚本
└── docs/                   # 范围、威胁模型、规则、决策、费曼汇报
```

## 签名机与观察机的隔离

| 手段 | 作用 |
|---|---|
| 两个 FFI crate，各自只依赖需要的模块 | 观察机静态库里不会出现私钥派生/签名代码 |
| 签名相关函数放在 Cargo feature `signing` 后面，观察机不开启 | 同上，编译期保证 |
| 检查签名机二进制（C4/C5）与源码（C9/C11） | 签名机里不会出现网络代码 |
| 两个 FFI 库分开构建，C3 检查依赖图 | 防止 Cargo 合并 feature 把签名代码带进观察机（D18） |
| 两个独立 Xcode 工程、不同 Bundle ID | 不可能误把网络代码编进签名机 |

## Rust ↔ Swift 接口（手写 C ABI）

- 所有函数 `extern "C"`，参数/返回值只有整数、指针 + 长度。
- 返回的数据由 Rust 分配，Swift 用完调用 `aw_buf_free` 释放；含秘密的缓冲区释放前清零。
- 复杂结构（交易显示模型）以 JSON 字节返回：Rust 端用 `aw-common` 里的最小 JSON 写出器，Swift 端用系统 `JSONDecoder` 解析。
- 种子不以字符串形式跨越接口：秘密只存在于 Rust 的 `AwSession` 中，Swift 只持有不透明句柄；手输助记词时只传单词序号（0–2047）；每个涉及秘密的接口返回前擦除 64 KiB 栈（D16）。

## 二维码

- 生成：CoreImage `CIQRCodeGenerator`（系统）。
- 识别：AVFoundation `AVCaptureMetadataOutput`（系统）。
- 编码：UR（BTC 用 `crypto-psbt` / `crypto-account`，EVM 用 ERC-4527 `eth-sign-request`，SOL/NEAR/TRON 兼容 Keystone 的 UR 类型）。

## 数据流：一笔 BTC 转账

1. 观察机：用 xpub 算地址、查 UTXO → 构造 PSBT（含找零派生路径）→ UR 动画二维码
2. 签名机：扫码 → Rust 解析 PSBT → 校验找零属于本钱包、计算手续费 → 生成显示模型 → 用户逐项确认 → 签名 → UR 动画二维码
3. 观察机：扫码 → 合并签名 → 最终化 → 广播
