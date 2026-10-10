# 06 · P2 计划：多链（EVM / BNB、DOGE、TRON、SOL、NEAR）

状态：2026-10-10 起草 · P1 的 BTC 框架（审查 → 签名 → 观察机复核、动画二维码、C1–C11 检查）原样复用

进度：P2a 第一部分完成（见 `docs/feynman/P2a.md`）；P2b 完成（`docs/feynman/P2b.md`）；P2a 第二部分 EIP-712 完成（`docs/feynman/P2a-2.md`，决策 D29），另按用户要求加入 passphrase 模式（D30）与区块浏览器网址（D31）。

**调整（2026-10-10，用户要求）**：先做"严格的随机数生成"与"各链地址生成"（P2b，见 `docs/feynman/P2b.md`），EIP-712 暂停（严格 JSON 解析器已完成），DOGE / TRON / SOL / NEAR 的交易审查与签名顺延为 P2c–P2e。

## 拆分与顺序

按"新增审计面"从小到大推进，每个子阶段结束都有中文费曼汇报（`docs/feynman/P2a.md` …）和独立审查：

| 子阶段 | 内容 | 新引入的第三方源码 | 主要新代码 |
|---|---|---|---|
| **P2a** | ETH、BNB Chain 及其他 EVM 链（按 chain-id 区分） | Keccak-f[1600]：RustCrypto `keccak` v0.1.2（零依赖，见下） | RLP、交易解析（legacy / EIP-155 / EIP-2930 / EIP-1559）、ERC-20 识别、EIP-191 消息、EIP-712 结构化数据、通用显示模型、UR `eth-sign-request` / `eth-signature` |
| **P2b** | DOGE | 无（复用 rust-bitcoin） | 旧式 P2PKH 签名、DOGE 地址、手续费规则 |
| **P2c** | TRON | 无（复用 Keccak、secp256k1） | 最小 protobuf 解码器、TRX / TRC-20 转账、权限修改类合约一律拒签 |
| **P2d** | SOL、NEAR | Ed25519：`ed25519-compact` 2.6.0（libsodium 作者维护，关闭全部可选依赖） | SLIP-10、Solana 消息（legacy / v0）、SPL Token、NEAR borsh 交易与 actions |

## 第三方源码选择

| 需要 | 候选 | 结论 |
|---|---|---|
| Keccak-f[1600] | RustCrypto `keccak` 0.1.3 起在 aarch64 上无条件依赖 `cpufeatures`，后者在苹果平台依赖 `libc`（体量大、带 build.rs）；`tiny-keccak` 依赖 `crunchy`（build.rs 生成代码） | 取 RustCrypto `keccak` **v0.1.2**（tag `keccak-v0.1.2`，commit `b59a4d5a`）：零依赖、两个源文件；0.1.3–0.1.6 的改动只涉及新增的 ARMv8 汇编后端和新函数，纯 Rust 置换函数未变（已比对 CHANGELOG 与 diff）。Keccak-256 的海绵填充自己写（约 30 行），用以太坊公开向量 + Python 标准库 `hashlib.sha3_256`（独立实现）做差分测试 |
| Ed25519 | `ed25519-dalek`（依赖链长，含过程宏 `curve25519-dalek-derive`）、`ed25519-compact`（零必需依赖）、Monocypher（C） | `ed25519-compact` 2.6.0，`default-features = false`，开启 `self-verify`（签完自验，防故障注入）；确定性签名（RFC 8032），用 RFC 8032 官方向量与 RFC 附带的 Python 参考实现交叉核对 |

两项都按 R1 引入（上游 git 固定 commit、证明是 tag 祖先、MANIFEST 登记、review-scan 清单、两人审查后才能发布），决策写入 `docs/05`。

## 共用改造（P2a 一并完成）

1. **通用显示模型**：Rust 输出与链无关的审查结果（标题、若干"标签 / 值 / 类型（地址、金额、数据）"行、警告列表与级别），Swift 只负责渲染。BTC 审查结果也迁移到同一模型。签名机 UI 不再为每条链写一套界面，减少 Swift 侧出错面。
2. **多链账户导出**：签名机解锁后按链导出账户二维码（EVM：`m/44'/60'/0'` 的 crypto-hdkey；SOL/NEAR：各地址公钥）；观察机按链导入。
3. **危险操作**：严格按 `docs/01`「各链危险操作」表实现——"默认拒签"项在 Rust 中直接返回错误码，Swift 无法绕过；"强警告"项进入显示模型的红色警告，需要用户额外确认。
4. **观察机联网**：每条链一个最小 HTTP 客户端（JSON-RPC / REST），节点地址可配置；广播前在本机重新解析已签名交易并与审查结果比对。

## P2a 验收标准（EVM）

- Keccak：以太坊公开向量、FIPS 202 KAT（经 SHA3 填充）与 Python `hashlib` 差分测试 1000 组随机输入全部一致。
- RLP：以太坊官方 `RLPTests` 向量（编码 + 拒绝非规范编码）。
- 签名：EIP-155 官方示例交易逐字节一致；EIP-1559 交易与 go-ethereum 测试数据一致；签名可被 secp256k1 恢复出本账户地址（签完自验）。
- ERC-20：`transfer` / `approve` / `transferFrom` 解码；无限额 `approve`、`setApprovalForAll`、`permit` / Permit2 强警告；EIP-7702 授权（type 4 交易）默认拒签。
- EIP-712：自写严格 JSON 解析器（拒绝重复键、深层嵌套、超长数字）；`hashStruct` 与 EIP-712 规范示例（Mail）一致。
- 端到端：观察机构造 → `eth-sign-request` 动画二维码 → 签名机审查签名 → `eth-signature` → 观察机拼装并本地验证。
- 供应链：C1–C11 全部通过；新增第三方条目有 review-scan 清单；C6 复现。

## 需要你配合的（与 P1 相同，可并行）

两台 iPhone + 开发者账号、第二台 Mac、测试网代币（Sepolia ETH / BSC Testnet BNB 的水龙头同样需要人机验证）、第三方源码审查人。
