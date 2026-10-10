# P2c：Solana 交易审查与签名（2026-10-11 起）

> 目标：观察机构造 SOL / SPL 代币转账 → `sol-sign-request` 动画二维码 → 签名机重新解析、完整显示、按规则拒签或强警告 → Ed25519 签名 → `sol-signature` → 观察机核对签名、拼出交易、广播。三种派生方案（D34）全部支持。
> 参考：`~/Documents/github_src` 下的 AirGap Vault / Wallet 不支持 Solana，没有可参考的链逻辑；只在交互流程上看设计，不拷贝任何代码（用户要求，且不确定其安全性）。

## 规则（写进 D37）

| 类别 | 内容 |
|---|---|
| 默认拒签 | 无法完整解析的消息；v0 消息里的地址查找表（离线无法核实被引用的地址）；签名者不是本账户；System `Assign`、`AssignWithSeed`；SPL Token / Token-2022 `SetAuthority`；本账户需要签名的位置不止一个 |
| 强警告（需确认） | 未知程序；SPL `Approve` / `ApproveChecked`；`CloseAccount`；durable nonce（`AdvanceNonceAccount`）；System `CreateAccount`；未知代币 mint；优先费过高；手续费付款人不是本账户 |
| 显示 | 每条指令逐项显示（程序、动作、金额、收款人）；手续费 = 5000 lamports × 签名数 + 计算单元价格 × 上限 / 10⁶；"总计最多扣除（金额 + 手续费）"；最近区块哈希 |

## 任务拆分（每项可独立交接，每项单独提交）

### T1 Rust：消息解析（`aw-chain-sol/src/message.rs`）
- legacy 与 v0（前缀 0x80）消息：头部三个计数、紧凑长度（shortvec，拒绝非最短编码）、账户、最近区块哈希、指令（程序序号、账户序号、数据），v0 的地址查找表段。
- 严格：序号越界、计数不一致、多余字节、超长（> 1232 字节，Solana 包大小上限）一律 `Parse`。
- 测试：手写已知消息的逐字节解析；Python 独立实现（`tools/testvectors/sol_message.py`）对照；模糊式随机截断不 panic。

### T2 Rust：指令识别与审查（`aw-chain-sol/src/review.rs`）
- System：Transfer、TransferWithSeed、CreateAccount、Assign（拒）、AdvanceNonceAccount（警告）。
- SPL Token / Token-2022：Transfer、TransferChecked、Approve(Checked)（警告）、SetAuthority（拒）、CloseAccount（警告）、InitializeAccount。
- Associated Token Account：Create / CreateIdempotent。
- ComputeBudget：SetComputeUnitLimit / SetComputeUnitPrice（进入手续费计算）。
- Memo：按文字显示（`as_text` 白名单）。
- 已知代币表（USDC、USDT 主网 mint，6 位小数）。
- 生成通用显示模型（`aw_common::display`）。

### T3 Rust：签名与 UR
- `aw-chain-sol/src/request.rs`：`sol-sign-request`（1 请求号、2 待签字节、3 派生路径、4 地址、5 来源、6 类型：1 交易 / 2 消息）与 `sol-signature`（1 请求号、2 签名 64 字节），与 Keystone 注册表一致；严格读取。
- `aw-chain-sol/src/sign.rs`（feature `signing`）：路径必须是 D34 三种方案之一，派生出的公钥必须是消息里的签名者；Ed25519 确定性签名，签完自验。
- `aw-chain-sol/src/watch.rs`（feature `watch`）：构造 SOL 转账、SPL TransferChecked（含按需创建收款方 ATA）、ComputeBudget；核对签名并拼出交易（shortvec 签名数 + 签名 + 消息）。
- FFI：签名机 `aw_session_review_ur / aw_session_sign_ur` 识别 `sol-sign-request`；导出 Solana 账户（每种方案的公钥）；观察机 `aw_sol_*`。

### T4 Swift
- 签名机：导出 Solana 账户二维码（选方案）；审查页沿用通用显示。
- 观察机：Solana 标签页（导入、余额、SPL 余额、节点登记簿：`api.mainnet-beta.solana.com`、PublicNode；devnet），发送页（优先费档位来自 `getRecentPrioritizationFees`，余额核对），广播并核对返回的签名。

### T5 文档与验证
- D37（中英）、威胁模型 SOL 行、费曼汇报 P2c（中英）、PlantUML 进度。
- 端到端测试（aw-e2e）：观察机构造 → 二维码 → 签名机审查签名 → 观察机拼装并验证签名。
- 独立复审（代理）后再提交最终版。

## 如何继续（交接）
1. 读本文件、`docs/05-decisions.md` D34–D36。
2. `bash -c 'source tools/env.sh && cargo test --workspace --locked --offline'` 确认绿。
3. 按 T1 → T5 顺序做；每个 T 先写失败测试再实现，单独提交。
