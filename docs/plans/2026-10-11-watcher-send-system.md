# 观察机"可发送的成型体系"：节点列表 + 手续费选择（2026-10-11）

> 目标：观察机（联网机）发送 BTC / EVM 时，节点可选、可加、可测；手续费（gas / 费率）可按档位选或自定义；
> 构造前核对余额；每一步的数字都来自 Rust 的检查算术。签名机不变（它只审查、只签名）。

## 现状（改之前）

| 项 | EVM | BTC |
|---|---|---|
| 节点 | 每条链 1 个内置 RPC（publicnode）+ 一个"链ID=URL"文本框 | 1 个 Esplora 地址文本框（默认 mempool.space testnet4） |
| 手续费 | 自动：优先费取节点建议值，最高单价 = 2 × 基础费 + 优先费；gas 上限固定 21 000 / 100 000 | 一个费率文本框，预填 mempool.space 的半小时档 |
| 余额核对 | 无（节点会拒，但用户看不到原因） | Rust `build_payment` 已核对 |
| 广播 | 选定节点；核对返回哈希 | 选定 Esplora |

## 任务拆分（每项可独立交接）

### T1 Rust：手续费档位与余额核对（`aw-chain-evm`、`aw-ffi-watch`）
- `uint.rs`：`div_u64`（U256 ÷ u64，长除法，除零返回 None）。
- 新模块 `fees.rs`：`tiers(FeeInput) -> Result<[Tier; 3], EvmError>`。
  - EIP-1559：输入下一区块基础费 + `eth_feeHistory` 的 reward 列（10/50/90 百分位 × N 个区块）；优先费 = 各列的中位数；最高单价 = 基础费 × {5/4, 3/2, 2} + 优先费（慢 / 标准 / 快）。
  - 旧式（无基础费）：输入 `eth_gasPrice`；三档 = 价格 × {9/10, 1, 5/4}，优先费 = 最高单价。
  - 全部检查算术；溢出返回 `Overflow`；空输入返回 `Parse`。
- `watch.rs`：`check_funds(native, token, value, gas_limit, max_fee) -> Result<bool, EvmError>`：原生币 ≥ 金额（代币转账时为 0）+ gas 上限 × 最高单价；代币转账还要代币余额 ≥ 数量。
- `review.rs`：交易显示加一行"总计最多扣除（金额 + 最高手续费）"（代币转账时为"最多扣除（仅手续费）"），审计 P1-11。
- FFI：`aw_evm_fee_tiers`（输入十六进制数量文本，输出 JSON 三档含 gwei 与最多手续费）、`aw_evm_check_funds`（余额不足返回 `AW_ERR_TX_REJECT_BASE - 19`）。头文件同步。
- 测试：单测（已知输入的档位、中位数奇偶、溢出、旧式）；e2e 显示行；FFI 往返。

### T2 Swift：节点登记簿（`ios/Watcher/Watcher/Nodes.swift`、`NodeSettingsView.swift`）
- 每个网络一组内置节点（见下表）+ 用户自定义节点；选中的节点与自定义列表以 JSON 存在 `AppStorage`。
- 节点页：单选；"测试全部"显示区块高度 / 延迟 / 链 ID 是否相符；添加（只许 https，先探测再保存）；删除自定义；选中节点落后最高区块 5 个以上时警告。
- 旧设置（`evm-rpc-overrides`、`esplora-base`）作为自定义节点一次性迁入。

### T3 Swift：EVM 发送页（`EvmViews.swift`、`EvmRPC.swift`）
- `EvmRPC` 增加 `feeHistory`、`gasPrice`、`estimateGas`、`blockNumber`。
- 发送页：手续费档位（慢 / 标准 / 快 / 自定义）+ 每档的优先费、最高单价（gwei）与"最多手续费"；自定义可填最高单价、优先费、gas 上限；代币转账 gas 上限 = 估算 × 1.2；高级：手动 nonce。
- 构造前调用 `aw_evm_check_funds`，不足则直接提示（不发给签名机）。
- 广播失败时可换节点重试。

### T4 Swift：BTC 发送页（`PayView.swift`、`Esplora.swift`、`AccountView.swift`）
- 费率档位：快（约 10 分钟）/ 标准（约 30 分钟）/ 慢（约 1 小时）/ 经济 / 自定义；mempool.space 用 `v1/fees/recommended`，其他 Esplora 用 `fee-estimates`。
- 广播后给出区块浏览器链接。

### T5 文档
- `docs/05-decisions.md` D35（中英）；`docs/00-scope.md` 观察机一行；费曼汇报 `docs/feynman/W1.md`（中英）。

## 内置节点（都是无需密钥的公共端点；用户可增删）

| 网络 | 节点 |
|---|---|
| Ethereum 主网 (1) | publicnode `https://ethereum-rpc.publicnode.com`；LlamaNodes `https://eth.llamarpc.com`；Cloudflare `https://cloudflare-eth.com`；1RPC `https://1rpc.io/eth`；dRPC `https://eth.drpc.org`；Flashbots Protect `https://rpc.flashbots.net`（只建议用来广播，防夹子） |
| BNB Smart Chain (56) | Binance `https://bsc-dataseed.binance.org`；`https://bsc-dataseed1.defibit.io`；`https://bsc-dataseed1.ninicoin.io`；publicnode `https://bsc-rpc.publicnode.com`；1RPC `https://1rpc.io/bnb`；dRPC `https://bsc.drpc.org` |
| Sepolia (11155111) | publicnode `https://ethereum-sepolia-rpc.publicnode.com`；`https://rpc.sepolia.org`；dRPC `https://sepolia.drpc.org`；1RPC `https://1rpc.io/sepolia` |
| BSC 测试网 (97) | publicnode `https://bsc-testnet-rpc.publicnode.com`；Binance `https://data-seed-prebsc-1-s1.binance.org:8545`；dRPC `https://bsc-testnet.drpc.org` |
| BTC 主网 | mempool.space `https://mempool.space/api`；Blockstream `https://blockstream.info/api` |
| BTC testnet4 | mempool.space `https://mempool.space/testnet4/api` |

## 不做 / 风险
- SOL / NEAR / TRON 的发送要等签名机实现这些链的签名（P2c / P2d）。
- 公共节点会看到查询的地址；要隐私就用自建节点（节点页可加）。
- 节点返回的余额、nonce、手续费都只用于构造；交易内容仍由签名机独立审查，"节点说谎"最多造成交易失败或多付手续费（手续费有签名机的异常告警兜底）。

## 如何继续（交接）
1. 读本文件与 `docs/05-decisions.md` D35。
2. 跑 `bash -c 'source tools/env.sh && cargo test --workspace --locked --offline'` 确认 Rust 侧绿。
3. 按 T2–T4 顺序改 Swift；真机构建用 `AW_DEVELOPMENT_TEAM=<团队> tools/ios/build-watcher.sh device`（先跑 `tools/repro/build-twice.sh`）。
4. 每个 T 单独提交；文档中英文同步。
