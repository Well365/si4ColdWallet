# 01 · 威胁模型

状态：P0 冻结 · 2026-10-10

## 要保护的东西

1. **种子 / 私钥**：泄露 = 全部资产丢失
2. **签名意图**：用户以为签 A，实际签了 B = 资产丢失
3. **构建产物完整性**：用户装上的 App 必须就是公开源码编出来的那个

## 信任边界（我们必须信任、无法消除的）

| 组件 | 为什么无法消除 | 我们做的缓解 |
|---|---|---|
| iOS 系统、Secure Enclave | 在 iPhone 上运行就必须信任 | 签名机不联网、不登录 Apple ID |
| Xcode / clang / ld / codesign | 编译 iOS App 的唯一途径 | 只从苹果官网下载并验签；锁版本 |
| Rust 官方编译器（rustc） | 自举仍依赖上一版二进制（Trusting Trust） | 锁版本；两台机器、两个网络下载后比对哈希 |
| 苹果系统框架（SwiftUI、AVFoundation、CoreImage、Security） | 同 iOS | 白名单，CI 检查只链接这些框架 |

除此以外**一切都不信任**：包仓库、第三方作者账号、我们自己的 CI、观察机、观察机连接的节点。

## 攻击者假设

- 观察机已被完全控制（可改金额、地址、交易内容、二维码内容）
- 网络 / RPC 节点会撒谎（余额、nonce、区块哈希、前序交易）
- 任一第三方依赖的发布账号会被盗，发布带合法签名/证明的恶意版本
- 我们自己某个开发者的 GitHub 账号会被盗
- 设备会被偷；攻击者有实验室级设备（故障注入、侧信道）
- 攻击者会用 AI 逐行审读我们的开源代码找漏洞

## 威胁清单与对策

| # | 威胁 | 真实案例 | 对策（在哪实现） |
|---|---|---|---|
| T1 | 随机数可预测 | Coldcard 2026-07（构建配置错误回退软件 PRNG）、Milk Sad、Profanity | 检查 `SecRandomCopyBytes` 返回值；可选骰子熵混合；启动时已知答案自检；生成后提供离线复算 |
| T2 | 依赖投毒 / 中间仓库篡改 | Trust Wallet 扩展 2025-12、@solana/web3.js 2024、TanStack 2026-05（带合法 SLSA 证明） | 第三方从上游 git 固定 commit 取源码入库；构建断网；二进制扫描；见 `02-supply-chain-policy.md` |
| T3 | 依赖里夹带预编译二进制 | serde_derive 1.0.172（2023-08） | CI 扫描 third_party/ 中所有 Mach-O/ELF/PE/静态库/wasm |
| T4 | 构建期代码执行（build.rs、过程宏） | 同 T2 | 最少化此类依赖；不用 UniFFI/serde 派生宏；构建机专用、断网 |
| T5 | 盲签 / 观察机篡改交易 | Bybit 2025、Radiant 2024、WazirX 2024 | 签名机本地完整解析；结构不合法或解析不完整即拒签；无盲签开关。能解析结构但无法识别语义的合约调用 / 结构化数据：完整显示原始内容 + 强警告 + 强制确认（决策 D25） |
| T6 | 交易解析器自身 bug | Ledger LSB-024（2026-08，计数溢出） | Rust、显式边界检查、模糊测试、Kani 证明不 panic |
| T7 | 恶意版本通过签名 nonce 泄露种子 | Dark Skippy 2024 | BTC：anti-exfil；EVM/TRON：确定性签名 + 大额双设备比对 |
| T8 | 地址投毒 / 剪贴板替换 | 2025-12 约 5000 万 USDT | 完整分组显示地址、白名单、相似地址告警、不用剪贴板 |
| T9 | 授权钓鱼 / 所有权转移 | Permit、EIP-7702、TRON 权限修改、SOL SetAuthority、NEAR AddKey | 每链"危险操作"默认拒签（见下表） |
| T10 | 种子从 UI 层泄露 | Slope 日志、SparkCat 相册 OCR、系统键盘学习 | 种子只在 Rust 内存；自带键盘；禁截屏/录屏；零日志；不用剪贴板 |
| T11 | 预签交易被延后利用 | Drift 2026-04（durable nonce） | SOL durable nonce 强警告；EVM 永远显示 nonce 与链 ID |
| T12 | 假冒 App / 假安装包 | 假 Ledger Live 2026-04、SeaFlower | 只支持自己编译安装；发布构建哈希供比对 |
| T13 | 签名机偷偷联网 | 通用手机有无线模块 | 签名机二进制不含网络符号（CI 检查）；设备流程：不登录 Apple ID、拔卡、关无线、飞行模式 |
| T14 | 设备被盗后物理提取 | TROPIC01、Tangem（2026） | 默认无状态；存储模式依赖 SE + 设备密码；passphrase 不保存；大额多签 |

## 各链"危险操作"（默认拒签或强警告）

| 链 | 默认拒签 | 强警告 |
|---|---|---|
| BTC / DOGE | 找零地址不属于本钱包；DOGE 缺前序交易 | 手续费超过付款金额 5%（全部转回自己时按全部输出计）或绝对值超过 0.001 BTC（D32）；0 聪对外输出不改变判定 |
| EVM | EIP-7702 授权；Safe `DELEGATECALL`（execTransaction / 模块入口 / `SafeTx`）、`approveHash`、恰好 32 字节的消息、对多签自身的管理调用、编码不规范或字段不全的 Safe 结构（D33） | 无限额 approve、permit/permit2、setApprovalForAll；未知合约调用；Safe 退款参数非零、模块入口、多签套多签 |
| SOL | SPL Token `SetAuthority`、System `Assign` / `AssignWithSeed`；v0 地址查找表（被引用的地址离线无法核实，D37 由强警告改为拒签）；本账户不是签名者；关联代币账户地址与推导不符 | durable nonce；未知程序；未知代币或小数位不符；代币授权；关闭代币账户；手续费超过 0.01 SOL；收款代币账户无法核对归属 |
| NEAR | `AddKey`（FullAccess）、`DeleteAccount` | 带 deposit 的 FunctionCall |
| TRON | `AccountPermissionUpdateContract` | TRC20 `approve`；fee_limit 异常 |

## 残余风险（接受并告知用户）

- iPhone 无线模块无法物理移除 → 签名机是"逻辑隔离"，大额资金应多签并把一把钥匙放在专用无射频硬件上
- 开发者证书可能需要周期性联网验证 → P1 实测，失败则进入方案评审
- 苹果与 Rust 官方工具链是信任根
