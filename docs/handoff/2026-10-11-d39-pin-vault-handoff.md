# 交接：D39 签名机本机保存钱包 + 6 位解锁密码（2026-10-11）

给接手的人或 AI：先读完这一页，再按"怎么继续"一步步做。每一步都可以单独完成、单独提交。

## 用户要的是什么

原话："应该是要加上打开要输入密码的界面。恢复钱包也不用每次一打开就重新输入助记词……重新启动强制输入密码，输入密码只要有一次错误，就直接 reset 复原就可以。"

用户已经拍板的三个选择：

| 问题 | 用户的选择 |
|---|---|
| 密码形式 | 6 位数字 PIN |
| 什么时候要输 | 重启 + 切到后台就锁 |
| passphrase 是否保存 | 让用户选（设置 PIN 时一个开关） |

设计与残余风险写在 `docs/05-decisions.md` 的 D39（英文 `docs/en/05-decisions.md`）。

## 现在的状态

| 项目 | 状态 |
|---|---|
| 代码（`ios/Signer/Signer/` 下 WalletVault、PinViews、RootView、SetupViews、WalletView） | 完成，已提交 |
| 签名机产物检查 C4/C5 白名单（CryptoKit、钥匙串、SwiftUI 新符号） | 已逐项审查并加入，模拟器与真机构建都"全部检查通过" |
| 模拟器界面流程 | 已验证：设置 PIN 页、两次输入、保存失败提示（模拟器没有 Secure Enclave）、"不保存"进入钱包、切后台后会话被丢弃 |
| 文档 | D39（中英）、威胁模型 T14、范围、设备准备、进度图、费曼汇报（中英）已写 |
| 独立安全复审 | **没做完**（中途按用户要求停止），是下一步第 1 件事 |
| 真机验证（保存、解锁、输错清除、passphrase 不保存时的提示） | **没做**；装真机前必须先问用户 |
| Rust 代码 | 没有改动；C6 记录仍有效 |

## 已知的问题（我自己看到、还没修）

1. **暂时性错误会被当成密码错误而清除钱包**：`WalletVault.unlock` 里 `sharedSecretFromKeyAgreement` 失败（Secure Enclave 暂时出错）与 GCM 校验失败走同一个分支，都会 wipe。应只在 `AES.GCM.open` 抛出认证失败时清除；Secure Enclave / 钥匙串的其他错误应提示"暂时无法读取，请重试"，不清除。
2. **钥匙串读取暂时失败时显示成"没有钱包"**：`load` 失败（例如 `errSecInteractionNotAllowed`）时 `exists` 返回 false，App 直接进入建立/恢复页。没有清除数据，但用户会以为钱包没了；之后若重新保存，会覆盖旧的。应区分"没有这一项"（`errSecItemNotFound`）与其他错误。
3. **句柄损坏也会清除**：`SecureEnclave...PrivateKey(dataRepresentation:)` 失败按"数据损坏"清除。通常合理，但同样需要排除暂时性错误。
4. PIN 与 passphrase 是 Swift `String`，无法保证清零（D39 已写明是残余风险）。
5. 已保存的钱包的指纹/类型显示：钱包页底部文字依赖 `WalletVault.exists`，在 `@State` 初始化时读一次；目前够用。

## 怎么继续（按顺序）

1. **安全复审**：用 security-reviewer 子代理只读审查 `git show HEAD -- ios/Signer`。重点：上面的已知问题 1–3、`unlock` 的切片下标与边界、SwiftUI 状态机（解锁中切后台、连按）、后台锁定是否有遗漏的路径。按 CRITICAL/HIGH 修完再提交。
2. **修已知问题 1–2**：给 `WalletVault.Failure` 加一个 `transient(OSStatus)` 之类的情况；`RootView.unlock` 对它显示"暂时无法读取，请重试"，停留在解锁页。
3. **重新构建并检查**：
   ```bash
   tools/ios/build-signer.sh sim
   ```
   ```bash
   AW_DEVELOPMENT_TEAM=X855Y85A4V tools/ios/build-signer.sh device
   ```
   两个都要以"全部检查通过（含产物）"结尾。C9 禁止源码里出现 `contentsOf:`、`print(`、`FileManager`、`UserDefaults` 等（列表在 `tools/awlib/repo_scan.py` 的 `SWIFT_BANNED`）。新符号出现在 C4 输出里时，逐项 `xcrun swift-demangle` 审查后再加入 `tools/checks/signer-imports.allow`，并写一行注释说明来源。
4. **先问用户**，同意后再装真机（13 Pro Max `00008110-0011241C1179801E`，17 Pro Max `00008150-001209381188401C`）。打包与安装：
   ```bash
   cd build/xcode/Release-iphoneos && mkdir -p Payload && cp -R Signer.app Payload/ && ditto -c -k --norsrc --keepParent Payload Signer.ipa
   ```
   ```bash
   xcrun devicectl device install app --device 00008110-0011241C1179801E build/xcode/Release-iphoneos/Signer.app
   ```
5. **真机验证清单**（用测试网、测试钱包）：设置 PIN 并保存 → 杀掉 App 重开要输 PIN → 正确 PIN 进入，指纹一致 → 切后台再回来要输 PIN → 输错一次后钱包被清除、回到恢复页 → passphrase 钱包"不保存"时输完 PIN 要求输 passphrase，输错不清除 → "忘记密码"与"从本机删除保存的钱包"都能清除 → 手机没设锁屏密码时保存失败有提示。
6. 把结果写进 `docs/feynman/D39.md` 第 4 节与英文版，进度图 `docs/progress/d39-progress.puml` 改百分比后用 `plantuml -tsvg` 重新生成，提交。

## 必须遵守的规矩

- 删除文件用 `/usr/bin/trash`，不用 `rm`。
- 不 `git push`（用户自己推）；提交信息不加署名行；格式 `feat: …` / `fix: …` / `docs: …`。
- `git commit` 单独一条命令执行（和 `find … -not` 写在一起会被钩子误拦）。
- 提交前先清掉 `.DS_Store`（C2 会拒绝）。
- 第三方代码只能以源码形式放在仓库里；不从网络取预编译二进制。
- 可以参考 `~/Documents/github_src/airgap-vault`、`airgap-wallet` 的设计，但不要拷贝代码。
- 改了 Rust 代码后，先跑 `tools/repro/build-twice.sh` 再构建 iOS。
- 每个阶段写中文费曼汇报 + PlantUML 进度图（`docs/feynman/`、`docs/progress/`）。

## 之后的其他待办（与 D39 无关）

- 用户推送 04666e5、015ee0d 及之后的提交。
- P0-4：十二个第三方库的两人人工审查（需要人）。
- P1-5 工具完整性锚点；P1-7 Xcode 版本强制。
- P2d：TRON / NEAR / DOGE 交易签名。
- 真机 Solana devnet 实发（需要测试币）；Ledger SOL 地址比对；截屏防护真机验证。
