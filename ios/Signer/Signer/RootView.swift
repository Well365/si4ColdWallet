import AWSignerC
import SwiftUI

/// 签名机的状态机：自检 → 本机有保存的钱包时输 PIN 解锁，否则建立/恢复钱包 → 已解锁。
/// App 一进入后台就锁定（决策 D39）：丢弃会话（Rust 侧清零密钥），回来要重新输 PIN。
struct RootView: View {
    enum Stage {
        case checking
        case failed(String)
        case setup(notice: String?)
        case locked
        case needsPassphrase(WalletVault.Contents, error: String?)
        case unlocked(SignerSession)
    }

    @Environment(\.scenePhase) private var phase
    @State private var stage: Stage = .checking

    var body: some View {
        Group {
            switch stage {
            case .checking:
                ProgressView("自检中…").task { runCheck() }
            case .failed(let msg):
                VStack(spacing: 16) {
                    Image(systemName: "xmark.octagon.fill").font(.largeTitle).foregroundStyle(.red)
                    Text(msg).multilineTextAlignment(.center)
                        .accessibilityIdentifier("selftest-failed")
                }
                .padding()
            case .setup(let notice):
                SetupView(notice: notice) { session in stage = .unlocked(session) }
            case .locked:
                UnlockPinView { pin in unlock(pin) } onForget: {
                    WalletVault.wipe()
                    stage = .setup(notice: "本机保存的钱包已清除，请用助记词恢复。")
                }
            case .needsPassphrase(let contents, let error):
                PassphrasePromptView(error: error) { text in open(contents, passphrase: text) }
            case .unlocked(let session):
                // 每一页顶部都显示当前是哪个钱包（排在导航栏上方，不与标题重叠）
                VStack(spacing: 0) {
                    Text(verbatim: "\(session.walletKind) · 指纹 \(session.fingerprint)")
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 4)
                        .background(session.usesPassphrase ? Color.indigo.opacity(0.15) : Color.gray.opacity(0.12))
                        .accessibilityIdentifier("wallet-badge")
                    NavigationStack {
                        WalletView(session: session) { lock() } onForget: {
                            WalletVault.wipe()
                            stage = .setup(notice: "本机保存的钱包已删除。")
                        }
                    }
                }
            }
        }
        .onChange(of: phase) { _, p in
            if p == .background { lock() }
        }
    }

    private func runCheck() {
        switch AWCore.startupCheck() {
        case .success: stage = WalletVault.exists ? .locked : .setup(notice: nil)
        case .failure(let f): stage = .failed(f.message)
        }
    }

    /// 锁定：会话被释放（Rust 侧清零），有保存的钱包就回到 PIN 页，否则回到建立/恢复页
    private func lock() {
        switch stage {
        case .unlocked, .needsPassphrase, .locked:
            stage = WalletVault.exists ? .locked : .setup(notice: nil)
        default:
            break
        }
    }

    private func unlock(_ pin: String) {
        do {
            let c = try WalletVault.unlock(pin: pin)
            if c.usesPassphrase && c.passphrase == nil {
                stage = .needsPassphrase(c, error: nil)
            } else {
                open(c, passphrase: c.passphrase ?? "")
            }
        } catch WalletVault.Failure.wrongPinWiped {
            stage = .setup(notice: "解锁密码错误：本机保存的钱包已清除，请用助记词恢复。")
        } catch WalletVault.Failure.corruptWiped {
            stage = .setup(notice: "本机保存的钱包数据无法读取，已清除，请用助记词恢复。")
        } catch {
            stage = .setup(notice: "无法读取本机保存的钱包，请用助记词恢复。")
        }
    }

    /// 用保存的单词（与 passphrase）建立会话并解锁；指纹必须与保存时一致
    private func open(_ c: WalletVault.Contents, passphrase: String) {
        let session = SignerSession()
        do {
            try session.setWords(c.words)
            try session.expectFingerprint(c.fingerprint)
            try session.setPassphrase(c.usesPassphrase ? passphrase : "")
            try session.unlock(testnet: c.testnet)
            stage = .unlocked(session)
        } catch AWCore.Failure.core(let code) where code == AW_ERR_FINGERPRINT_MISMATCH {
            // PIN 是对的，只是 passphrase 输错：不清除，重新输入
            stage = .needsPassphrase(c, error: "passphrase 不对（指纹不一致），请重新输入。")
        } catch {
            stage = .setup(notice: "解锁失败：\(error)")
        }
    }
}

/// PIN 正确、但 passphrase 没有保存：输入 passphrase（输错不会清除钱包，只是指纹对不上会重输）
struct PassphrasePromptView: View {
    let error: String?
    let onSubmit: (String) -> Void
    @State private var text = ""

    var body: some View {
        Form {
            Section {
                SecureField("passphrase", text: $text)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("解锁") {
                    let t = text
                    text = ""
                    onSubmit(t)
                }
                .disabled(text.isEmpty)
            } header: {
                Text("输入 passphrase")
            } footer: {
                Text("这个钱包的 passphrase 没有保存在本机。输错时指纹对不上，不会进入钱包，也不会清除本机保存的助记词。")
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
    }
}
