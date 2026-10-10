import SwiftUI

/// 建立或恢复钱包，然后解锁。导航用显式路径管理，完成时一次性回到本页。
struct SetupView: View {
    enum Route: Hashable {
        case generate
        case backup
        case restore
    }

    let onUnlocked: (SignerSession) -> Void
    @State private var session = SignerSession()
    @State private var path: [Route] = []
    @State private var hasWords = false
    @State private var testnet = true
    @State private var mode = WalletMode.standard
    @State private var passphrase = ""
    @State private var passphraseAgain = ""
    @State private var expectedFingerprint = ""
    @State private var error: String?

    enum WalletMode: Hashable {
        case standard
        case passphrase
    }

    var body: some View {
        NavigationStack(path: $path) {
            form
                .navigationDestination(for: Route.self) { route in
                    switch route {
                    case .generate: GenerateView(session: session) { path.append(.backup) }
                    case .backup: BackupView(session: session) { wordsReady() }
                    case .restore: RestoreView(session: session) { wordsReady() }
                    }
                }
        }
    }

    private func wordsReady() {
        hasWords = true
        path.removeAll()
    }

    private var form: some View {
        Form {
            Section {
                Label("自检通过", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                    .accessibilityIdentifier("selftest-status")
            }
            Section("1. 助记词") {
                if hasWords {
                    Label("已载入 \(session.wordIndices.count) 个单词", systemImage: "key.fill")
                } else {
                    NavigationLink("生成新钱包（系统随机数 + 骰子）", value: Route.generate)
                    NavigationLink("恢复钱包（输入助记词）", value: Route.restore)
                }
            }
            if hasWords {
                Section {
                    Picker("钱包类型", selection: $mode) {
                        Text("标准钱包").tag(WalletMode.standard)
                        Text("passphrase 钱包").tag(WalletMode.passphrase)
                    }
                    .pickerStyle(.segmented)
                    if mode == .passphrase { passphraseFields }
                    TextField("预期指纹（可选，8 位十六进制）", text: $expectedFingerprint)
                        .font(.system(.body, design: .monospaced))
                        .keyboardType(.asciiCapable)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if fingerprint == .invalid {
                        Text("指纹应为 8 位十六进制，例如 73c5da0a").font(.footnote).foregroundStyle(.red)
                    }
                    Toggle("测试网（建议先用测试网熟悉流程）", isOn: $testnet)
                } header: {
                    Text("2. 解锁")
                } footer: {
                    Text(mode == .passphrase
                         ? "passphrase 相当于第 25 个单词：输错不会报错，而是进入另一个钱包。第一次使用时请记下解锁后显示的指纹，以后填进“预期指纹”，不一致就不会进入。passphrase 永不保存，忘了就无法找回这个钱包里的资产。"
                         : "填写预期指纹可以确认恢复出来的是同一个钱包。")
                }
                Section {
                    Button("解锁") { unlock() }.bold().disabled(!canUnlock)
                }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("AW Signer · 离线签名机")
    }

    @ViewBuilder private var passphraseFields: some View {
        SecureField("passphrase（永不保存）", text: $passphrase)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        SecureField("再输入一次", text: $passphraseAgain)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        if !passphraseAgain.isEmpty && passphrase != passphraseAgain {
            Text("两次输入不一致").font(.footnote).foregroundStyle(.red)
        }
        ForEach(PassphraseCheck.cautions(passphrase), id: \.self) { c in
            Label(c, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.orange)
        }
    }

    private var fingerprint: PassphraseCheck.Fingerprint {
        PassphraseCheck.fingerprint(expectedFingerprint)
    }

    private var canUnlock: Bool {
        guard fingerprint != .invalid else { return false }
        if mode == .standard { return true }
        return !passphrase.isEmpty && passphrase == passphraseAgain
    }

    private func unlock() {
        do {
            if case .value(let fp) = fingerprint {
                try session.expectFingerprint(fp)
            } else {
                try session.expectFingerprint(nil)
            }
            try session.setPassphrase(mode == .passphrase ? passphrase : "")
            passphrase = ""
            passphraseAgain = ""
            try session.unlock(testnet: testnet)
            onUnlocked(session)
        } catch let f as AWCore.Failure {
            error = f.message
        } catch {
            self.error = "\(error)"
        }
    }
}

/// 生成：系统随机数 + 可选骰子（威胁 T1）。
/// 生成助记词的两种方式（与 Rust entropy.rs 对应）
enum EntropyMode: String, CaseIterable, Identifiable {
    case mixed = "系统随机数 + 骰子"
    case diceOnly = "纯骰子（可独立验证）"
    var id: String { rawValue }
}

struct GenerateView: View {
    let session: SignerSession
    let onGenerated: () -> Void
    @State private var mode = EntropyMode.mixed
    @State private var dice: [UInt8] = []
    @State private var wordCount = 24
    @State private var error: String?

    /// 纯骰子模式的最低次数（与 Rust 一致）；混合模式下是建议值
    private var required: Int { wordCount == 24 ? 100 : 50 }
    private var bits: Int { Int(Double(dice.count) * 2.585) }
    private var ready: Bool { mode == .mixed || dice.count >= required }

    var body: some View {
        Form {
            Section {
                Picker("单词数", selection: $wordCount) {
                    Text("12").tag(12)
                    Text("24").tag(24)
                }
                .pickerStyle(.segmented)
                Picker("随机来源", selection: $mode) {
                    ForEach(EntropyMode.allCases) { Text($0.rawValue).tag($0) }
                }
            } footer: {
                Text(mode == .mixed
                     ? "系统随机数先经过健康检查，再与骰子点数一起哈希混合。骰子越多越安全：即使系统随机数有缺陷，只要骰子足够，助记词依然安全。"
                     : "完全不用设备随机数：熵 = SHA-256(骰子点数)。你可以在一台离线电脑上用 tools/testvectors/verify_dice.py（或 printf '%s' 点数 | shasum -a 256）复算，确认助记词确实来自你掷的骰子。")
            }
            Section {
                Text("已掷 \(dice.count) 次，约 \(bits) 位熵（\(mode == .diceOnly ? "至少需要" : "建议至少") \(required) 次）").monospacedDigit()
                LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 6)) {
                    ForEach(1...6, id: \.self) { n in
                        Button("\(n)") { dice.append(UInt8(48 + n)) }
                            .buttonStyle(.bordered)
                    }
                }
                Button("撤销上一次") { undo() }.disabled(dice.isEmpty)
                Button("清空", role: .destructive) { wipeDice() }
            } header: {
                Text(mode == .diceOnly ? "骰子（必需）" : "骰子（可选）")
            } footer: {
                Text(mode == .mixed && dice.count < required
                     ? "请用真实的骰子，每次按实际点数输入。当前骰子不足 \(required) 次：安全性主要依赖系统随机数。"
                     : "请用真实的骰子，每次按实际点数输入，不要自己编数字（乱按或有规律的点数会被拒绝）。")
            }
            Section {
                Button("生成") { generate() }.bold().disabled(!ready)
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("生成新钱包")
        // 随机数审查 M3：预留容量避免数组扩容时在旧内存里留下副本；离开页面时清零
        .onAppear { dice.reserveCapacity(1024) }
        .onDisappear { wipeDice() }
    }

    private func undo() {
        guard !dice.isEmpty else { return }
        dice[dice.count - 1] = 0
        dice.removeLast()
    }

    private func wipeDice() {
        dice.withUnsafeMutableBufferPointer { $0.update(repeating: 0) }
        dice.removeAll(keepingCapacity: true)
    }

    private func generate() {
        do {
            switch mode {
            case .mixed: try session.generate(dice: dice, wordCount: wordCount)
            case .diceOnly: try session.generateFromDice(dice, wordCount: wordCount)
            }
            wipeDice()
            onGenerated()
        } catch let f as AWCore.Failure {
            error = f.message
            if mode == .diceOnly { wipeDice() } // 纯骰子模式下骰子就是全部秘密：失败也清零，重新掷
        } catch {
            self.error = "\(error)"
        }
    }
}

/// 抄写备份。
struct BackupView: View {
    let session: SignerSession
    let onConfirmed: () -> Void

    var body: some View {
        List {
            Section {
                Text("请用纸笔或钢板抄写下面的单词并核对两遍。不要拍照、不要截屏、不要存到任何电子设备。")
                    .foregroundStyle(.orange)
            }
            Section("助记词") {
                ForEach(Array(session.wordIndices.enumerated()), id: \.offset) { i, idx in
                    HStack {
                        Text("\(i + 1).").monospacedDigit().foregroundStyle(.secondary).frame(width: 36, alignment: .trailing)
                        Text(AWCore.words[idx]).font(.system(.body, design: .monospaced))
                    }
                }
            }
            Section {
                Button("我已抄写并核对") { onConfirmed() }.bold()
            }
        }
        .navigationTitle("备份助记词")
    }
}

/// 恢复：用自带单词键盘输入（不经过系统键盘）。
struct RestoreView: View {
    let session: SignerSession
    let onDone: () -> Void
    @State private var expected = 24
    @State private var indices: [UInt16] = []
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            Picker("单词数", selection: $expected) {
                Text("12").tag(12)
                Text("24").tag(24)
            }
            .pickerStyle(.segmented)
            .disabled(!indices.isEmpty)
            Text("第 \(min(indices.count + 1, expected)) / \(expected) 个单词")
                .font(.headline)
                .accessibilityIdentifier("restore-progress")
            WordKeyboard { idx in
                indices.append(idx)
                if indices.count == expected { finish() }
            }
            HStack {
                Button("删除上一个") { _ = indices.popLast() }.disabled(indices.isEmpty)
                Spacer()
                Button("全部清空", role: .destructive) { indices.removeAll() }.disabled(indices.isEmpty)
            }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .padding()
        .navigationTitle("恢复钱包")
    }

    private func finish() {
        do {
            try session.setWords(indices)
            indices.removeAll()
            onDone()
        } catch let f as AWCore.Failure {
            error = f.message + "，请检查后重新输入"
            indices.removeAll()
        } catch {
            self.error = "\(error)"
        }
    }
}
