import SwiftUI

/// 已解锁：导出账户公钥、扫描待签请求、审查并签名。
struct WalletView: View {
    let session: SignerSession
    let onLock: () -> Void

    var body: some View {
        List {
            Section {
                LabeledContent("钱包类型", value: session.walletKind)
                LabeledContent("钱包指纹", value: session.fingerprint)
                    .font(.system(.body, design: .monospaced))
                    .accessibilityIdentifier("fingerprint")
            } footer: {
                Text(session.usesPassphrase
                     ? "这是 passphrase 钱包：请记下指纹，下次解锁时填进“预期指纹”核对。观察机导入账户后也会显示同一个指纹。"
                     : "观察机导入账户后会显示同一个指纹，请核对。")
            }
            Section {
                NavigationLink("各链收款地址（BTC、ETH/BNB、SOL、DOGE、TRON、NEAR）") { AddressesView(session: session) }
            }
            Section("导出账户公钥（给观察机扫描）") {
                ForEach(AccountChain.allCases) { chain in
                    NavigationLink(chain.title) { ExportAccountView(session: session, chain: chain) }
                }
            }
            Section {
                NavigationLink("扫描待签请求") { ScanRequestView(session: session) }
            } footer: {
                Text("比特币交易与以太坊 / BNB 等 EVM 链的交易、消息都在这里扫描，签名机会自动识别。")
            }
            Section {
                Button("锁定并清除内存中的密钥", role: .destructive) { onLock() }
            }
        }
        .navigationTitle("钱包")
        .navigationBarBackButtonHidden()
    }
}

struct ExportAccountView: View {
    let session: SignerSession
    let chain: AccountChain
    @State private var frames: URFrames?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 16) {
            if let frames {
                AnimatedQRView(source: frames)
                Text(chain.pathNote).font(.footnote).foregroundStyle(.secondary)
            } else if let error {
                Text(error).foregroundStyle(.red)
            } else {
                ProgressView()
            }
        }
        .padding()
        .navigationTitle(chain.title)
        .task {
            do { frames = try session.exportAccount(chain) } catch let f as AWCore.Failure { error = f.message } catch { self.error = "\(error)" }
        }
    }
}

struct ScanRequestView: View {
    let session: SignerSession
    @State private var scan = URScan()
    @State private var progress = (got: 0, total: 0)
    @State private var completed: URScan?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            QRScannerView { text in receive(text) }
                .frame(height: 360)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            if progress.total > 0 {
                ProgressView(value: Double(progress.got), total: Double(progress.total)) {
                    Text("已收到 \(progress.got) / \(progress.total) 段")
                }
            } else {
                Text("对准观察机屏幕上的动画二维码").foregroundStyle(.secondary)
            }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .padding()
        .navigationTitle("扫描待签请求")
        .navigationDestination(isPresented: Binding(get: { completed != nil }, set: { if !$0 { completed = nil } })) {
            if let completed { ReviewView(session: session, scan: completed) }
        }
    }

    private func receive(_ text: String) {
        do {
            let done = try scan.receive(text)
            progress = scan.progress
            error = nil
            if done {
                completed = scan
                scan = URScan()
                progress = (0, 0)
            }
        } catch let f as AWCore.Failure {
            error = f.message
        } catch {
            self.error = "\(error)"
        }
    }
}

/// 审查：逐行显示 Rust 生成的内容与警告；含高风险警告时必须额外确认才能签名。
struct ReviewView: View {
    let session: SignerSession
    let scan: URScan
    @State private var model: DisplayModel?
    @State private var signed: URFrames?
    @State private var acknowledged = false
    @State private var error: String?

    var body: some View {
        List {
            if let error {
                Section {
                    Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                        .accessibilityIdentifier("review-rejected")
                }
            }
            if let model {
                if !model.warnings.isEmpty {
                    Section("提示与警告") {
                        ForEach(model.warnings) { w in
                            Label(w.text, systemImage: Self.icon(w.level)).foregroundStyle(Self.color(w.level))
                        }
                    }
                }
                Section("\(model.title) · \(model.chain) \(model.network)") {
                    ForEach(model.rows) { r in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(r.label).font(.caption).foregroundStyle(.secondary)
                            Self.value(r)
                        }
                    }
                }
                if let signed {
                    Section("已签名：请让观察机扫描") { AnimatedQRView(source: signed) }
                } else {
                    Section {
                        if model.hasDanger {
                            Toggle("我已逐条阅读上面的高风险警告，确认要签名", isOn: $acknowledged)
                        }
                        Button("确认无误，签名") { sign() }
                            .bold()
                            .disabled(model.hasDanger && !acknowledged)
                    }
                }
            }
        }
        .navigationTitle("审查")
        .task { load() }
    }

    private func load() {
        do { model = try session.review(scan) } catch let f as AWCore.Failure { error = f.message } catch { self.error = "\(error)" }
    }

    private func sign() {
        do { signed = try session.sign(scan, confirmedDanger: acknowledged) } catch let f as AWCore.Failure { error = f.message } catch { self.error = "\(error)" }
    }

    @ViewBuilder
    static func value(_ r: DisplayModel.Row) -> some View {
        switch r.style {
        case "address": Text(grouped(r.value)).font(.system(.callout, design: .monospaced)).textSelection(.disabled)
        case "amount": Text(r.value).bold()
        // 不截断：被签名的内容必须完整可见（Rust 侧已限制长度并按行切分）
        case "data": Text(r.value).font(.system(.caption, design: .monospaced))
        default: Text(r.value)
        }
    }

    static func icon(_ level: String) -> String {
        switch level {
        case "danger": return "exclamationmark.octagon.fill"
        case "caution": return "exclamationmark.triangle.fill"
        default: return "info.circle"
        }
    }

    static func color(_ level: String) -> Color {
        switch level {
        case "danger": return .red
        case "caution": return .orange
        default: return .secondary
        }
    }

    /// 地址每 4 个字符一组，便于逐组核对（威胁 T8）。
    static func grouped(_ s: String) -> String {
        stride(from: 0, to: s.count, by: 4).map { i in
            let a = s.index(s.startIndex, offsetBy: i)
            let b = s.index(a, offsetBy: min(4, s.count - i))
            return String(s[a..<b])
        }.joined(separator: " ")
    }
}

/// 各链收款地址：由 Rust 从同一组助记词派生，可显示为二维码供付款方扫描。
struct AddressesView: View {
    let session: SignerSession
    @State private var chain = AddressChain.btc
    @State private var index: UInt32 = 0
    @State private var info: AddressInfo?
    @State private var error: String?

    var body: some View {
        List {
            Section {
                Picker("链", selection: $chain) {
                    ForEach(AddressChain.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                Stepper("序号 #\(index)", value: $index, in: 0...chain.maxIndex)
            }
            if let info {
                Section(info.chain) {
                    if let img = QRCodeImage.make(info.address) {
                        Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
                            .frame(maxWidth: 240).padding(8).background(Color.white).frame(maxWidth: .infinity)
                    }
                    Text(ReviewView.grouped(info.address)).font(.system(.callout, design: .monospaced))
                    LabeledContent("路径", value: info.path).font(.footnote)
                    Text(info.note).font(.footnote).foregroundStyle(.secondary)
                    explorers(info.explorers)
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Section {
                Text("付款前请在观察机上核对同一个地址。地址只包含公开信息，不会泄露私钥。").font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("收款地址")
        .onChange(of: chain) { _, c in if index > c.maxIndex { index = 0 } }
        .task(id: "\(chain.rawValue)-\(index)") { load() }
    }

    /// 只显示网址文字（verbatim：不解析成链接，不能点击）；签名机不联网
    @ViewBuilder private func explorers(_ list: [ExplorerLink]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("区块浏览器（只显示，请在联网设备的浏览器里输入；签名机不联网）")
                .font(.footnote).foregroundStyle(.secondary)
            if list.isEmpty {
                Text("这个网络没有常用的公共区块浏览器").font(.footnote)
            }
            ForEach(list) { e in
                Text(verbatim: e.name).font(.caption).bold()
                Text(verbatim: e.url).font(.system(.caption, design: .monospaced))
            }
        }
    }

    private func load() {
        do {
            info = try session.address(chain: chain, index: index)
            error = nil
        } catch let f as AWCore.Failure {
            info = nil
            error = f.message
        } catch {
            self.error = "\(error)"
        }
    }
}
