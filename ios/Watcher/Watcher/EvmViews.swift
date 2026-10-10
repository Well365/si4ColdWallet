import SwiftUI
import UIKit

/// EVM 标签页：账户以 UR 字符串保存在本机（只是公钥）。
struct EvmTab: View {
    @AppStorage("evm-account-ur") private var accountUR = ""
    @State private var account: EvmAccount?

    var body: some View {
        NavigationStack {
            Group {
                if let account {
                    EvmAccountView(account: account) {
                        accountUR = ""
                        self.account = nil
                    }
                } else {
                    EvmImportView { acct in
                        accountUR = acct.urString
                        account = acct
                    }
                }
            }
            .task {
                if account == nil, !accountUR.isEmpty { account = try? EvmAccount.from(ur: accountUR) }
            }
        }
    }
}

struct EvmImportView: View {
    let onImported: (EvmAccount) -> Void
    @State private var scan = URScan()
    @State private var error: String?

    var body: some View {
        VStack(spacing: 16) {
            Text("在签名机上打开\"以太坊 / BNB 等 EVM 链\"账户公钥二维码，然后扫描。").multilineTextAlignment(.center)
            QRScannerView { text in receive(text) }
                .frame(height: 360)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            Button("从剪贴板导入（UR 文本）") { paste() }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .padding()
        .navigationTitle("导入 EVM 账户")
    }

    private func paste() {
        guard let text = UIPasteboard.general.string, !text.isEmpty else { error = "剪贴板为空"; return }
        do { onImported(try EvmAccount.from(ur: text.trimmingCharacters(in: .whitespacesAndNewlines))) } catch let f as WatchCore.Failure { error = f.message } catch { self.error = "\(error)" }
    }

    private func receive(_ text: String) {
        do {
            if try scan.receive(text) { onImported(try EvmAccount.from(scan: scan)) }
        } catch let f as WatchCore.Failure {
            error = f.message
            scan = URScan()
        } catch {
            self.error = "\(error)"
        }
    }
}

struct EvmAccountView: View {
    let account: EvmAccount
    let onForget: () -> Void
    @AppStorage("evm-network") private var chainId: Int = 11_155_111
    @AppStorage("evm-rpc-overrides") private var rpcOverrides = ""
    @State private var balances: [String: String] = [:]
    @State private var error: String?

    private var network: EvmNetwork {
        EvmNetwork.all.first { $0.chainId == UInt64(chainId) } ?? EvmNetwork.all[0]
    }

    /// 每条链可以改用自己的节点（"链ID=URL" 每行一条）
    private var rpcURL: URL? {
        let custom = rpcOverrides.split(separator: "\n").compactMap { line -> (UInt64, String)? in
            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2, let id = UInt64(parts[0]) else { return nil }
            return (id, String(parts[1]).trimmingCharacters(in: .whitespaces))
        }.first { $0.0 == network.chainId }?.1
        guard let u = URL(string: custom ?? network.defaultRPC), u.scheme == "https" else { return nil }
        return u
    }

    var body: some View {
        List {
            Section {
                LabeledContent("钱包指纹", value: account.fingerprint).font(.system(.body, design: .monospaced))
                Picker("网络", selection: $chainId) {
                    ForEach(EvmNetwork.all) { Text($0.name).tag(Int($0.chainId)) }
                }
            } footer: {
                Text("指纹应与签名机显示的一致。所有 EVM 链共用同一个地址。")
            }
            Section("收款地址 #0") {
                Text(account.address(index: 0)).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                if let u = network.addressURL(account.address(index: 0)) {
                    Link("在区块浏览器查看（\(network.name)）", destination: u)
                    Text(verbatim: u.absoluteString).font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Section("余额（\(network.name)）") {
                LabeledContent(network.symbol, value: balances[""] ?? "—")
                ForEach(network.tokens) { t in LabeledContent(t.symbol, value: balances[t.contract] ?? "—") }
                Button("刷新") { Task { await refresh() } }
            }
            Section {
                if let rpcURL {
                    NavigationLink("发送") { EvmPayView(account: account, network: network, rpc: EvmRPC(url: rpcURL)) }
                } else {
                    Text("节点地址无效（必须是 https）").foregroundStyle(.red)
                }
                NavigationLink("签名消息（personal_sign / EIP-712）") { EvmMessageView(account: account, network: network) }
            }
            Section("自定义节点（可选）") {
                TextField("链ID=https://…（每行一条）", text: $rpcOverrides, axis: .vertical)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.caption, design: .monospaced))
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Section { Button("移除此账户", role: .destructive) { onForget() } }
        }
        .navigationTitle("EVM 账户")
        .task(id: chainId) { await refresh() }
    }

    private func refresh() async {
        guard let rpcURL else { return }
        let rpc = EvmRPC(url: rpcURL)
        let addr = account.address(index: 0)
        do {
            // 节点必须真的是所选网络，防止配错节点导致在错误的链上构造交易
            guard try await rpc.chainId() == network.chainId else {
                error = "节点的链 ID 与所选网络不一致"
                return
            }
            var b: [String: String] = [:]
            b[""] = EvmAmount.format(hexQuantity: try await rpc.balance(addr), decimals: 18)
            for t in network.tokens {
                b[t.contract] = EvmAmount.format(hexQuantity: try await rpc.tokenBalance(t.contract, owner: addr), decimals: t.decimals)
            }
            balances = b
            error = nil
        } catch let e as EvmRPC.RPCError {
            error = "查询失败：\(e.message)"
        } catch {
            self.error = "查询失败：\(error.localizedDescription)"
        }
    }
}

struct EvmPayView: View {
    let account: EvmAccount
    let network: EvmNetwork
    let rpc: EvmRPC
    @State private var to = ""
    @State private var amount = ""
    @State private var token: EvmToken?
    @State private var pending: EvmPending?
    @State private var frames: URFrames?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Form {
            Section("收款人与金额") {
                Picker("资产", selection: $token) {
                    Text(network.symbol).tag(EvmToken?.none)
                    ForEach(network.tokens) { Text($0.symbol).tag(EvmToken?.some($0)) }
                }
                TextField("0x…", text: $to)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
                TextField("金额（如 0.01）", text: $amount).keyboardType(.decimalPad)
            }
            Section {
                Button(busy ? "正在向节点查询 nonce 与手续费…" : "构造交易") { Task { await build() } }
                    .bold().disabled(busy)
            }
            if let pending, let frames {
                Section("签名机将显示（请逐行对照）：\(pending.display.title)") {
                    ForEach(pending.display.rows) { r in LabeledContent(r.label, value: r.value) }
                    ForEach(pending.display.warnings) { w in Text(w.text).foregroundStyle(w.level == "info" ? Color.secondary : Color.red) }
                }
                Section("待签请求：请用签名机扫描") {
                    AnimatedQRView(source: frames)
                    NavigationLink("扫描签名机返回的签名") { EvmSignedView(pending: pending, network: network, rpc: rpc) }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("发送（\(network.name)）")
    }

    private func build() async {
        busy = true
        defer { busy = false }
        do {
            let addr = account.address(index: 0)
            let nonce = try await rpc.nonce(addr)
            let fees = try await rpc.fees()
            // 代币转账 gas 上限取保守值；只按实际消耗收费
            let gas: UInt64 = token == nil ? 21_000 : 100_000
            let p = try account.buildTransfer(network: network, nonce: nonce, fees: fees, gasLimit: gas,
                                              to: to.trimmingCharacters(in: .whitespaces), amount: amount, token: token)
            frames = try p.frames()
            pending = p
            error = nil
        } catch let f as WatchCore.Failure {
            error = f.message
        } catch let e as EvmRPC.RPCError {
            error = "节点：\(e.message)"
        } catch {
            self.error = "\(error.localizedDescription)"
        }
    }
}

struct EvmSignedView: View {
    let pending: EvmPending
    let network: EvmNetwork
    let rpc: EvmRPC
    @State private var scan = URScan()
    @State private var progress = (got: 0, total: 0)
    @State private var raw: String?
    @State private var txHash: String?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            if let raw {
                Text("签名已验证，交易已就绪").font(.headline).foregroundStyle(.green)
                ScrollView { Text(raw).font(.system(.caption2, design: .monospaced)).textSelection(.enabled) }.frame(maxHeight: 160)
                if let txHash {
                    Text("已广播：\(txHash)").font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                    if let u = network.txURL(txHash) { Link("在区块浏览器查看", destination: u) }
                } else {
                    Button("广播") { Task { await broadcast(raw) } }.buttonStyle(.borderedProminent)
                }
            } else {
                QRScannerView { text in receive(text) }
                    .frame(height: 360)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                if progress.total > 0 { ProgressView(value: Double(progress.got), total: Double(progress.total)) }
            }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .padding()
        .navigationTitle("签名结果")
    }

    private func receive(_ text: String) {
        do {
            let done = try scan.receive(text)
            progress = scan.progress
            if done { raw = try pending.finalize(scan: scan) }
        } catch let f as WatchCore.Failure {
            error = f.message
            scan = URScan()
        } catch {
            self.error = "\(error)"
        }
    }

    private func broadcast(_ hex: String) async {
        do {
            let returned = try await rpc.sendRaw(hex)
            // 节点返回的哈希必须就是这笔交易的哈希，否则"已广播"可能是假的
            guard let expected = EvmAmount.txHash(rawHex: hex), returned.lowercased() == expected.lowercased() else {
                error = "节点返回的交易哈希与这笔交易不符，广播结果不可信：\(returned)"
                return
            }
            txHash = expected
        } catch let e as EvmRPC.RPCError {
            error = "广播失败：\(e.message)"
        } catch {
            self.error = "广播失败：\(error.localizedDescription)"
        }
    }
}

/// 发起消息签名：粘贴 dApp 给出的消息或 eth_signTypedData_v4 JSON，生成请求给签名机扫描
struct EvmMessageView: View {
    let account: EvmAccount
    let network: EvmNetwork
    @State private var typed = true
    @State private var text = ""
    @State private var bindChain = true
    @State private var pending: EvmPending?
    @State private var frames: URFrames?
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                Picker("类型", selection: $typed) {
                    Text("结构化签名（EIP-712）").tag(true)
                    Text("消息（personal_sign）").tag(false)
                }
                .pickerStyle(.segmented)
                TextField(typed ? "粘贴 eth_signTypedData_v4 的 JSON" : "要签名的消息", text: $text, axis: .vertical)
                    .lineLimit(4...12)
                    .keyboardType(typed ? .asciiCapable : .default)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.caption, design: .monospaced))
                HStack {
                    Button("从剪贴板粘贴") { text = UIPasteboard.general.string ?? "" }
                    Spacer()
                    Button("清空", role: .destructive) {
                        text = ""
                        pending = nil
                        frames = nil
                        error = nil
                    }
                }
                .buttonStyle(.borderless)
                if typed { Toggle("核对链 ID 是否为 \(network.name)", isOn: $bindChain) }
                Button("生成签名请求") { build() }.bold().disabled(text.isEmpty)
            } footer: {
                Text("观察机先用与签名机相同的规则检查：格式不严谨、链 ID 不符、超长的内容在这里就会被拒。")
            }
            if let pending, let frames {
                Section("签名机将显示（请逐行对照）：\(pending.display.title)") {
                    ForEach(pending.display.rows) { r in LabeledContent(r.label, value: r.value) }
                    ForEach(pending.display.warnings) { w in Text(w.text).foregroundStyle(w.level == "info" ? Color.secondary : Color.red) }
                }
                Section("待签请求：请用签名机扫描") {
                    AnimatedQRView(source: frames)
                    NavigationLink("扫描签名机返回的签名") { EvmMessageSignedView(pending: pending) }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("消息签名")
    }

    private func build() {
        do {
            let p = try account.buildMessage(typed: typed, text: text,
                                             chainId: typed && bindChain ? network.chainId : 0)
            frames = try p.frames()
            pending = p
            error = nil
        } catch let f as WatchCore.Failure {
            pending = nil
            error = f.message
        } catch {
            self.error = "\(error.localizedDescription)"
        }
    }
}

/// 扫描签名机返回的签名；核对它确实来自本地址后显示，可复制回 dApp
struct EvmMessageSignedView: View {
    let pending: EvmPending
    @State private var scan = URScan()
    @State private var progress = (got: 0, total: 0)
    @State private var signature: String?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            if let signature {
                Text("签名已核对：确实由本地址签出").font(.headline).foregroundStyle(.green)
                Text(signature).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            } else {
                QRScannerView { text in receive(text) }
                    .frame(height: 360)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                if progress.total > 0 { ProgressView(value: Double(progress.got), total: Double(progress.total)) }
            }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .padding()
        .navigationTitle("签名结果")
    }

    private func receive(_ text: String) {
        do {
            let done = try scan.receive(text)
            progress = scan.progress
            if done { signature = try pending.finalize(scan: scan) }
        } catch let f as WatchCore.Failure {
            error = f.message
            scan = URScan()
        } catch {
            self.error = "\(error)"
        }
    }
}
