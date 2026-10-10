import AWWatchC
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
    @ObservedObject private var book = NodeBook.shared
    @State private var balances: [String: String] = [:]
    @State private var error: String?

    private var network: EvmNetwork {
        EvmNetwork.all.first { $0.chainId == UInt64(chainId) } ?? EvmNetwork.all[0]
    }

    private var nodeNet: NodeNetwork { .evm(network) }

    /// 当前节点（查询余额、获取手续费、构造；广播时可以另选）
    private var rpc: EvmRPC? {
        NodeBook.validURL(book.current(nodeNet).url).map { EvmRPC(url: $0) }
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
                NodeSummaryRow(net: nodeNet)
                if let rpc {
                    NavigationLink("发送") { EvmPayView(account: account, network: network, rpc: rpc) }
                } else {
                    Text("节点地址无效（必须是 https）").foregroundStyle(.red)
                }
                NavigationLink("签名消息（personal_sign / EIP-712）") { EvmMessageView(account: account, network: network) }
            } footer: {
                Text("节点可在“节点”页选择、测试或添加自己的；发送页可以选手续费档位，广播时可以换节点。")
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Section { Button("移除此账户", role: .destructive) { onForget() } }
        }
        .navigationTitle("EVM 账户")
        .task(id: "\(chainId)-\(book.current(nodeNet).url)") { await refresh() }
    }

    private func refresh() async {
        guard let rpc else { return }
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

/// 发送（决策 D35）：收款人与金额 → 手续费档位（慢 / 标准 / 快 / 自定义）与 gas 上限 → 核对余额 → 构造 → 签名机扫码
struct EvmPayView: View {
    let account: EvmAccount
    let network: EvmNetwork
    let rpc: EvmRPC

    private struct InputError: Error { let message: String }

    @State private var to = ""
    @State private var amount = ""
    @State private var token: EvmToken?
    @State private var tiers: [EvmFeeTier] = []
    @State private var speed = "standard"
    @State private var customMaxFee = ""
    @State private var customPriority = ""
    @State private var gasLimitText = ""
    @State private var estimatedGas: UInt64?
    @State private var gasNote: String?
    @State private var feeError: String?
    @State private var loadingFees = false
    @State private var manualNonce = false
    @State private var nonceText = ""
    @State private var pending: EvmPending?
    @State private var frames: URFrames?
    @State private var busy = false
    @State private var error: String?

    private var defaultGas: UInt64 { token == nil ? 21_000 : 100_000 }

    /// 实际使用的 gas 上限：手填优先；否则用估算值；估算失败用默认值
    private var gasLimit: UInt64? {
        gasLimitText.isEmpty ? (estimatedGas ?? defaultGas) : UInt64(gasLimitText)
    }

    var body: some View {
        Form {
            Section("收款人与金额") {
                Picker("资产", selection: $token) {
                    Text(network.symbol).tag(EvmToken?.none)
                    ForEach(network.tokens) { Text($0.symbol).tag(EvmToken?.some($0)) }
                }
                TextField("0x…", text: $to)
                    .keyboardType(.asciiCapable)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
                TextField("金额（如 0.01）", text: $amount).keyboardType(.decimalPad)
            }
            Section {
                Picker("档位", selection: $speed) {
                    ForEach(tiers) { Text($0.label).tag($0.speed) }
                    Text("自定义").tag("custom")
                }
                .pickerStyle(.segmented)
                if speed == "custom" {
                    TextField("最高单价（gwei，如 30）", text: $customMaxFee).keyboardType(.decimalPad)
                    TextField("优先费（gwei，如 1.5）", text: $customPriority).keyboardType(.decimalPad)
                } else if let t = tiers.first(where: { $0.speed == speed }) {
                    LabeledContent("优先费", value: "\(t.maxPriorityGwei) gwei")
                    LabeledContent("最高单价", value: "\(t.maxFeeGwei) gwei")
                }
                LabeledContent("Gas 上限", value: gasLimit.map { String($0) } ?? "无效")
                TextField("手动 Gas 上限（留空 = 自动估算）", text: $gasLimitText).keyboardType(.numberPad)
                if let cost = maxCostText { LabeledContent("最多手续费", value: cost) }
                if let gasNote { Text(gasNote).font(.footnote).foregroundStyle(.secondary) }
                if let feeError { Text(feeError).font(.footnote).foregroundStyle(.red) }
                Button(loadingFees ? "正在获取…" : "重新获取手续费") { Task { await loadFees() } }.disabled(loadingFees)
            } header: {
                Text("手续费（gas）")
            } footer: {
                Text("最多手续费 = Gas 上限 × 最高单价；实际按用量与当时的基础费收取，多余的不扣。签名机会再显示一遍“总计最多扣除”，请两边对照。")
            }
            Section("高级") {
                Toggle("手动指定 nonce（替换或加速卡住的交易）", isOn: $manualNonce)
                if manualNonce { TextField("nonce", text: $nonceText).keyboardType(.numberPad) }
            }
            Section {
                Button(busy ? "正在向节点查询余额与 nonce…" : "核对余额并构造交易") { Task { await build() } }
                    .bold().disabled(busy)
            }
            if let pending, let frames {
                Section("签名机将显示（请逐行对照）：\(pending.display.title)") {
                    ForEach(pending.display.rows) { r in LabeledContent(r.label, value: r.value) }
                    ForEach(pending.display.warnings) { w in Text(w.text).foregroundStyle(w.level == "info" ? Color.secondary : Color.red) }
                }
                Section("待签请求：请用签名机扫描") {
                    AnimatedQRView(source: frames)
                    NavigationLink("扫描签名机返回的签名") { EvmSignedView(pending: pending, network: network) }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("发送（\(network.name)）")
        .task { await loadFees() }
        .scrollDismissesKeyboard(.immediately)
        .onChange(of: token) { _, _ in
            estimatedGas = nil
            gasNote = nil
        }
    }

    /// 32 字节大端 → u64（高 24 字节必须为 0）
    private func u64(_ b: [UInt8]) -> UInt64? {
        guard b.count == 32, b.prefix(24).allSatisfy({ $0 == 0 }) else { return nil }
        return b.suffix(8).reduce(0) { $0 << 8 | UInt64($1) }
    }

    /// 选中档位的手续费；自定义时解析 gwei 文本（由 Rust 解析，不用浮点）
    private func selectedFees() throws -> EvmFees {
        if speed == "custom" {
            let maxFee = try EvmAmount.parse(customMaxFee, decimals: 9)
            let prio = try EvmAmount.parse(customPriority.isEmpty ? "0" : customPriority, decimals: 9)
            guard maxFee.contains(where: { $0 != 0 }) else { throw InputError(message: "最高单价不能为 0") }
            // 等长大端数组按字典序比较就是按数值比较
            guard !maxFee.lexicographicallyPrecedes(prio) else { throw InputError(message: "优先费不能高于最高单价") }
            return EvmFees(maxPriorityFee: prio, maxFee: maxFee)
        }
        guard let t = tiers.first(where: { $0.speed == speed }) else {
            throw InputError(message: "还没有获取到手续费：请点“重新获取手续费”，或选“自定义”")
        }
        return EvmFees(maxPriorityFee: t.maxPriorityFee, maxFee: t.maxFee)
    }

    private var maxCostText: String? {
        guard let gas = gasLimit, let fees = try? selectedFees(), let maxFee = u64(fees.maxFee) else { return nil }
        let (v, overflow) = maxFee.multipliedReportingOverflow(by: gas)
        return overflow ? "过大" : "\(EvmAmount.format(v, decimals: 18)) \(network.symbol)"
    }

    private func loadFees() async {
        loadingFees = true
        defer { loadingFees = false }
        do {
            await estimate(from: account.address(index: 0))
            let history = try await rpc.feeHistory()
            let suggested = await rpc.maxPriorityFee()
            let price = history.nextBaseFee == nil ? try await rpc.gasPrice() : 0
            tiers = try EvmAmount.feeTiers(history: history, suggested: suggested, gasPrice: price, gasLimit: gasLimit ?? defaultGas)
            feeError = nil
        } catch let f as WatchCore.Failure {
            feeError = "手续费计算失败：\(f.message)；可以换节点或选“自定义”"
        } catch let e as EvmRPC.RPCError {
            feeError = "节点：\(e.message)；可以换节点或选“自定义”"
        } catch {
            feeError = "\(error.localizedDescription)；可以换节点或选“自定义”"
        }
    }

    /// 估算 gas：转给普通地址的原生币转账正好 21000；代币或合约按估算 × 1.2；估算失败用默认值
    private func estimate(from: String) async {
        let rcpt = to.trimmingCharacters(in: .whitespaces)
        let target = token?.contract ?? rcpt
        guard target.count == 42, target.hasPrefix("0x") else {
            estimatedGas = nil
            gasNote = nil
            return
        }
        do {
            let value = try EvmAmount.parse(amount.isEmpty ? "0" : amount, decimals: token?.decimals ?? 18)
            var data = "0x"
            if token != nil {
                guard rcpt.count == 42, rcpt.hasPrefix("0x") else {
                    estimatedGas = nil
                    return
                }
                data = "0xa9059cbb" + String(repeating: "0", count: 24) + rcpt.dropFirst(2).lowercased()
                    + value.map { String(format: "%02x", $0) }.joined()
            }
            let g = try await rpc.estimateGas(from: from, to: target,
                                              value: token == nil ? EvmAmount.quantity(value) : "0x0", data: data)
            estimatedGas = g == 21_000 ? g : g + g / 5
            gasNote = g == 21_000 ? nil : "节点估算用量 \(g)，上限多留 20%"
        } catch {
            estimatedGas = nil
            gasNote = "节点无法估算 gas，使用\(token == nil ? "普通转账" : "代币转账")的默认上限 \(defaultGas)"
        }
    }

    private func build() async {
        busy = true
        defer { busy = false }
        pending = nil
        frames = nil
        do {
            let addr = account.address(index: 0)
            if gasLimitText.isEmpty { await estimate(from: addr) }
            guard let gas = gasLimit, gas >= 21_000 else { throw InputError(message: "Gas 上限无效（至少 21000）") }
            let fees = try selectedFees()
            let value = try EvmAmount.parse(amount, decimals: token?.decimals ?? 18)
            guard try await rpc.chainId() == network.chainId else { throw InputError(message: "节点的链 ID 与所选网络不一致") }
            let native = try await rpc.balance(addr)
            var tokenBalance: String?
            if let t = token { tokenBalance = try await rpc.tokenBalance(t.contract, owner: addr) }
            try EvmAmount.checkFunds(native: native, token: tokenBalance, value: value, gasLimit: gas, maxFee: fees.maxFee)
            let nonce: UInt64
            if manualNonce {
                guard let n = UInt64(nonceText) else { throw InputError(message: "nonce 必须是整数") }
                nonce = n
            } else {
                nonce = try await rpc.nonce(addr)
            }
            let p = try account.buildTransfer(network: network, nonce: nonce, fees: fees, gasLimit: gas,
                                              to: to.trimmingCharacters(in: .whitespaces), amount: amount, token: token)
            frames = try p.frames()
            pending = p
            error = nil
        } catch let f as WatchCore.Failure {
            switch f.code {
            case AW_ERR_TX_REJECT_BASE - 19:
                error = "\(network.symbol) 余额不够支付\(token == nil ? "金额 + 最高手续费" : "最高手续费")"
            case AW_ERR_TX_REJECT_BASE - 21:
                error = "\(token?.symbol ?? "代币") 余额不足"
            default:
                error = f.message
            }
        } catch let e as InputError {
            error = e.message
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
    @State private var scan = URScan()
    @State private var progress = (got: 0, total: 0)
    @State private var raw: String?
    @State private var txHash: String?
    @State private var broadcastURL = ""
    @State private var broadcasting = false
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
                    BroadcastNodePicker(net: .evm(network), selection: $broadcastURL)
                    Button(broadcasting ? "正在广播…" : "广播") { Task { await broadcast(raw) } }
                        .buttonStyle(.borderedProminent).disabled(broadcasting)
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
        let chosen = broadcastURL.isEmpty ? NodeBook.shared.current(.evm(network)).url : broadcastURL
        guard let url = NodeBook.validURL(chosen) else {
            error = "广播节点地址无效"
            return
        }
        let rpc = EvmRPC(url: url, timeout: 30)
        broadcasting = true
        defer { broadcasting = false }
        do {
            guard try await rpc.chainId() == network.chainId else {
                error = "广播节点的链 ID 与所选网络不一致"
                return
            }
            let returned = try await rpc.sendRaw(hex)
            // 节点返回的哈希必须就是这笔交易的哈希，否则"已广播"可能是假的
            guard let expected = EvmAmount.txHash(rawHex: hex), returned.lowercased() == expected.lowercased() else {
                error = "节点返回的交易哈希与这笔交易不符，广播结果不可信：\(returned)"
                return
            }
            txHash = expected
            error = nil
        } catch let e as EvmRPC.RPCError {
            error = "广播失败：\(e.message)（可以换一个节点再试）"
        } catch {
            self.error = "广播失败：\(error.localizedDescription)（可以换一个节点再试）"
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
