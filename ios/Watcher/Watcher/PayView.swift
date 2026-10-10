import SwiftUI

/// 付款（决策 D35）：收款人与金额 → 费率档位（快 / 标准 / 慢 / 经济 / 自定义）→ 构造 → 签名机扫码
struct PayView: View {
    let account: WatchAccount
    let utxos: [UTXO]
    let changeIndex: UInt32
    let esplora: Esplora?
    let net: NodeNetwork
    @State private var to = ""
    @State private var amount = ""
    @State private var tiers: [Esplora.FeeTier] = []
    @State private var feeKey = "standard"
    @State private var customRate = ""
    @State private var feeError: String?
    @State private var loadingFees = false
    @State private var pending: PendingPayment?
    @State private var frames: URFrames?
    @State private var error: String?

    /// 选中的费率（sat/vB）
    private var rate: UInt64? {
        feeKey == "custom" ? UInt64(customRate) : tiers.first { $0.key == feeKey }?.satPerVb
    }

    var body: some View {
        Form {
            Section("收款人") {
                TextField(account.isTestnet ? "tb1…" : "bc1…", text: $to)
                    .keyboardType(.asciiCapable)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
                TextField("金额（聪）", text: $amount).keyboardType(.numberPad)
            }
            Section {
                Picker("费率", selection: $feeKey) {
                    ForEach(tiers) { t in Text("\(t.label) · \(t.satPerVb) sat/vB").tag(t.key) }
                    Text("自定义").tag("custom")
                }
                .pickerStyle(.inline)
                .labelsHidden()
                if feeKey == "custom" {
                    TextField("费率（sat/vB，整数）", text: $customRate).keyboardType(.numberPad)
                }
                if let feeError { Text(feeError).font(.footnote).foregroundStyle(.red) }
                Button(loadingFees ? "正在获取…" : "重新获取费率") { Task { await loadFees() } }.disabled(loadingFees || esplora == nil)
            } header: {
                Text("手续费")
            } footer: {
                Text("手续费 = 交易大小（vB）× 费率，构造后显示实际金额。签名机对超过付款 5% 或 0.001 BTC 的手续费会强警告。")
            }
            Section {
                Button("构造交易") { build() }.bold()
            }
            if let pending, let frames {
                Section("待签交易：请用签名机扫描") {
                    LabeledContent("付款", value: "\(pending.summary.amountSat) 聪")
                    LabeledContent("手续费", value: "\(pending.summary.feeSat) 聪（约 \(pending.summary.vsizeEstimate) vB）")
                    LabeledContent("找零", value: pending.summary.changeSat.map { "\($0) 聪" } ?? "无")
                    LabeledContent("总计扣除", value: "\(pending.summary.amountSat + pending.summary.feeSat) 聪")
                    AnimatedQRView(source: frames)
                    NavigationLink("扫描签名机返回的签名") {
                        SignedScanView(pending: pending, net: net)
                    }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("付款")
        .scrollDismissesKeyboard(.immediately)
        .task { if tiers.isEmpty { await loadFees() } }
    }

    private func loadFees() async {
        guard let esplora else { return }
        loadingFees = true
        defer { loadingFees = false }
        do {
            tiers = try await esplora.feeTiers()
            feeError = nil
        } catch {
            feeError = "获取费率失败：\(error.localizedDescription)；可以换节点或选“自定义”"
            if tiers.isEmpty { feeKey = "custom" }
        }
    }

    private func build() {
        guard let amt = UInt64(amount), let rate, rate > 0 else {
            error = "金额与费率必须是正整数"
            return
        }
        do {
            let p = try account.buildPayment(utxos: utxos, to: to.trimmingCharacters(in: .whitespaces), amount: amt, feeRate: rate, changeIndex: changeIndex)
            frames = try p.frames()
            pending = p
            error = nil
        } catch let f as WatchCore.Failure {
            error = f.message
        } catch {
            self.error = "\(error)"
        }
    }
}

struct SignedScanView: View {
    let pending: PendingPayment
    let net: NodeNetwork
    @State private var scan = URScan()
    @State private var progress = (got: 0, total: 0)
    @State private var txHex: String?
    @State private var txid: String?
    @State private var broadcastURL = ""
    @State private var broadcasting = false
    @State private var error: String?

    private var testnet: Bool {
        if case .esplora(let t) = net.kind { return t }
        return false
    }

    var body: some View {
        VStack(spacing: 12) {
            if let txHex {
                Text("签名已验证，交易已就绪").font(.headline).foregroundStyle(.green)
                ScrollView { Text(txHex).font(.system(.caption2, design: .monospaced)).textSelection(.enabled) }
                    .frame(maxHeight: 200)
                if let txid {
                    Text("已广播：\(txid)").font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                    if let u = Explorer.url(testnet ? "https://mempool.space/testnet4/tx/" : "https://mempool.space/tx/", txid) {
                        Link("在区块浏览器查看", destination: u)
                    }
                } else {
                    BroadcastNodePicker(net: net, selection: $broadcastURL)
                    Button(broadcasting ? "正在广播…" : "广播") { Task { await broadcast(txHex) } }
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
            if done { txHex = try pending.finalize(signedPSBT: try scan.takePSBT()) }
        } catch let f as WatchCore.Failure {
            error = f.message
            scan = URScan()
        } catch {
            self.error = "\(error)"
        }
    }

    private func broadcast(_ hex: String) async {
        let chosen = broadcastURL.isEmpty ? NodeBook.shared.current(net).url : broadcastURL
        guard let url = NodeBook.validURL(chosen) else {
            error = "广播节点地址无效"
            return
        }
        let esplora = Esplora(base: url, timeout: 30)
        broadcasting = true
        defer { broadcasting = false }
        do {
            // 广播前确认节点的网络（主网 / testnet4）与账户一致
            guard try await esplora.genesisHash() == (testnet ? Esplora.testnet4Genesis : Esplora.mainnetGenesis) else {
                error = "广播节点的网络与账户不一致"
                return
            }
            let id = try await esplora.broadcast(txHex: hex).trimmingCharacters(in: .whitespacesAndNewlines)
            txid = id
            error = nil
        } catch let e as Esplora.BroadcastError {
            error = "广播失败：\(e.message)（可以换一个节点再试）"
        } catch {
            self.error = "广播失败：\(error.localizedDescription)（可以换一个节点再试）"
        }
    }
}
