import AWWatchC
import SwiftUI
import UIKit

/// Solana 标签页（P2c）：账户只是地址 + 账户类型 + 序号，保存在本机（公开信息）
struct SolTab: View {
    @AppStorage("sol-account") private var stored = ""
    @State private var account: SolAccount?

    var body: some View {
        NavigationStack {
            Group {
                if let account {
                    SolAccountView(account: account) {
                        stored = ""
                        self.account = nil
                    }
                } else {
                    SolImportView { acct in
                        stored = (try? String(decoding: JSONEncoder().encode(acct), as: UTF8.self)) ?? ""
                        account = acct
                    }
                }
            }
            .task {
                if account == nil, let d = stored.data(using: .utf8) { account = try? JSONDecoder().decode(SolAccount.self, from: d) }
            }
        }
    }
}

/// 导入：扫描签名机“收款地址”页上 Solana 地址的二维码（或粘贴），再选与签名机上相同的账户类型和序号
struct SolImportView: View {
    let onImported: (SolAccount) -> Void
    @State private var address = ""
    @State private var scheme = SolScheme.phantom
    @State private var index: UInt32 = 0
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                QRScannerView { text in address = text.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .frame(height: 200)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                TextField("Solana 地址", text: $address)
                    .keyboardType(.asciiCapable)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
                Button("从剪贴板粘贴") { address = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "" }
            } header: {
                Text("在签名机的“收款地址”页选 SOL，扫描它的二维码")
            }
            Section {
                Picker("账户类型", selection: $scheme) {
                    ForEach(SolScheme.allCases) { Text($0.title).tag($0) }
                }
                Stepper("序号 #\(index)", value: $index, in: 0...scheme.maxIndex)
            } footer: {
                Text("必须与签名机上这个地址的账户类型和序号一致；不一致时签名机会拒签，不会签错。")
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("导入 Solana 账户")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("导入") { importAccount() }.bold().disabled(address.isEmpty)
            }
        }
        .onChange(of: scheme) { _, s in if index > s.maxIndex { index = 0 } }
    }

    private func importAccount() {
        guard SolCore.parseAddress(address) != nil else {
            error = "不是有效的 Solana 地址"
            return
        }
        onImported(SolAccount(address: address, scheme: scheme, index: index))
    }
}

struct SolAccountView: View {
    let account: SolAccount
    let onForget: () -> Void
    @AppStorage("sol-network") private var genesis = SolNetwork.all[0].genesis
    @ObservedObject private var book = NodeBook.shared
    @State private var balances: [String: String] = [:]
    @State private var error: String?

    private var network: SolNetwork { SolNetwork.all.first { $0.genesis == genesis } ?? SolNetwork.all[0] }
    private var nodeNet: NodeNetwork { .solana(network) }
    private var rpc: SolRPC? { NodeBook.validURL(book.current(nodeNet).url).map { SolRPC(url: $0) } }

    var body: some View {
        List {
            Section {
                Picker("网络", selection: $genesis) {
                    ForEach(SolNetwork.all) { Text($0.name).tag($0.genesis) }
                }
                LabeledContent("账户类型", value: "\(account.scheme.title) #\(account.index)")
            }
            Section("地址") {
                Text(account.address).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                if let u = network.addressURL(account.address) {
                    Link("在区块浏览器查看", destination: u)
                }
            }
            Section("余额（\(network.name)）") {
                LabeledContent("SOL", value: balances[""] ?? "—")
                ForEach(network.tokens) { t in LabeledContent(t.symbol, value: balances[t.mint] ?? "—") }
                Button("刷新") { Task { await refresh() } }
            }
            Section {
                NodeSummaryRow(net: nodeNet)
                if let rpc {
                    NavigationLink("发送") { SolPayView(account: account, network: network, rpc: rpc) }
                } else {
                    Text("节点地址无效（必须是 https）").foregroundStyle(.red)
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Section { Button("移除此账户", role: .destructive) { onForget() } }
        }
        .navigationTitle("Solana 账户")
        .task(id: "\(genesis)-\(book.current(nodeNet).url)") { await refresh() }
    }

    private func refresh() async {
        // 先清空：切换网络或查询失败时不能留着上一个网络的余额
        balances = [:]
        guard let rpc, let owner = account.key else { return }
        do {
            guard try await rpc.genesisHash() == network.genesis else {
                error = "节点的网络与所选网络不一致"
                return
            }
            var b: [String: String] = [:]
            b[""] = SolCore.format(try await rpc.balance(account.address), decimals: 9)
            for t in network.tokens {
                guard let mint = SolCore.parseAddress(t.mint), let ata = SolCore.ata(owner: owner, mint: mint) else { continue }
                b[t.mint] = SolCore.format(try await rpc.tokenBalance(ata), decimals: t.decimals)
            }
            balances = b
            error = nil
        } catch let e as SolRPC.RPCError {
            error = "查询失败：\(e.message)"
        } catch {
            self.error = "查询失败：\(error.localizedDescription)"
        }
    }
}

/// 发送（决策 D37）：收款人与金额 → 优先费档位（慢 / 标准 / 快 / 自定义）→ 核对余额 → 构造 → 签名机扫码
struct SolPayView: View {
    let account: SolAccount
    let network: SolNetwork
    let rpc: SolRPC

    private struct InputError: Error { let message: String }

    @State private var token: SolToken?
    @State private var to = ""
    @State private var amount = ""
    @State private var tiers: [SolFeeTier] = []
    @State private var speed = "standard"
    @State private var customPrice = ""
    @State private var feeError: String?
    @State private var pending: SolPending?
    @State private var frames: URFrames?
    @State private var busy = false
    @State private var error: String?

    /// 计算单元上限：SOL 转账约 450 单元、代币转账（含按需建账户）约 3 万，各留余量
    private var unitLimit: UInt32 { token == nil ? 1_000 : 60_000 }

    private var price: UInt64? {
        speed == "custom" ? UInt64(customPrice) : tiers.first { $0.speed == speed }?.price
    }

    /// 最高手续费（lamports）= 5000 + ⌈价格 × 上限 / 10⁶⌉
    private var maxFee: UInt64? {
        guard let price else { return nil }
        let (prod, o) = price.multipliedReportingOverflow(by: UInt64(unitLimit))
        return o ? nil : 5_000 + (prod + 999_999) / 1_000_000
    }

    var body: some View {
        Form {
            Section("收款人与金额") {
                Picker("资产", selection: $token) {
                    Text("SOL").tag(SolToken?.none)
                    ForEach(network.tokens) { Text($0.symbol).tag(SolToken?.some($0)) }
                }
                TextField("收款地址", text: $to)
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
                    TextField("优先费（微 lamports / 计算单元）", text: $customPrice).keyboardType(.numberPad)
                } else if let t = tiers.first(where: { $0.speed == speed }) {
                    LabeledContent("优先费", value: "\(t.price) 微 lamports / 单元")
                }
                LabeledContent("计算单元上限", value: "\(unitLimit)")
                if let maxFee { LabeledContent("最多手续费", value: "\(SolCore.format(maxFee, decimals: 9)) SOL") }
                if let feeError { Text(feeError).font(.footnote).foregroundStyle(.red) }
                Button("重新获取优先费") { Task { await loadTiers() } }
            } header: {
                Text("手续费")
            } footer: {
                Text("手续费 = 5000 lamports + 优先费 × 计算单元上限 / 10⁶。签名机会再显示一遍“总计最多扣除”，请两边对照。")
            }
            Section {
                Button(busy ? "正在向节点查询…" : "核对余额并构造交易") { Task { await build() } }.bold().disabled(busy)
            }
            if let pending, let frames {
                Section("签名机将显示（请逐行对照）：\(pending.display.title)") {
                    ForEach(pending.display.rows) { r in LabeledContent(r.label, value: r.value) }
                    ForEach(pending.display.warnings) { w in Text(w.text).foregroundStyle(w.level == "info" ? Color.secondary : Color.red) }
                }
                Section("待签请求：请用签名机扫描（最近区块哈希约 1 分钟后过期，请尽快完成）") {
                    AnimatedQRView(source: frames)
                    NavigationLink("扫描签名机返回的签名") { SolSignedView(pending: pending, network: network) }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("发送（\(network.name)）")
        .scrollDismissesKeyboard(.immediately)
        .task { await loadTiers() }
    }

    private func loadTiers() async {
        do {
            let samples = try await rpc.prioritizationFees([account.address])
            tiers = try SolCore.tiers(samples: samples, unitLimit: unitLimit)
            feeError = nil
        } catch {
            feeError = "获取优先费失败：\(error.localizedDescription)；可以换节点或选“自定义”"
            if tiers.isEmpty { speed = "custom" }
        }
    }

    private func build() async {
        busy = true
        defer { busy = false }
        pending = nil
        frames = nil
        do {
            guard let price, let maxFee else { throw InputError(message: "请选择手续费档位，或填写自定义优先费") }
            let decimals = token?.decimals ?? 9
            let value = try SolCore.parseAmount(amount, decimals: decimals)
            guard value > 0 else { throw InputError(message: "金额必须大于 0") }
            guard SolCore.parseAddress(to) != nil else { throw InputError(message: "收款地址不是有效的 Solana 地址") }
            guard try await rpc.genesisHash() == network.genesis else { throw InputError(message: "节点的网络与所选网络不一致") }
            // 构造前核对余额：SOL 要够"金额 + 最多手续费"（发代币时只算手续费），代币要够数量
            let sol = try await rpc.balance(account.address)
            let (need, o) = (token == nil ? value : 0).addingReportingOverflow(maxFee)
            guard !o, sol >= need else {
                throw InputError(message: token == nil
                                 ? "SOL 余额不够支付金额 + 最多手续费"
                                 : "SOL 余额不够支付最多手续费（发代币时还可能需要约 0.002 SOL 为收款方建代币账户）")
            }
            if let t = token {
                guard let owner = account.key, let mint = SolCore.parseAddress(t.mint),
                      let ata = SolCore.ata(owner: owner, mint: mint) else { throw InputError(message: "代币账户推导失败") }
                guard try await rpc.tokenBalance(ata) >= value else { throw InputError(message: "\(t.symbol) 余额不足") }
            }
            let blockhash = try await rpc.latestBlockhash()
            let p = try SolPending.build(account: account, to: to, amount: value, token: token, blockhash: blockhash,
                                         unitLimit: unitLimit, unitPrice: price)
            frames = try p.frames()
            pending = p
            error = nil
        } catch let e as InputError {
            error = e.message
        } catch let f as WatchCore.Failure {
            error = f.message
        } catch let e as SolRPC.RPCError {
            error = "节点：\(e.message)"
        } catch {
            self.error = "\(error.localizedDescription)"
        }
    }
}

struct SolSignedView: View {
    let pending: SolPending
    let network: SolNetwork
    @State private var scan = URScan()
    @State private var progress = (got: 0, total: 0)
    @State private var done: SolFinalized?
    @State private var sent: String?
    @State private var broadcastURL = ""
    @State private var broadcasting = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            if let done {
                Text("签名已验证，交易已就绪").font(.headline).foregroundStyle(.green)
                Text("交易号：\(done.txid)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                if let sent {
                    Text("已广播").font(.headline)
                    if let u = network.txURL(sent) { Link("在区块浏览器查看", destination: u) }
                } else {
                    BroadcastNodePicker(net: .solana(network), selection: $broadcastURL)
                    Button(broadcasting ? "正在广播…" : "广播") { Task { await broadcast(done) } }
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
            let finished = try scan.receive(text)
            progress = scan.progress
            if finished { done = try pending.finalize(scan: scan) }
        } catch let f as WatchCore.Failure {
            error = f.message
            scan = URScan()
        } catch {
            self.error = "\(error)"
        }
    }

    private func broadcast(_ f: SolFinalized) async {
        let chosen = broadcastURL.isEmpty ? NodeBook.shared.current(.solana(network)).url : broadcastURL
        guard let url = NodeBook.validURL(chosen) else {
            error = "广播节点地址无效"
            return
        }
        let rpc = SolRPC(url: url, timeout: 30)
        broadcasting = true
        defer { broadcasting = false }
        do {
            guard try await rpc.genesisHash() == network.genesis else {
                error = "广播节点的网络与所选网络不一致"
                return
            }
            let b64 = Data(try Esplora.bytes(f.txHex)).base64EncodedString()
            let returned = try await rpc.send(base64: b64)
            // 节点返回的交易签名必须就是这笔交易的签名，否则“已广播”可能是假的
            guard returned == f.txid else {
                error = "节点返回的交易签名与这笔交易不符，广播结果不可信：\(returned)"
                return
            }
            sent = returned
            error = nil
        } catch let e as SolRPC.RPCError {
            error = "广播失败：\(e.message)（区块哈希可能已过期，需要重新构造；也可以换一个节点再试）"
        } catch {
            self.error = "广播失败：\(error.localizedDescription)"
        }
    }
}
