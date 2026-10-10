import SwiftUI

struct AccountView: View {
    let account: WatchAccount
    let onRemove: () -> Void
    @State private var receiveIndex: UInt32 = 0
    @State private var utxos: [UTXO] = []
    @State private var nextChange: UInt32 = 0
    @State private var loading = false
    @State private var error: String?
    @ObservedObject private var book = NodeBook.shared

    private var nodeNet: NodeNetwork { .bitcoin(testnet: account.isTestnet) }

    /// 当前节点（查询、获取费率；广播时可以另选）
    private var esplora: Esplora? {
        NodeBook.validURL(book.current(nodeNet).url).map { Esplora(base: $0) }
    }

    private var balance: UInt64 { utxos.reduce(0) { $0 + $1.value } }

    var body: some View {
        List {
            Section {
                LabeledContent("钱包指纹", value: account.fingerprint).font(.system(.body, design: .monospaced))
                    .accessibilityIdentifier("watch-fingerprint")
                LabeledContent("网络", value: account.isTestnet ? "测试网" : "主网")
            } footer: {
                Text("请与签名机上显示的指纹核对。")
            }
            Section("收款地址 m/84'/…/0/\(receiveIndex)") {
                let addr = account.address(change: false, index: receiveIndex)
                if let img = QRCodeImage.make(addr.uppercased()) {
                    Image(uiImage: img).interpolation(.none).resizable().scaledToFit().frame(maxWidth: 220)
                        .frame(maxWidth: .infinity)
                }
                Text(addr).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                    .accessibilityIdentifier("receive-address")
                if let u = Explorer.bitcoinAddress(addr, testnet: account.isTestnet) {
                    Link("在区块浏览器查看（mempool.space）", destination: u)
                    Text(verbatim: u.absoluteString).font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary).textSelection(.enabled)
                }
                Button("下一个地址") { receiveIndex += 1 }
            }
            Section {
                LabeledContent("余额", value: "\(balance) 聪（\(utxos.count) 个 UTXO）")
                Button(loading ? "查询中…" : "刷新余额") { Task { await refresh() } }.disabled(loading || esplora == nil)
                NavigationLink("付款") {
                    PayView(account: account, utxos: utxos, changeIndex: nextChange, esplora: esplora, net: nodeNet)
                }
                .disabled(utxos.isEmpty)
            }
            Section("设置") {
                NodeSummaryRow(net: nodeNet)
                Button("删除此账户", role: .destructive) { onRemove() }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("观察钱包")
    }

    /// 扫描收款 0–19 与找零 0–9 地址；记录下一个未使用的找零地址。
    private func refresh() async {
        guard let esplora else { return }
        loading = true
        defer { loading = false }
        do {
            var found = [UTXO]()
            var firstUnusedChange: UInt32?
            for (change, count) in [(false, UInt32(20)), (true, UInt32(10))] {
                for i in 0..<count {
                    let addr = account.address(change: change, index: i)
                    let used = try await esplora.txCount(address: addr) > 0
                    if used {
                        found += try await esplora.utxos(address: addr, change: change, index: i)
                    } else if change, firstUnusedChange == nil {
                        firstUnusedChange = i
                    }
                }
            }
            utxos = found
            nextChange = firstUnusedChange ?? 10
            error = nil
        } catch {
            self.error = "查询失败：\(error.localizedDescription)"
        }
    }
}
