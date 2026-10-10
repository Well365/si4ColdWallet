import SwiftUI

struct PayView: View {
    let account: WatchAccount
    let utxos: [UTXO]
    let changeIndex: UInt32
    let esplora: Esplora?
    @State private var to = ""
    @State private var amount = ""
    @State private var feeRate = ""
    @State private var pending: PendingPayment?
    @State private var frames: URFrames?
    @State private var error: String?

    var body: some View {
        Form {
            Section("收款人") {
                TextField(account.isTestnet ? "tb1…" : "bc1…", text: $to)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
                TextField("金额（聪）", text: $amount).keyboardType(.numberPad)
                TextField("费率（sat/vB）", text: $feeRate).keyboardType(.numberPad)
            }
            Section {
                Button("构造交易") { build() }.bold()
            }
            if let pending, let frames {
                Section("待签交易：请用签名机扫描") {
                    LabeledContent("付款", value: "\(pending.summary.amountSat) 聪")
                    LabeledContent("手续费", value: "\(pending.summary.feeSat) 聪")
                    LabeledContent("找零", value: pending.summary.changeSat.map { "\($0) 聪" } ?? "无")
                    AnimatedQRView(source: frames)
                    NavigationLink("扫描签名机返回的签名") {
                        SignedScanView(pending: pending, esplora: esplora)
                    }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("付款")
        .task {
            if feeRate.isEmpty, let fees = try? await esplora?.recommendedFees() { feeRate = String(fees.halfHourFee) }
        }
    }

    private func build() {
        guard let amt = UInt64(amount), let rate = UInt64(feeRate) else {
            error = "金额与费率必须是整数"
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
    let esplora: Esplora?
    @State private var scan = URScan()
    @State private var progress = (got: 0, total: 0)
    @State private var txHex: String?
    @State private var txid: String?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 12) {
            if let txHex {
                Text("签名已验证，交易已就绪").font(.headline).foregroundStyle(.green)
                ScrollView { Text(txHex).font(.system(.caption2, design: .monospaced)).textSelection(.enabled) }
                    .frame(maxHeight: 200)
                if let txid {
                    Text("已广播：\(txid)").font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                } else {
                    Button("广播") { Task { await broadcast(txHex) } }.buttonStyle(.borderedProminent).disabled(esplora == nil)
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
        guard let esplora else { return }
        do {
            txid = try await esplora.broadcast(txHex: hex)
        } catch let e as Esplora.BroadcastError {
            error = "广播失败：\(e.message)"
        } catch {
            self.error = "广播失败：\(error.localizedDescription)"
        }
    }
}
