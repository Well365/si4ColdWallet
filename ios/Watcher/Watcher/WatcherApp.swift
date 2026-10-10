import SwiftUI
import UIKit

/// 观察机入口。只持有公钥；联网查询余额、构造交易、广播。
@main
struct WatcherApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                WatcherRoot().tabItem { Label("比特币", systemImage: "bitcoinsign.circle") }
                EvmTab().tabItem { Label("以太坊 / BNB", systemImage: "diamond") }
            }
        }
    }
}

/// 账户以 UR 字符串保存在本机（只是公钥，不是秘密）。
struct WatcherRoot: View {
    @AppStorage("account-ur") private var accountUR = ""
    @State private var account: WatchAccount?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Group {
                if let account {
                    AccountView(account: account) {
                        accountUR = ""
                        self.account = nil
                    }
                } else {
                    ImportAccountView { acct in
                        accountUR = acct.urString
                        account = acct
                    }
                }
            }
            .task { restore() }
        }
    }

    private func restore() {
        guard account == nil, !accountUR.isEmpty else { return }
        do {
            account = try WatchAccount.from(ur: accountUR)
        } catch {
            accountUR = ""
        }
    }
}

struct ImportAccountView: View {
    let onImported: (WatchAccount) -> Void
    @State private var scan = URScan()
    @State private var error: String?

    var body: some View {
        VStack(spacing: 16) {
            Text("在签名机上打开\"显示账户公钥二维码\"，然后扫描。").multilineTextAlignment(.center)
            QRScannerView { text in receive(text) }
                .frame(height: 360)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            Button("从剪贴板导入（UR 文本）") { importFromPasteboard() }
                .accessibilityIdentifier("import-paste")
            if let error { Text(error).foregroundStyle(.red) }
        }
        .padding()
        .navigationTitle("导入账户")
    }

    /// 观察机是联网设备，允许剪贴板；签名机禁止（检查 C9）。
    private func importFromPasteboard() {
        guard let text = UIPasteboard.general.string, !text.isEmpty else {
            error = "剪贴板为空"
            return
        }
        do {
            onImported(try WatchAccount.from(ur: text.trimmingCharacters(in: .whitespacesAndNewlines)))
        } catch let f as WatchCore.Failure {
            error = f.message
        } catch {
            self.error = "\(error)"
        }
    }

    private func receive(_ text: String) {
        do {
            if try scan.receive(text) {
                onImported(try WatchAccount.from(scan: scan))
            }
        } catch let f as WatchCore.Failure {
            error = f.message
            scan = URScan()
        } catch {
            self.error = "\(error)"
        }
    }
}
