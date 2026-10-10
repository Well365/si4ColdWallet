import SwiftUI

/// 签名机的状态机：自检 → 建立/恢复钱包 → 已解锁。
struct RootView: View {
    enum Stage {
        case checking
        case failed(String)
        case setup
        case unlocked(SignerSession)
    }

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
            case .setup:
                SetupView { session in stage = .unlocked(session) }
            case .unlocked(let session):
                NavigationStack {
                    WalletView(session: session) { stage = .setup }
                }
            }
        }
    }

    private func runCheck() {
        switch AWCore.startupCheck() {
        case .success: stage = .setup
        case .failure(let f): stage = .failed(f.message)
        }
    }
}
