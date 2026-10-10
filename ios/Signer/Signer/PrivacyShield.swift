import SwiftUI
import UIKit

/// 隐私遮罩（威胁 T10）：切到后台（App 切换器快照）或屏幕被录制/投屏时遮住全部内容；
/// 检测到截屏时提示用户立即删除截图。
struct PrivacyShield: ViewModifier {
    @Environment(\.scenePhase) private var phase
    @State private var captured = UIScreen.main.isCaptured
    @State private var screenshotWarning = false

    func body(content: Content) -> some View {
        content
            .overlay {
                if phase != .active || captured {
                    ZStack {
                        Color(uiColor: .systemBackground)
                        Label(captured ? "检测到屏幕录制/投屏，内容已隐藏" : "已隐藏", systemImage: "eye.slash")
                            .foregroundStyle(.secondary)
                    }
                    .ignoresSafeArea()
                }
            }
            .alert("检测到截屏", isPresented: $screenshotWarning) {
                Button("知道了", role: .cancel) {}
            } message: {
                Text("截图可能包含敏感信息，请立即在相册中删除，并清空\"最近删除\"。")
            }
            .task {
                for await _ in NotificationCenter.default.notifications(named: UIScreen.capturedDidChangeNotification) {
                    captured = UIScreen.main.isCaptured
                }
            }
            .task {
                for await _ in NotificationCenter.default.notifications(named: UIApplication.userDidTakeScreenshotNotification) {
                    screenshotWarning = true
                }
            }
    }
}

extension View {
    func privacyShield() -> some View { modifier(PrivacyShield()) }
}
