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

/// 截屏、录屏、投屏都看不到的文字（威胁 T10，审计 P1-8）：把文字放进 isSecureTextEntry 输入框的安全图层。
/// 输入框从不成为第一响应者、不接受交互，所以不会弹出键盘。
/// 系统实现变了、找不到安全图层时退回普通显示（截屏提醒仍然有效）。
struct SecureText: UIViewRepresentable {
    let text: String

    func makeUIView(context: Context) -> UIView {
        let label = UILabel()
        label.text = text
        label.font = .monospacedSystemFont(ofSize: UIFont.preferredFont(forTextStyle: .body).pointSize, weight: .regular)
        label.textColor = .label
        let field = UITextField()
        field.isSecureTextEntry = true
        field.isUserInteractionEnabled = false
        guard let secure = field.layer.sublayers?.first?.delegate as? UIView else { return label }
        secure.subviews.forEach { $0.removeFromSuperview() }
        secure.isUserInteractionEnabled = false
        label.translatesAutoresizingMaskIntoConstraints = false
        secure.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: secure.leadingAnchor),
            label.trailingAnchor.constraint(equalTo: secure.trailingAnchor),
            label.centerYAnchor.constraint(equalTo: secure.centerYAnchor),
        ])
        return secure
    }

    func updateUIView(_ uiView: UIView, context: Context) {}
}

