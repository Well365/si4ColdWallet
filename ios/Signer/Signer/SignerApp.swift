import SwiftUI
import UIKit

/// 签名机入口。此 App 不包含任何网络代码（检查 C4/C9 会扫描源码与最终二进制）。
@main
struct SignerApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            RootView()
                .privacyShield()
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    /// 禁止第三方键盘（威胁 T10：第三方键盘可以记录输入）。
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}
