// 测试工具（不进入 App）：用 macOS 系统 CoreImage 从截图中识别二维码，打印内容。
// 用法：xcrun swift tools/testvectors/qr_from_png.swift <截图.png>
import CoreImage
import Foundation

let url = URL(fileURLWithPath: CommandLine.arguments[1])
guard let image = CIImage(contentsOf: url),
      let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
else { fatalError("无法读取图片") }
for case let f as CIQRCodeFeature in detector.features(in: image) {
    print(f.messageString ?? "")
}
