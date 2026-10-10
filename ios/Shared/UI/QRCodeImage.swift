import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

/// 用系统 CoreImage 生成二维码（决策 D9：不引入第三方二维码库）。
enum QRCodeImage {
    /// UR 帧是大写字母数字，用 L 级纠错即可（动画中丢帧由喷泉码弥补）。
    static func make(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "L"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cg = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

/// 一组动画二维码帧的来源（由 Rust 编码器提供，可无限生成喷泉码帧）。
@MainActor
protocol QRFrameSource: AnyObject {
    var partCount: Int { get }
    func nextFrame() -> String?
}

/// 循环播放动画二维码。每 0.25 秒一帧。
struct AnimatedQRView: View {
    let source: QRFrameSource
    @State private var image: UIImage?
    @State private var shown = 0

    var body: some View {
        VStack(spacing: 12) {
            TimelineView(.periodic(from: .now, by: 0.25)) { context in
                Group {
                    if let image {
                        Image(uiImage: image)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                    } else {
                        ProgressView()
                    }
                }
                .onChange(of: context.date) { advance() }
            }
            .frame(maxWidth: 360, maxHeight: 360)
            .padding(12)
            .background(Color.white)
            .accessibilityIdentifier("animated-qr")
            Text(source.partCount > 1 ? "动画二维码 · 共 \(source.partCount) 段 · 已播放 \(shown) 帧" : "单帧二维码")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .onAppear { advance() }
    }

    private func advance() {
        guard let frame = source.nextFrame() else { return }
        image = QRCodeImage.make(frame)
        shown += 1
    }
}
