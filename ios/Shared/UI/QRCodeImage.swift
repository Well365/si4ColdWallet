import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

/// 用系统 CoreImage 生成二维码（决策 D9：不引入第三方二维码库）。
enum QRCodeImage {
    /// 共用一个渲染上下文：每帧新建一个代价很高，动画二维码会占满主线程、界面失去响应
    private static let context = CIContext()

    /// UR 帧是大写字母数字，用 L 级纠错即可（动画中丢帧由喷泉码弥补）。
    /// 按每个模块 1 像素生成，由界面用 `.interpolation(.none)` 放大，既清晰又省计算。
    static func make(_ text: String) -> UIImage? {
        makeCG(text).map { UIImage(cgImage: $0) }
    }

    /// 可在后台线程调用（CIContext 线程安全）
    nonisolated static func makeCG(_ text: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "L"
        guard let output = filter.outputImage else { return nil }
        return context.createCGImage(output, from: output.extent)
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
    /// 上一帧还在生成时跳过本次（帧较密时生成可能慢于 0.25 秒）
    @State private var rendering = false

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

    /// 二维码图像在后台线程生成，主线程只负责显示：否则帧较密时主线程被占满，界面无法滚动
    private func advance() {
        guard !rendering, let frame = source.nextFrame() else { return }
        rendering = true
        Task {
            let cg = await Task.detached(priority: .userInitiated) { QRCodeImage.makeCG(frame) }.value
            image = cg.map { UIImage(cgImage: $0) }
            shown += 1
            rendering = false
        }
    }
}
