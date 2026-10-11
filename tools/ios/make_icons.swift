#!/usr/bin/env swift
// airgap-wallet 图标生成器（决策 D38）：沿用 si4 家族风格——绿色方底、45° 斜放的蓝 / 浅绿双色胶囊；
// 胶囊从中间断开留出一道"空气间隙"（air gap），中间放各自的图形：
//   签名机 Signer：白色挂锁（离线保管、签名）
//   观察机 Watcher：白色眼睛（只看不签）
// 输出：不透明 8 位 sRGB PNG（没有 alpha、没有预先圆角，iOS 自己加遮罩），符合 App Store 图标规格。
// 用法：
//   swift tools/ios/make_icons.swift                 生成两个 App 的 1024×1024 图标到各自的 Assets.xcassets
//   swift tools/ios/make_icons.swift --preview <png> 生成并排预览图（另含 60/120 px 小尺寸）
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

func rgb(_ hex: UInt32) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
}

// si4 家族配色
let green: UInt32 = 0x2E7F47, darkGreen: UInt32 = 0x1E5A33, white: UInt32 = 0xFFFFFF
let lightGreen: UInt32 = 0x9FD9B4, blue: UInt32 = 0x4A8DFF

enum Glyph { case padlock, eye }

let tilt: CGFloat = 45 * .pi / 180
let capsuleAspect: CGFloat = 2.05   // 长 / 粗
let gapWidth: CGFloat = 0.24        // 空气间隙宽度（以胶囊粗细为单位）
let safeFraction: CGFloat = 0.76    // 四周各留 12%
let glyphFill: CGFloat = 0.60       // 图形占胶囊粗细的比例：两侧要露出空气间隙

/// 胶囊粗细（像素）：让 45° 斜放的胶囊外接框落在安全区里
func thickness(_ size: CGFloat) -> CGFloat {
    let core = capsuleAspect - 1
    let bb = core * cos(tilt) + 1
    return size * safeFraction / bb
}

func drawCapsule(_ ctx: CGContext, t: CGFloat) {
    let L = capsuleAspect * t
    let rect = CGRect(x: -L / 2, y: -t / 2, width: L, height: t)
    ctx.saveGState()
    ctx.rotate(by: tilt) // CoreGraphics 的 y 轴向上：向右上方升起
    ctx.addPath(CGPath(roundedRect: rect, cornerWidth: t / 2, cornerHeight: t / 2, transform: nil))
    ctx.clip()
    ctx.setFillColor(rgb(blue)); ctx.fill(CGRect(x: -L / 2, y: -t / 2, width: L / 2, height: t))
    ctx.setFillColor(rgb(lightGreen)); ctx.fill(CGRect(x: 0, y: -t / 2, width: L / 2, height: t))
    // 空气间隙：露出底色，两侧各一道深绿细边
    let g = gapWidth * t, edge = max(0.035 * t, 1)
    ctx.setFillColor(rgb(darkGreen)); ctx.fill(CGRect(x: -g / 2 - edge, y: -t / 2, width: g + 2 * edge, height: t))
    ctx.setFillColor(rgb(green)); ctx.fill(CGRect(x: -g / 2, y: -t / 2, width: g, height: t))
    ctx.restoreGState()
}

/// 挂锁（以 k 为尺寸单位，原点居中）
func drawPadlock(_ ctx: CGContext, k: CGFloat) {
    let bw = 0.78 * k, bh = 0.60 * k, radius = 0.13 * k
    let rise = 0.40 * k, stroke = 0.16 * k
    let bodyRect = CGRect(x: -bw / 2, y: -bh / 2 - rise / 2, width: bw, height: bh)
    let body = CGPath(roundedRect: bodyRect, cornerWidth: radius, cornerHeight: radius, transform: nil)
    let r = (0.55 * k - stroke) / 2
    let arcY = bodyRect.maxY + rise - stroke / 2 - r
    let shackle = CGMutablePath()
    shackle.move(to: CGPoint(x: -r, y: bodyRect.midY))
    shackle.addLine(to: CGPoint(x: -r, y: arcY))
    shackle.addArc(center: CGPoint(x: 0, y: arcY), radius: r, startAngle: .pi, endAngle: 0, clockwise: true)
    shackle.addLine(to: CGPoint(x: r, y: bodyRect.midY))
    let shackleFill = shackle.copy(strokingWithWidth: stroke, lineCap: .butt, lineJoin: .round, miterLimit: 4)
    let parts: [CGPath] = [shackleFill, body]
    ctx.setStrokeColor(rgb(darkGreen)); ctx.setLineWidth(max(0.14 * k, 2)); ctx.setLineJoin(.round)
    for p in parts { ctx.addPath(p); ctx.strokePath() }
    ctx.setFillColor(rgb(white))
    for p in parts { ctx.addPath(p); ctx.fillPath() }
    // 锁孔
    let cy = bodyRect.midY + 0.06 * k, kr = max(0.10 * k, 1.2)
    ctx.setFillColor(rgb(darkGreen))
    ctx.fillEllipse(in: CGRect(x: -kr, y: cy - kr, width: 2 * kr, height: 2 * kr))
    let slot = CGMutablePath()
    slot.move(to: CGPoint(x: -kr * 0.45, y: cy))
    slot.addLine(to: CGPoint(x: kr * 0.45, y: cy))
    slot.addLine(to: CGPoint(x: kr * 0.75, y: cy - 0.24 * k))
    slot.addLine(to: CGPoint(x: -kr * 0.75, y: cy - 0.24 * k))
    slot.closeSubpath()
    ctx.addPath(slot); ctx.fillPath()
}

/// 眼睛（以 k 为尺寸单位，原点居中）：杏仁形白色眼白、深绿虹膜、白色高光
func drawEye(_ ctx: CGContext, k: CGFloat) {
    let w = 0.98 * k, h = 0.62 * k
    let eye = CGMutablePath()
    eye.move(to: CGPoint(x: -w / 2, y: 0))
    eye.addQuadCurve(to: CGPoint(x: w / 2, y: 0), control: CGPoint(x: 0, y: h))
    eye.addQuadCurve(to: CGPoint(x: -w / 2, y: 0), control: CGPoint(x: 0, y: -h))
    eye.closeSubpath()
    ctx.setStrokeColor(rgb(darkGreen)); ctx.setLineWidth(max(0.14 * k, 2)); ctx.setLineJoin(.round)
    ctx.addPath(eye); ctx.strokePath()
    ctx.setFillColor(rgb(white)); ctx.addPath(eye); ctx.fillPath()
    let ir = 0.21 * k
    ctx.setFillColor(rgb(darkGreen))
    ctx.fillEllipse(in: CGRect(x: -ir, y: -ir, width: 2 * ir, height: 2 * ir))
    let hr = 0.065 * k
    ctx.setFillColor(rgb(white))
    ctx.fillEllipse(in: CGRect(x: 0.06 * k - hr, y: 0.07 * k - hr, width: 2 * hr, height: 2 * hr))
}

func drawIcon(_ ctx: CGContext, glyph: Glyph, size: CGFloat) {
    ctx.setFillColor(rgb(green)); ctx.fill(CGRect(x: 0, y: 0, width: size, height: size))
    let t = thickness(size)
    ctx.saveGState()
    ctx.translateBy(x: size / 2, y: size / 2)
    drawCapsule(ctx, t: t)
    switch glyph {
    case .padlock: drawPadlock(ctx, k: glyphFill * t)
    case .eye: drawEye(ctx, k: glyphFill * t * 1.05)
    }
    ctx.restoreGState()
}

func render(_ glyph: Glyph, _ px: Int) -> CGImage {
    guard let cs = CGColorSpace(name: CGColorSpace.sRGB),
          let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                              bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else {
        fatalError("无法创建 \(px)×\(px) 位图")
    }
    ctx.setShouldAntialias(true)
    ctx.interpolationQuality = .high
    drawIcon(ctx, glyph: glyph, size: CGFloat(px))
    guard let img = ctx.makeImage() else { fatalError("makeImage 失败") }
    return img
}

func writePNG(_ image: CGImage, _ path: String) {
    let url = URL(fileURLWithPath: path)
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    guard let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else {
        fatalError("无法写 \(path)")
    }
    CGImageDestinationAddImage(dest, image, nil)
    guard CGImageDestinationFinalize(dest) else { fatalError("无法写 \(path)") }
}

let args = CommandLine.arguments
if args.count == 3, args[1] == "--preview" {
    // 并排预览：两个 1024 缩到 400，下方各一行 120 / 60 px 小尺寸
    let w = 900, h = 640
    guard let cs = CGColorSpace(name: CGColorSpace.sRGB),
          let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                              bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { fatalError() }
    ctx.setFillColor(rgb(0xF2F2F7)); ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
    for (i, g) in [Glyph.padlock, .eye].enumerated() {
        let x0 = CGFloat(30 + i * 450)
        ctx.draw(render(g, 1024), in: CGRect(x: x0, y: 210, width: 400, height: 400))
        ctx.draw(render(g, 120), in: CGRect(x: x0 + 60, y: 40, width: 120, height: 120))
        ctx.draw(render(g, 60), in: CGRect(x: x0 + 240, y: 70, width: 60, height: 60))
    }
    guard let img = ctx.makeImage() else { fatalError() }
    writePNG(img, args[2])
} else {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().path
    writePNG(render(.padlock, 1024), root + "/ios/Signer/Signer/Assets.xcassets/AppIcon.appiconset/app-icon-1024.png")
    writePNG(render(.eye, 1024), root + "/ios/Watcher/Watcher/Assets.xcassets/AppIcon.appiconset/app-icon-1024.png")
    print("写好了两个 1024×1024 图标")
}
