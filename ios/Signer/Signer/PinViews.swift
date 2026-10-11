import SwiftUI

/// 6 位 PIN 的数字键盘（自带，不经过系统键盘：威胁 T10）
struct PinPad: View {
    @Binding var pin: String
    let onComplete: (String) -> Void

    private let rows = [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["", "0", "⌫"]]

    var body: some View {
        VStack(spacing: 24) {
            HStack(spacing: 16) {
                ForEach(0..<6, id: \.self) { i in
                    Circle()
                        .strokeBorder(Color.primary, lineWidth: 1.5)
                        .background(Circle().fill(i < pin.count ? Color.primary : Color.clear))
                        .frame(width: 16, height: 16)
                }
            }
            .accessibilityElement()
            .accessibilityLabel("已输入 \(pin.count) 位，共 6 位")
            VStack(spacing: 14) {
                ForEach(rows, id: \.self) { row in
                    HStack(spacing: 22) {
                        ForEach(row, id: \.self) { key in keyButton(key) }
                    }
                }
            }
        }
    }

    @ViewBuilder private func keyButton(_ key: String) -> some View {
        if key.isEmpty {
            Color.clear.frame(width: 76, height: 76)
        } else {
            Button {
                tap(key)
            } label: {
                Text(key == "⌫" ? "" : key)
                    .font(.system(size: 30, weight: .medium, design: .rounded))
                    .frame(width: 76, height: 76)
                    .background(key == "⌫" ? Color.clear : Color.gray.opacity(0.18), in: Circle())
                    .overlay {
                        if key == "⌫" { Image(systemName: "delete.left").font(.title2) }
                    }
            }
            .buttonStyle(.plain)
            .accessibilityLabel(key == "⌫" ? "删除" : key)
        }
    }

    private func tap(_ key: String) {
        if key == "⌫" {
            _ = pin.popLast()
            return
        }
        guard pin.count < 6 else { return }
        pin.append(key)
        if pin.count == 6 {
            let done = pin
            onComplete(done)
        }
    }
}

/// 设置 PIN：输两次一致才保存；说明"解锁时输错一次就清除"
struct SetPinView: View {
    let hasPassphrase: Bool
    /// 保存失败时的说明（例如没有设置锁屏密码）
    let error: String?
    /// (PIN, 是否同时保存 passphrase)
    let onSet: (String, Bool) -> Void
    let onSkip: () -> Void
    @State private var first: String?
    @State private var pin = ""
    @State private var storePassphrase = false
    @State private var mismatch = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Text(first == nil ? "设置 6 位解锁密码" : "再输入一次")
                    .font(.title2.bold())
                Text("以后打开签名机、或从后台回来时都要输入。**输错一次，钱包就会从本机清除**，只能再用助记词恢复，请确认助记词已经抄好。")
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.orange)
                if hasPassphrase && first == nil {
                    Toggle("同时保存 passphrase（解锁后直接可用；不保存则每次解锁后再输入）", isOn: $storePassphrase)
                        .font(.footnote)
                }
                if let error {
                    Text(error).font(.footnote).foregroundStyle(.red)
                }
                if mismatch {
                    Text("两次输入不一致，请重新设置").font(.footnote).foregroundStyle(.red)
                }
                PinPad(pin: $pin) { entered in
                    if let f = first {
                        first = nil
                        if f == entered {
                            onSet(entered, storePassphrase)
                        } else {
                            mismatch = true
                        }
                    } else {
                        first = entered
                        mismatch = false
                    }
                    pin = ""
                }
                Button("不保存，下次重新输入助记词") { onSkip() }
                    .font(.footnote)
            }
            .padding()
        }
        .navigationTitle("解锁密码")
        .navigationBarTitleDisplayMode(.inline)
        // 钱包此时已解锁：不允许返回上一页（只能保存或选择不保存）
        .navigationBarBackButtonHidden()
    }
}

/// 开机 / 从后台回来：输入 PIN 解锁本机保存的钱包
struct UnlockPinView: View {
    let onPin: (String) -> Void
    let onForget: () -> Void
    @State private var pin = ""
    @State private var confirmForget = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "lock.fill").font(.largeTitle)
            Text("输入解锁密码").font(.title2.bold())
            Text("输错一次，本机保存的钱包就会被清除。")
                .font(.footnote).foregroundStyle(.orange)
            PinPad(pin: $pin) { entered in
                pin = ""
                onPin(entered)
            }
            Spacer()
            Button("忘记密码：清除本机钱包，用助记词恢复", role: .destructive) { confirmForget = true }
                .font(.footnote)
        }
        .padding()
        .confirmationDialog("清除本机保存的钱包？", isPresented: $confirmForget, titleVisibility: .visible) {
            Button("清除", role: .destructive) { onForget() }
        } message: {
            Text("清除后只能用助记词重新恢复。")
        }
    }
}
