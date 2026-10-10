import SwiftUI

/// 自带的 BIP39 单词键盘（威胁 T10）：不使用系统键盘，避免键盘学习、联想与第三方键盘记录。
/// 输入字母前缀，从词表中选取单词；只把单词序号交给调用方。
struct WordKeyboard: View {
    let onWord: (UInt16) -> Void
    @State private var prefix = ""

    private static let rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"].map { Array($0).map(String.init) }

    private var matches: [(Int, String)] {
        guard !prefix.isEmpty else { return [] }
        return AWCore.words.enumerated().filter { $0.element.hasPrefix(prefix) }.prefix(8).map { ($0.offset, $0.element) }
    }

    var body: some View {
        VStack(spacing: 8) {
            Text(prefix.isEmpty ? "输入单词前几个字母" : prefix)
                .font(.system(.title3, design: .monospaced))
                .frame(maxWidth: .infinity, minHeight: 32)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(matches, id: \.0) { idx, word in
                        Button(word) {
                            onWord(UInt16(idx))
                            prefix = ""
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            }
            .frame(minHeight: 40)
            ForEach(Self.rows, id: \.self) { row in
                HStack(spacing: 4) {
                    ForEach(row, id: \.self) { letter in
                        Button(letter) { if prefix.count < 8 { prefix += letter } }
                            .frame(maxWidth: .infinity, minHeight: 40)
                            .background(Color(uiColor: .secondarySystemBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
            Button("退格") { _ = prefix.popLast() }.disabled(prefix.isEmpty)
        }
    }
}
