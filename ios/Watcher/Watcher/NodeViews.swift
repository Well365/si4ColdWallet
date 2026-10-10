import SwiftUI

/// 节点列表（决策 D35）：选中、逐个体检（区块高度 / 延迟 / 链是否正确）、添加与删除自定义节点
struct NodeListView: View {
    let net: NodeNetwork
    @ObservedObject private var book = NodeBook.shared
    @State private var health: [String: NodeHealth] = [:]
    @State private var testing = false
    @State private var newName = ""
    @State private var newURL = ""
    @State private var addError: String?
    @State private var adding = false

    private var best: UInt64? { health.values.compactMap(\.height).max() }

    var body: some View {
        List {
            Section {
                ForEach(book.nodes(net)) { node in
                    Button { book.select(node, in: net) } label: { row(node) }
                        .swipeActions {
                            if !node.builtin {
                                Button("删除", role: .destructive) { book.remove(node, from: net) }
                            }
                        }
                }
            } header: {
                Text("选中的节点用于查询余额、获取手续费、构造与广播")
            } footer: {
                Text("公共节点能看到你查询的地址；要隐私就添加自己的节点。节点不可信：交易内容由签名机独立审查，节点说谎最多导致交易失败或多付手续费。自定义节点左滑可删除。")
            }
            Section {
                Button(testing ? "正在逐个测试…" : "测试全部节点") { Task { await testAll() } }.disabled(testing)
            }
            Section("添加节点（必须是 https）") {
                TextField("名称（可选）", text: $newName)
                TextField("https://…", text: $newURL)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
                Button(adding ? "正在测试…" : "测试并添加") { Task { await add() } }.disabled(adding || newURL.isEmpty)
                if let addError { Text(addError).foregroundStyle(.red).font(.footnote) }
            }
        }
        .navigationTitle("节点（\(net.title)）")
        .task { await testAll() }
    }

    @ViewBuilder private func row(_ node: Node) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(node.name).foregroundStyle(.primary)
                    if node.builtin { Text("内置").font(.caption2).foregroundStyle(.secondary) }
                    if node.broadcastOnly { Text("建议只用于广播").font(.caption2).foregroundStyle(.orange) }
                }
                Text(verbatim: node.url).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                if let h = health[node.url] {
                    Text(h.summary(best: best)).font(.caption)
                        .foregroundStyle(h.problem != nil ? Color.red : h.isBehind(best: best) ? Color.orange : Color.green)
                }
            }
            Spacer()
            if book.current(net).url == node.url {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint)
            }
        }
    }

    private func testAll() async {
        testing = true
        defer { testing = false }
        for node in book.nodes(net) {
            health[node.url] = await NodeProbe.check(node, on: net.kind)
        }
    }

    private func add() async {
        guard let url = NodeBook.validURL(newURL) else {
            addError = "网址无效：必须以 https:// 开头，且不能带用户名密码"
            return
        }
        adding = true
        defer { adding = false }
        let name = newName.trimmingCharacters(in: .whitespaces)
        let node = Node(name: name.isEmpty ? (url.host ?? "自定义") : name, url: url.absoluteString)
        let h = await NodeProbe.check(node, on: net.kind)
        if let problem = h.problem {
            addError = "没有添加：\(problem)"
            return
        }
        book.add(node, to: net)
        book.select(node, in: net)
        health[node.url] = h
        newName = ""
        newURL = ""
        addError = nil
    }
}

/// 账户页上的一行：当前节点 + 进入节点列表
struct NodeSummaryRow: View {
    let net: NodeNetwork
    @ObservedObject private var book = NodeBook.shared

    var body: some View {
        NavigationLink {
            NodeListView(net: net)
        } label: {
            LabeledContent("节点", value: book.current(net).name)
        }
    }
}

/// 广播用的节点选择（默认是当前节点；失败时可以换一个再试）
struct BroadcastNodePicker: View {
    let net: NodeNetwork
    @Binding var selection: String
    @ObservedObject private var book = NodeBook.shared

    var body: some View {
        Picker("广播节点", selection: $selection) {
            ForEach(book.nodes(net)) { n in Text(n.name).tag(n.url) }
        }
        .onAppear { if selection.isEmpty { selection = book.current(net).url } }
    }
}
