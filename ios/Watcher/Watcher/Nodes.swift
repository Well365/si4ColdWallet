import Foundation

/// 一个节点（内置或用户添加）。观察机不信任节点：余额、nonce、手续费只用来构造交易，
/// 交易内容由签名机独立审查；节点说谎最多导致交易失败或多付手续费（签名机对异常手续费有告警）。
struct Node: Codable, Hashable, Identifiable {
    let name: String
    let url: String
    var builtin = false
    /// 只建议用来广播（例如 Flashbots Protect：交易不进公开内存池，防夹子）
    var broadcastOnly = false
    var id: String { url }
}

/// 一个网络的节点集合：EVM 链按链 ID，比特币按主网 / 测试网（决策 D35）
struct NodeNetwork: Hashable {
    enum Kind: Hashable {
        case evm(chainId: UInt64)
        case esplora(testnet: Bool)
        /// Solana：按创世区块哈希区分主网 / devnet
        case solana(genesis: String)
    }

    let key: String
    let title: String
    let kind: Kind
    let builtins: [Node]

    static func evm(_ n: EvmNetwork) -> NodeNetwork {
        NodeNetwork(key: "evm-\(n.chainId)", title: n.name, kind: .evm(chainId: n.chainId), builtins: n.nodes)
    }

    static func solana(_ n: SolNetwork) -> NodeNetwork {
        NodeNetwork(key: "sol-\(n.genesis.prefix(8))", title: n.name, kind: .solana(genesis: n.genesis), builtins: n.nodes)
    }

    static func bitcoin(testnet: Bool) -> NodeNetwork {
        NodeNetwork(key: testnet ? "btc-testnet4" : "btc-main",
                    title: testnet ? "Bitcoin testnet4" : "Bitcoin 主网",
                    kind: .esplora(testnet: testnet),
                    builtins: testnet ? Esplora.testnetNodes : Esplora.mainnetNodes)
    }
}

/// 节点登记簿：内置公共节点 + 用户添加的节点；每个网络选中哪一个。全部存在本机（只是网址，不是秘密）。
@MainActor
final class NodeBook: ObservableObject {
    static let shared = NodeBook()

    private struct Stored: Codable {
        var custom: [String: [Node]] = [:]
        var selected: [String: String] = [:]
    }

    private static let storageKey = "node-book-v1"
    @Published private var stored: Stored

    private init() {
        if let data = UserDefaults.standard.data(forKey: Self.storageKey),
           let s = try? JSONDecoder().decode(Stored.self, from: data) {
            stored = s
        } else {
            stored = Self.migrated()
        }
    }

    /// 旧版设置（"链ID=URL" 文本框、Esplora 地址文本框）迁入登记簿，只做一次
    private static func migrated() -> Stored {
        var s = Stored()
        let d = UserDefaults.standard
        for line in (d.string(forKey: "evm-rpc-overrides") ?? "").split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2, let id = UInt64(parts[0].trimmingCharacters(in: .whitespaces)) else { continue }
            let url = parts[1].trimmingCharacters(in: .whitespaces)
            guard Self.validURL(url) != nil else { continue }
            let key = "evm-\(id)"
            s.custom[key, default: []].append(Node(name: "自定义", url: url))
            s.selected[key] = url
        }
        if let base = d.string(forKey: "esplora-base"), Self.validURL(base) != nil,
           base != Esplora.testnetNodes.first?.url {
            let key = base.contains("testnet") ? "btc-testnet4" : "btc-main"
            s.custom[key, default: []].append(Node(name: "自定义", url: base))
            s.selected[key] = base
        }
        d.removeObject(forKey: "evm-rpc-overrides")
        d.removeObject(forKey: "esplora-base")
        if let data = try? JSONEncoder().encode(s) { d.set(data, forKey: storageKey) }
        return s
    }

    private func save() {
        if let data = try? JSONEncoder().encode(stored) { UserDefaults.standard.set(data, forKey: Self.storageKey) }
    }

    /// 只接受 https，且不能带用户名密码
    nonisolated static func validURL(_ text: String) -> URL? {
        guard let u = URL(string: text.trimmingCharacters(in: .whitespaces)), u.scheme == "https",
              let host = u.host, !host.isEmpty, u.user == nil, u.password == nil
        else { return nil }
        return u
    }

    func nodes(_ net: NodeNetwork) -> [Node] {
        net.builtins + (stored.custom[net.key] ?? [])
    }

    /// 选中的节点；没选过或已删除时用第一个内置节点
    func current(_ net: NodeNetwork) -> Node {
        let all = nodes(net)
        return all.first { $0.url == stored.selected[net.key] } ?? all.first { !$0.broadcastOnly } ?? all[0]
    }

    func select(_ node: Node, in net: NodeNetwork) {
        stored.selected[net.key] = node.url
        save()
    }

    func add(_ node: Node, to net: NodeNetwork) {
        guard !nodes(net).contains(where: { $0.url == node.url }) else { return }
        stored.custom[net.key, default: []].append(node)
        save()
    }

    func remove(_ node: Node, from net: NodeNetwork) {
        stored.custom[net.key]?.removeAll { $0.url == node.url }
        if stored.selected[net.key] == node.url { stored.selected[net.key] = nil }
        save()
    }
}

/// 节点体检结果
struct NodeHealth {
    var height: UInt64?
    var latencyMs: Int?
    var problem: String?

    func summary(best: UInt64?) -> String {
        if let problem { return problem }
        var parts: [String] = []
        if let height { parts.append("区块 #\(height)") }
        if let latencyMs { parts.append("\(latencyMs) ms") }
        if let height, let best, best > height + 5 { parts.append("落后 \(best - height) 个区块") }
        return parts.joined(separator: " · ")
    }

    func isBehind(best: UInt64?) -> Bool {
        guard let height, let best else { return false }
        return best > height + 5
    }
}

/// 节点体检：EVM 节点核对链 ID 并取区块高度；Esplora 节点核对创世区块（主网 / testnet4）并取区块高度
enum NodeProbe {
    static func check(_ node: Node, on kind: NodeNetwork.Kind) async -> NodeHealth {
        guard let url = NodeBook.validURL(node.url) else { return NodeHealth(problem: "网址无效（必须是 https）") }
        let start = Date()
        let elapsed = { Int(Date().timeIntervalSince(start) * 1000) }
        do {
            switch kind {
            case .evm(let chainId):
                let rpc = EvmRPC(url: url, timeout: 8)
                let id = try await rpc.chainId()
                guard id == chainId else { return NodeHealth(problem: "链 ID 不符（节点是 \(id)，需要 \(chainId)）") }
                let h = try await rpc.blockNumber()
                return NodeHealth(height: h, latencyMs: elapsed())
            case .solana(let genesis):
                let rpc = SolRPC(url: url, timeout: 8)
                guard try await rpc.genesisHash() == genesis else { return NodeHealth(problem: "网络不符（创世区块哈希不对）") }
                let h = try await rpc.slot()
                return NodeHealth(height: h, latencyMs: elapsed())
            case .esplora(let testnet):
                let e = Esplora(base: url, timeout: 8)
                let genesis = try await e.genesisHash()
                guard genesis == (testnet ? Esplora.testnet4Genesis : Esplora.mainnetGenesis) else {
                    return NodeHealth(problem: "网络不符（创世区块不是\(testnet ? " testnet4" : "主网")）")
                }
                let h = try await e.tipHeight()
                return NodeHealth(height: h, latencyMs: elapsed())
            }
        } catch let e as EvmRPC.RPCError {
            return NodeHealth(problem: "失败：\(e.message)")
        } catch let e as SolRPC.RPCError {
            return NodeHealth(problem: "失败：\(e.message)")
        } catch {
            return NodeHealth(problem: "连接失败：\(error.localizedDescription)")
        }
    }
}
