import Foundation

/// Esplora 兼容接口（mempool.space / blockstream.info / 自建 electrs）。
/// 观察机不信任它返回的数据：每笔 UTXO 都附带完整前序交易，由 Rust 核心核对脚本属于本账户，
/// 签名机还会再次核对前序交易哈希与金额（威胁 T5）。
struct Esplora {
    let base: URL
    var timeout: TimeInterval = 20

    /// 内置节点（决策 D35）；用户可在节点页添加自己的 electrs / mempool 实例
    static let mainnetNodes = [
        Node(name: "mempool.space", url: "https://mempool.space/api", builtin: true),
        Node(name: "Blockstream", url: "https://blockstream.info/api", builtin: true),
    ]
    static let testnetNodes = [
        Node(name: "mempool.space testnet4", url: "https://mempool.space/testnet4/api", builtin: true),
    ]
    static let mainnetGenesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    static let testnet4Genesis = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"

    private struct RawUTXO: Decodable {
        let txid: String
        let vout: UInt32
        let value: UInt64
    }

    private struct AddressInfo: Decodable {
        struct Stats: Decodable { let txCount: Int }
        let chainStats: Stats
        let mempoolStats: Stats
    }

    /// mempool.space 的推荐费率（sat/vB）
    struct Fees: Decodable {
        let fastestFee: UInt64
        let halfHourFee: UInt64
        let hourFee: UInt64
        let economyFee: UInt64?
        let minimumFee: UInt64?
    }

    /// 一档费率
    struct FeeTier: Identifiable, Hashable {
        let key: String
        let label: String
        let satPerVb: UInt64
        var id: String { key }
    }

    private func get(_ path: String) async throws -> Data {
        var req = URLRequest(url: base.appending(path: path))
        req.timeoutInterval = timeout
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        return data
    }

    private var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }

    func txCount(address: String) async throws -> Int {
        let info = try decoder.decode(AddressInfo.self, from: try await get("address/\(address)"))
        return info.chainStats.txCount + info.mempoolStats.txCount
    }

    func utxos(address: String, change: Bool, index: UInt32) async throws -> [UTXO] {
        let list = try decoder.decode([RawUTXO].self, from: try await get("address/\(address)/utxo"))
        var out = [UTXO]()
        for u in list {
            guard u.txid.count == 64, u.txid.allSatisfy(\.isHexDigit) else { throw URLError(.cannotParseResponse) }
            let hex = String(decoding: try await get("tx/\(u.txid)/hex"), as: UTF8.self)
            out.append(UTXO(txid: u.txid, vout: u.vout, value: u.value, change: change, index: index, rawTx: try Self.bytes(hex)))
        }
        return out
    }

    func tipHeight() async throws -> UInt64 {
        let text = String(decoding: try await get("blocks/tip/height"), as: UTF8.self)
        guard let h = UInt64(text.trimmingCharacters(in: .whitespacesAndNewlines)) else { throw URLError(.cannotParseResponse) }
        return h
    }

    /// 创世区块哈希：用来确认节点确实是主网或 testnet4
    func genesisHash() async throws -> String {
        String(decoding: try await get("block-height/0"), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func recommendedFees() async throws -> Fees {
        try decoder.decode(Fees.self, from: try await get("v1/fees/recommended"))
    }

    /// 费率档位（决策 D35）：mempool.space 用推荐接口；其他 Esplora 用 fee-estimates（按确认区块数）。
    /// 一律向上取整到整数 sat/vB，至少 1
    func feeTiers() async throws -> [FeeTier] {
        if let f = try? await recommendedFees() {
            return [
                FeeTier(key: "fast", label: "快（约 10 分钟）", satPerVb: max(1, f.fastestFee)),
                FeeTier(key: "standard", label: "标准（约 30 分钟）", satPerVb: max(1, f.halfHourFee)),
                FeeTier(key: "slow", label: "慢（约 1 小时）", satPerVb: max(1, f.hourFee)),
                FeeTier(key: "economy", label: "经济（不赶时间）", satPerVb: max(1, f.economyFee ?? f.hourFee)),
            ]
        }
        let est = try JSONDecoder().decode([String: Double].self, from: try await get("fee-estimates"))
        func at(_ blocks: [Int]) -> UInt64 {
            let v = blocks.lazy.compactMap { est[String($0)] }.first ?? 1
            return max(1, UInt64(min(v.rounded(.up), 100_000)))
        }
        return [
            FeeTier(key: "fast", label: "快（约 1 个区块）", satPerVb: at([1, 2])),
            FeeTier(key: "standard", label: "标准（约 3 个区块）", satPerVb: at([3, 4])),
            FeeTier(key: "slow", label: "慢（约 6 个区块）", satPerVb: at([6, 7])),
            FeeTier(key: "economy", label: "经济（约 1 天）", satPerVb: at([144, 504])),
        ]
    }

    func broadcast(txHex: String) async throws -> String {
        var req = URLRequest(url: base.appending(path: "tx"))
        req.httpMethod = "POST"
        req.httpBody = Data(txHex.utf8)
        req.timeoutInterval = 30
        let (data, resp) = try await URLSession.shared.data(for: req)
        let body = String(decoding: data, as: UTF8.self)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw BroadcastError(message: body) }
        return body
    }

    struct BroadcastError: Error { let message: String }

    static func bytes(_ hex: String) throws -> [UInt8] {
        let t = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.count % 2 == 0 else { throw URLError(.cannotParseResponse) }
        var out = [UInt8]()
        out.reserveCapacity(t.count / 2)
        var i = t.startIndex
        while i < t.endIndex {
            let j = t.index(i, offsetBy: 2)
            guard let b = UInt8(t[i..<j], radix: 16) else { throw URLError(.cannotParseResponse) }
            out.append(b)
            i = j
        }
        return out
    }
}
