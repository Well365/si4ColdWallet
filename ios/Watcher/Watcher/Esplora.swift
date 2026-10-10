import Foundation

/// Esplora 兼容接口（mempool.space / blockstream.info / 自建 electrs）。
/// 观察机不信任它返回的数据：每笔 UTXO 都附带完整前序交易，由 Rust 核心核对脚本属于本账户，
/// 签名机还会再次核对前序交易哈希与金额（威胁 T5）。
struct Esplora {
    let base: URL

    static let defaultTestnet = URL(string: "https://mempool.space/testnet4/api")!

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

    struct Fees: Decodable {
        let fastestFee: UInt64
        let halfHourFee: UInt64
        let hourFee: UInt64
    }

    private func get(_ path: String) async throws -> Data {
        var req = URLRequest(url: base.appending(path: path))
        req.timeoutInterval = 20
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

    func recommendedFees() async throws -> Fees {
        try decoder.decode(Fees.self, from: try await get("v1/fees/recommended"))
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
