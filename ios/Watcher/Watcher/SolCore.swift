import AWWatchC
import Foundation

/// Solana 网络（P2c）：按创世区块哈希区分；内置节点 2026-10-11 实测可用
struct SolNetwork: Hashable, Identifiable {
    let name: String
    let genesis: String
    let nodes: [Node]
    /// 区块浏览器的 cluster 参数（主网为空）
    let cluster: String
    let tokens: [SolToken]
    var id: String { genesis }

    static let all: [SolNetwork] = [
        SolNetwork(name: "Solana devnet", genesis: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
                   nodes: [Node(name: "Solana 官方", url: "https://api.devnet.solana.com", builtin: true)],
                   cluster: "devnet", tokens: []),
        SolNetwork(name: "Solana 主网", genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
                   nodes: [Node(name: "Solana 官方", url: "https://api.mainnet-beta.solana.com", builtin: true),
                           Node(name: "PublicNode", url: "https://solana-rpc.publicnode.com", builtin: true)],
                   cluster: "",
                   tokens: [SolToken(symbol: "USDC", mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", decimals: 6),
                            SolToken(symbol: "USDT", mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYb", decimals: 6)]),
    ]

    func txURL(_ sig: String) -> URL? {
        guard let u = Explorer.url("https://explorer.solana.com/tx/", sig) else { return nil }
        return cluster.isEmpty ? u : URL(string: u.absoluteString + "?cluster=" + cluster)
    }

    func addressURL(_ addr: String) -> URL? {
        guard let u = Explorer.url("https://explorer.solana.com/address/", addr) else { return nil }
        return cluster.isEmpty ? u : URL(string: u.absoluteString + "?cluster=" + cluster)
    }
}

struct SolToken: Hashable, Identifiable {
    let symbol: String
    let mint: String
    let decimals: UInt8
    var id: String { mint }
}

/// 账户类型（与签名机的 SolScheme、Rust 的 Scheme::ALL 顺序一致，决策 D34）
enum SolScheme: UInt32, CaseIterable, Identifiable, Codable {
    case phantom = 0, ledgerLive = 1, ledgerMain = 2
    var id: UInt32 { rawValue }

    var title: String {
        switch self {
        case .phantom: return "Phantom / Trezor"
        case .ledgerLive: return "Ledger Live"
        case .ledgerMain: return "Ledger 主账户"
        }
    }

    var maxIndex: UInt32 { self == .ledgerMain ? 0 : 19 }
}

/// 观察的 Solana 账户：地址 + 账户类型 + 序号（只是公开信息）。签名机会核对这三者是否一致
struct SolAccount: Codable, Equatable {
    let address: String
    let scheme: SolScheme
    let index: UInt32

    var key: [UInt8]? { SolCore.parseAddress(address) }
}

/// 一档优先费（与 Rust aw_sol_priority_tiers 的输出一一对应）
struct SolFeeTier: Decodable, Identifiable, Hashable {
    let speed: String
    let label: String
    /// 微 lamports / 计算单元
    let price: UInt64
    /// 最高手续费（lamports）
    let maxFee: UInt64
    let maxFeeText: String
    var id: String { speed }
}

/// 签名回来后的结果
struct SolFinalized: Decodable {
    let txHex: String
    let txid: String
}

enum SolCore {
    static func parseAddress(_ text: String) -> [UInt8]? {
        let b = Array(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        var out = [UInt8](repeating: 0, count: 32)
        let rc = b.withUnsafeBufferPointer { s in out.withUnsafeMutableBufferPointer { aw_sol_parse_address(s.baseAddress, s.count, $0.baseAddress) } }
        return rc == AW_OK ? out : nil
    }

    static func ata(owner: [UInt8], mint: [UInt8]) -> String? {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        let rc = owner.withUnsafeBufferPointer { o in mint.withUnsafeBufferPointer { aw_sol_ata(o.baseAddress, $0.baseAddress, 0, &p, &l) } }
        return rc == AW_OK ? WatchCore.takeString(p, l) : nil
    }

    static func tiers(samples: [UInt64], unitLimit: UInt32) throws -> [SolFeeTier] {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        let rc = samples.withUnsafeBufferPointer { aw_sol_priority_tiers($0.baseAddress, $0.count, unitLimit, &p, &l) }
        try WatchCore.check(rc)
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return try d.decode([SolFeeTier].self, from: Data(WatchCore.takeBuffer(p, l)))
    }

    /// 金额文本 → 最小单位（由 Rust 解析，不用浮点；必须放得进 u64）
    static func parseAmount(_ text: String, decimals: UInt8) throws -> UInt64 {
        let b = try EvmAmount.parse(text, decimals: UInt32(decimals))
        guard b.count == 32, b.prefix(24).allSatisfy({ $0 == 0 }) else { throw WatchCore.Failure(code: AW_ERR_BAD_ARGUMENT) }
        return b.suffix(8).reduce(0) { $0 << 8 | UInt64($1) }
    }

    static func format(_ v: UInt64, decimals: UInt8) -> String {
        EvmAmount.format(v, decimals: UInt32(decimals))
    }
}

@MainActor
final class SolPending {
    private nonisolated(unsafe) let raw: OpaquePointer
    let display: DisplayModel

    init(raw: OpaquePointer, display: DisplayModel) {
        self.raw = raw
        self.display = display
    }

    deinit {
        aw_sol_pending_free(raw)
    }

    /// 构造转账：`token` 为 nil 时转 SOL（amount 为 lamports），否则为代币最小单位
    static func build(account: SolAccount, to: String, amount: UInt64, token: SolToken?, blockhash: String,
                      unitLimit: UInt32, unitPrice: UInt64) throws -> SolPending {
        guard let from = account.key, let bh = SolCore.parseAddress(blockhash) else {
            throw WatchCore.Failure(code: AW_ERR_BAD_ARGUMENT)
        }
        let mint = token.flatMap { SolCore.parseAddress($0.mint) }
        if token != nil && mint == nil { throw WatchCore.Failure(code: AW_ERR_BAD_ARGUMENT) }
        let toBytes = Array(to.trimmingCharacters(in: .whitespaces).utf8)
        let rid = withUnsafeBytes(of: UUID().uuid) { Array($0) }
        var pending: OpaquePointer?
        var jp: UnsafeMutablePointer<UInt8>?
        var jl = 0
        let rc = from.withUnsafeBufferPointer { f in
            toBytes.withUnsafeBufferPointer { t in
                bh.withUnsafeBufferPointer { b in
                    rid.withUnsafeBufferPointer { r in
                        if let mint {
                            return mint.withUnsafeBufferPointer { m in
                                aw_sol_build_transfer(f.baseAddress, account.scheme.rawValue, account.index, t.baseAddress, t.count,
                                                      amount, m.baseAddress, token?.decimals ?? 0, 0, b.baseAddress,
                                                      unitLimit, unitPrice, r.baseAddress, &pending, &jp, &jl)
                            }
                        }
                        return aw_sol_build_transfer(f.baseAddress, account.scheme.rawValue, account.index, t.baseAddress, t.count,
                                                     amount, nil, 0, 0, b.baseAddress,
                                                     unitLimit, unitPrice, r.baseAddress, &pending, &jp, &jl)
                    }
                }
            }
        }
        try WatchCore.check(rc)
        guard let pending else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        let display = try JSONDecoder().decode(DisplayModel.self, from: Data(WatchCore.takeBuffer(jp, jl)))
        return SolPending(raw: pending, display: display)
    }

    func frames() throws -> URFrames {
        var enc: OpaquePointer?
        try WatchCore.check(aw_sol_pending_encoder(raw, &enc))
        guard let enc else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        return URFrames(raw: enc)
    }

    func finalize(scan: URScan) throws -> SolFinalized {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        try WatchCore.check(aw_sol_pending_finalize(raw, scan.raw, &p, &l))
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return try d.decode(SolFinalized.self, from: Data(WatchCore.takeBuffer(p, l)))
    }
}
