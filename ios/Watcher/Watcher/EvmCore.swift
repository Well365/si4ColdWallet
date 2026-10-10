import AWWatchC
import Foundation

/// EVM 账户（m/44'/60'/0'）的 Swift 封装。地址派生、金额解析、交易构造与签名核对全部在 Rust 中。
@MainActor
final class EvmAccount {
    nonisolated(unsafe) let raw: OpaquePointer

    private init(raw: OpaquePointer) {
        self.raw = raw
    }

    deinit {
        aw_evm_free(raw)
    }

    static func from(scan: URScan) throws -> EvmAccount {
        var out: OpaquePointer?
        try WatchCore.check(aw_evm_from_decoder(scan.raw, &out))
        guard let out else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        return EvmAccount(raw: out)
    }

    static func from(ur: String) throws -> EvmAccount {
        let bytes = Array(ur.utf8)
        var out: OpaquePointer?
        let rc = bytes.withUnsafeBufferPointer { aw_evm_from_ur($0.baseAddress, $0.count, &out) }
        try WatchCore.check(rc)
        guard let out else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        return EvmAccount(raw: out)
    }

    var urString: String {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        guard aw_evm_to_ur(raw, &p, &l) == AW_OK else { return "" }
        return WatchCore.takeString(p, l)
    }

    var fingerprint: String { String(format: "%08x", aw_evm_fingerprint(raw)) }

    func address(index: UInt32) -> String {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        guard aw_evm_address(raw, index, &p, &l) == AW_OK else { return "" }
        return WatchCore.takeString(p, l)
    }

    /// 构造转账并生成签名请求。`token` 为 nil 时转原生币。
    func buildTransfer(network: EvmNetwork, nonce: UInt64, fees: EvmFees, gasLimit: UInt64,
                       to: String, amount: String, token: EvmToken?) throws -> EvmPending {
        let value = try EvmAmount.parse(amount, decimals: token?.decimals ?? 18)
        let prio = EvmAmount.bytes(fees.maxPriorityFee)
        let maxFee = EvmAmount.bytes(fees.maxFee)
        let toBytes = Array(to.utf8)
        let tokenBytes = Array((token?.contract ?? "").utf8)
        let uuid = UUID().uuid
        let rid = withUnsafeBytes(of: uuid) { Array($0) }
        var pending: OpaquePointer?
        var jp: UnsafeMutablePointer<UInt8>?
        var jl = 0
        let rc = toBytes.withUnsafeBufferPointer { t in
            tokenBytes.withUnsafeBufferPointer { k in
                aw_evm_build_transfer(raw, 0, network.chainId, nonce, prio, maxFee, gasLimit,
                                      t.baseAddress, t.count, value, k.baseAddress, k.count, rid,
                                      &pending, &jp, &jl)
            }
        }
        try WatchCore.check(rc)
        guard let pending else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        let display = try JSONDecoder().decode(DisplayModel.self, from: Data(WatchCore.takeBuffer(jp, jl)))
        return EvmPending(raw: pending, account: self, display: display)
    }
}

@MainActor
final class EvmPending {
    private nonisolated(unsafe) let raw: OpaquePointer
    private let account: EvmAccount
    /// 与签名机将显示的内容相同（同一份 Rust 审查代码生成），便于两台设备逐行对照
    let display: DisplayModel

    init(raw: OpaquePointer, account: EvmAccount, display: DisplayModel) {
        self.raw = raw
        self.account = account
        self.display = display
    }

    deinit {
        aw_evm_pending_free(raw)
    }

    func frames() throws -> URFrames {
        var enc: OpaquePointer?
        try WatchCore.check(aw_evm_pending_encoder(raw, &enc))
        guard let enc else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        return URFrames(raw: enc)
    }

    /// 核对签名机返回的签名，返回可广播的 "0x…" 原始交易
    func finalize(scan: URScan) throws -> String {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        try WatchCore.check(aw_evm_pending_finalize(account.raw, raw, scan.raw, &p, &l))
        return WatchCore.takeString(p, l)
    }
}

/// 金额：解析与格式化都交给 Rust（不用浮点）
enum EvmAmount {
    static func parse(_ text: String, decimals: UInt32) throws -> [UInt8] {
        // 中文输入法常把小数点打成全角"。"或"．"：只做这一种替换，其余字符仍由 Rust 严格校验
        let normalized = text.trimmingCharacters(in: .whitespaces)
            .replacingOccurrences(of: "。", with: ".")
            .replacingOccurrences(of: "．", with: ".")
        let bytes = Array(normalized.utf8)
        var out = [UInt8](repeating: 0, count: 32)
        let rc = bytes.withUnsafeBufferPointer { b in
            out.withUnsafeMutableBufferPointer { aw_evm_parse_amount(b.baseAddress, b.count, decimals, $0.baseAddress) }
        }
        try WatchCore.check(rc)
        return out
    }

    /// 原始交易的哈希（由 Rust 计算，用来核对节点返回的哈希）
    static func txHash(rawHex: String) -> String? {
        let bytes = Array(rawHex.utf8)
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        let rc = bytes.withUnsafeBufferPointer { aw_evm_tx_hash($0.baseAddress, $0.count, &p, &l) }
        return rc == AW_OK ? WatchCore.takeString(p, l) : nil
    }

    /// JSON-RPC 十六进制数量 → 十进制文本
    static func format(hexQuantity: String, decimals: UInt32) -> String? {
        let bytes = Array(hexQuantity.utf8)
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        let rc = bytes.withUnsafeBufferPointer { aw_evm_format_quantity($0.baseAddress, $0.count, decimals, &p, &l) }
        return rc == AW_OK ? WatchCore.takeString(p, l) : nil
    }

    static func bytes(_ v: UInt64) -> [UInt8] {
        [UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: v.bigEndian) { Array($0) }
    }
}

struct EvmFees {
    let maxPriorityFee: UInt64
    let maxFee: UInt64
}

struct EvmToken: Hashable, Identifiable {
    let symbol: String
    let contract: String
    let decimals: UInt32
    var id: String { contract }
}

struct EvmNetwork: Hashable, Identifiable {
    let name: String
    let chainId: UInt64
    let symbol: String
    let defaultRPC: String
    /// 区块浏览器根地址（以 / 结尾）
    let explorer: String
    let tokens: [EvmToken]
    var id: UInt64 { chainId }

    func txURL(_ hash: String) -> URL? { Explorer.url(explorer + "tx/", hash) }
    func addressURL(_ address: String) -> URL? { Explorer.url(explorer + "address/", address) }

    static let all: [EvmNetwork] = [
        EvmNetwork(name: "Sepolia 测试网", chainId: 11_155_111, symbol: "SepoliaETH",
                   defaultRPC: "https://ethereum-sepolia-rpc.publicnode.com", explorer: "https://sepolia.etherscan.io/", tokens: []),
        EvmNetwork(name: "BNB Smart Chain 测试网", chainId: 97, symbol: "tBNB",
                   defaultRPC: "https://bsc-testnet-rpc.publicnode.com", explorer: "https://testnet.bscscan.com/", tokens: []),
        EvmNetwork(name: "Ethereum 主网", chainId: 1, symbol: "ETH",
                   defaultRPC: "https://ethereum-rpc.publicnode.com", explorer: "https://etherscan.io/",
                   tokens: [EvmToken(symbol: "USDT", contract: "0xdAC17F958D2ee523a2206206994597C13D831ec7", decimals: 6),
                            EvmToken(symbol: "USDC", contract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals: 6)]),
        EvmNetwork(name: "BNB Smart Chain 主网", chainId: 56, symbol: "BNB",
                   defaultRPC: "https://bsc-rpc.publicnode.com", explorer: "https://bscscan.com/",
                   tokens: [EvmToken(symbol: "USDT", contract: "0x55d398326f99059fF775485246999027B3197955", decimals: 18),
                            EvmToken(symbol: "USDC", contract: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", decimals: 18)]),
    ]
}

/// 通用显示模型（与 Rust aw-common::display 一一对应）
struct DisplayModel: Decodable {
    struct Row: Decodable, Identifiable {
        let label: String
        let value: String
        let style: String
        var id: String { label + value }
    }

    struct Warning: Decodable, Identifiable {
        let level: String
        let text: String
        var id: String { level + text }
    }

    let chain: String
    let network: String
    let title: String
    let rows: [Row]
    let warnings: [Warning]
}

/// 区块浏览器网址：只拼接固定前缀与全字母数字的地址或哈希，避免被构造的值改成别的站点
enum Explorer {
    static func url(_ prefix: String, _ item: String) -> URL? {
        guard !item.isEmpty, item.unicodeScalars.allSatisfy({ $0.isASCII && CharacterSet.alphanumerics.contains($0) }) else {
            return nil
        }
        return URL(string: prefix + item)
    }

    static func bitcoinAddress(_ address: String, testnet: Bool) -> URL? {
        url(testnet ? "https://mempool.space/testnet4/address/" : "https://mempool.space/address/", address)
    }
}
