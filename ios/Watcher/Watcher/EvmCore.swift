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
        let prio = fees.maxPriorityFee
        let maxFee = fees.maxFee
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

    /// 消息签名请求：`typed` 为 true 时 `text` 是 EIP-712 JSON，否则是 personal_sign 文本。
    /// `chainId` 为 0 表示不核对链。观察机先用与签名机相同的规则检查。
    func buildMessage(typed: Bool, text: String, chainId: UInt64) throws -> EvmPending {
        let bytes = Array(text.utf8)
        let uuid = UUID().uuid
        let rid = withUnsafeBytes(of: uuid) { Array($0) }
        var pending: OpaquePointer?
        var jp: UnsafeMutablePointer<UInt8>?
        var jl = 0
        let rc = bytes.withUnsafeBufferPointer { b in
            aw_evm_build_message(raw, 0, typed ? 1 : 0, b.baseAddress, b.count, chainId, rid, &pending, &jp, &jl)
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

    /// 核对签名机返回的签名：交易返回可广播的 "0x…" 原始交易，消息返回 "0x…" 65 字节签名
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

    /// 32 字节大端整数 → JSON-RPC 十六进制数量（"0x0"、"0x1a…"）
    static func quantity(_ b: [UInt8]) -> String {
        let hex = b.map { String(format: "%02x", $0) }.joined().drop { $0 == "0" }
        return "0x" + (hex.isEmpty ? "0" : String(hex))
    }

    /// u64 wei → 按小数位格式化的文本（由 Rust 格式化，不用浮点）
    static func format(_ v: UInt64, decimals: UInt32) -> String {
        format(hexQuantity: "0x" + String(v, radix: 16), decimals: decimals) ?? "\(v)"
    }

    /// 手续费三档（决策 D35，由 Rust 用检查算术计算）：`history.nextBaseFee` 为 nil 时按旧式链处理
    static func feeTiers(history: EvmRPC.FeeHistory, suggested: UInt64, gasPrice: UInt64, gasLimit: UInt64) throws -> [EvmFeeTier] {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        let rc: Int32
        if let base = history.nextBaseFee {
            rc = history.rewards.withUnsafeBufferPointer {
                aw_evm_fee_tiers(1, base, $0.baseAddress, $0.count, suggested, gasLimit, &p, &l)
            }
        } else {
            rc = aw_evm_fee_tiers(0, 0, nil, 0, gasPrice, gasLimit, &p, &l)
        }
        try WatchCore.check(rc)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode([EvmFeeTier].self, from: Data(WatchCore.takeBuffer(p, l)))
    }

    /// 构造前核对余额（决策 D35）：原生币要够"金额 + gas 上限 × 最高单价"（代币转账只算手续费），代币要够数量。
    /// 不够时抛出 AW_ERR_EVM_NATIVE_SHORT / AW_ERR_EVM_TOKEN_SHORT
    static func checkFunds(native: String, token: String?, value: [UInt8], gasLimit: UInt64, maxFee: [UInt8]) throws {
        let n = Array(native.utf8)
        let t = Array((token ?? "").utf8)
        let rc = n.withUnsafeBufferPointer { nb in
            t.withUnsafeBufferPointer { tb in
                value.withUnsafeBufferPointer { vb in
                    maxFee.withUnsafeBufferPointer { fb in
                        aw_evm_check_funds(nb.baseAddress, nb.count, tb.baseAddress, tb.count, vb.baseAddress, gasLimit, fb.baseAddress)
                    }
                }
            }
        }
        try WatchCore.check(rc)
    }
}

/// 构造交易用的手续费：32 字节大端整数（wei / gas）
struct EvmFees {
    let maxPriorityFee: [UInt8]
    let maxFee: [UInt8]

    init(maxPriorityFee: UInt64, maxFee: UInt64) {
        self.maxPriorityFee = EvmAmount.bytes(maxPriorityFee)
        self.maxFee = EvmAmount.bytes(maxFee)
    }

    init(maxPriorityFee: [UInt8], maxFee: [UInt8]) {
        self.maxPriorityFee = maxPriorityFee
        self.maxFee = maxFee
    }
}

/// 一档手续费（与 Rust aw_evm_fee_tiers 的输出一一对应）
struct EvmFeeTier: Decodable, Identifiable, Hashable {
    let speed: String
    let label: String
    let maxPriorityFee: UInt64
    let maxFee: UInt64
    let maxPriorityGwei: String
    let maxFeeGwei: String
    /// gas 上限 × 最高单价（原生币单位文本）
    let maxCost: String
    var id: String { speed }
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
    /// 内置节点（决策 D35：都是无需密钥的公共节点，2026-10-11 实测可用；用户可在节点页增删）
    let nodes: [Node]
    /// 区块浏览器根地址（以 / 结尾）
    let explorer: String
    let tokens: [EvmToken]
    var id: UInt64 { chainId }

    func txURL(_ hash: String) -> URL? { Explorer.url(explorer + "tx/", hash) }
    func addressURL(_ address: String) -> URL? { Explorer.url(explorer + "address/", address) }

    static let all: [EvmNetwork] = [
        EvmNetwork(name: "Sepolia 测试网", chainId: 11_155_111, symbol: "SepoliaETH",
                   nodes: [Node(name: "PublicNode", url: "https://ethereum-sepolia-rpc.publicnode.com", builtin: true),
                           Node(name: "dRPC", url: "https://sepolia.drpc.org", builtin: true)],
                   explorer: "https://sepolia.etherscan.io/", tokens: []),
        EvmNetwork(name: "BNB Smart Chain 测试网", chainId: 97, symbol: "tBNB",
                   nodes: [Node(name: "PublicNode", url: "https://bsc-testnet-rpc.publicnode.com", builtin: true),
                           Node(name: "BNB Chain 官方", url: "https://data-seed-prebsc-1-s1.bnbchain.org:8545", builtin: true),
                           Node(name: "dRPC", url: "https://bsc-testnet.drpc.org", builtin: true)],
                   explorer: "https://testnet.bscscan.com/", tokens: []),
        EvmNetwork(name: "Ethereum 主网", chainId: 1, symbol: "ETH",
                   nodes: [Node(name: "PublicNode", url: "https://ethereum-rpc.publicnode.com", builtin: true),
                           Node(name: "dRPC", url: "https://eth.drpc.org", builtin: true),
                           Node(name: "Flashbots Protect", url: "https://rpc.flashbots.net", builtin: true, broadcastOnly: true)],
                   explorer: "https://etherscan.io/",
                   tokens: [EvmToken(symbol: "USDT", contract: "0xdAC17F958D2ee523a2206206994597C13D831ec7", decimals: 6),
                            EvmToken(symbol: "USDC", contract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals: 6)]),
        EvmNetwork(name: "BNB Smart Chain 主网", chainId: 56, symbol: "BNB",
                   nodes: [Node(name: "BNB Chain 官方", url: "https://bsc-dataseed.bnbchain.org", builtin: true),
                           Node(name: "Defibit", url: "https://bsc-dataseed1.defibit.io", builtin: true),
                           Node(name: "Ninicoin", url: "https://bsc-dataseed1.ninicoin.io", builtin: true),
                           Node(name: "PublicNode", url: "https://bsc-rpc.publicnode.com", builtin: true),
                           Node(name: "dRPC", url: "https://bsc.drpc.org", builtin: true)],
                   explorer: "https://bscscan.com/",
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
