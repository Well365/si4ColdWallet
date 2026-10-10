import Foundation

/// 最小 JSON-RPC 客户端（以太坊节点接口）。观察机不信任节点：nonce、手续费只用来构造交易，
/// 交易内容由签名机独立审查；节点返回的余额只用于显示与构造前的提示。
struct EvmRPC {
    let url: URL
    var timeout: TimeInterval = 20

    struct RPCError: Error {
        let message: String
    }

    /// eth_feeHistory 的结果：下一区块基础费（节点不支持 EIP-1559 时为 nil）与各区块 10/50/90 百分位优先费（展平）
    struct FeeHistory {
        let nextBaseFee: UInt64?
        let rewards: [UInt64]
    }

    private func call(_ method: String, _ params: [Any]) async throws -> Any {
        let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": method, "params": params]
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = timeout
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw RPCError(message: "节点响应无效") }
        if let err = obj["error"] as? [String: Any] {
            throw RPCError(message: (err["message"] as? String) ?? "节点返回错误")
        }
        guard let result = obj["result"] else { throw RPCError(message: "节点响应缺少结果") }
        return result
    }

    private func quantity(_ method: String, _ params: [Any]) async throws -> String {
        guard let s = try await call(method, params) as? String, s.hasPrefix("0x") else {
            throw RPCError(message: "节点返回的数值格式不对")
        }
        return s
    }

    static func u64(_ hex: String) throws -> UInt64 {
        guard hex.hasPrefix("0x"), let v = UInt64(hex.dropFirst(2), radix: 16) else {
            throw RPCError(message: "数值超出范围")
        }
        return v
    }

    func chainId() async throws -> UInt64 {
        try Self.u64(try await quantity("eth_chainId", []))
    }

    func blockNumber() async throws -> UInt64 {
        try Self.u64(try await quantity("eth_blockNumber", []))
    }

    /// 原生币余额（十六进制数量）
    func balance(_ address: String) async throws -> String {
        try await quantity("eth_getBalance", [address, "latest"])
    }

    /// ERC-20 余额：balanceOf(address)，返回去掉前导零的十六进制数量
    func tokenBalance(_ token: String, owner: String) async throws -> String {
        let data = "0x70a08231" + String(repeating: "0", count: 24) + owner.dropFirst(2).lowercased()
        guard let s = try await call("eth_call", [["to": token, "data": data], "latest"]) as? String, s.hasPrefix("0x") else {
            throw RPCError(message: "节点返回的数据格式不对")
        }
        let trimmed = s.dropFirst(2).drop { $0 == "0" }
        return "0x" + (trimmed.isEmpty ? "0" : String(trimmed))
    }

    func nonce(_ address: String) async throws -> UInt64 {
        try Self.u64(try await quantity("eth_getTransactionCount", [address, "pending"]))
    }

    func gasPrice() async throws -> UInt64 {
        try Self.u64(try await quantity("eth_gasPrice", []))
    }

    /// 节点建议的优先费；不支持时为 0
    func maxPriorityFee() async -> UInt64 {
        (try? Self.u64(try await quantity("eth_maxPriorityFeePerGas", []))) ?? 0
    }

    /// 最近 `blocks` 个区块的基础费与优先费分布。节点不支持 eth_feeHistory 时退回最新区块的基础费、没有分布
    func feeHistory(blocks: Int = 10) async throws -> FeeHistory {
        if let obj = try? await call("eth_feeHistory", ["0x" + String(blocks, radix: 16), "latest", [10, 50, 90]]) as? [String: Any],
           let bases = obj["baseFeePerGas"] as? [String], let last = bases.last {
            let rows = (obj["reward"] as? [[String]]) ?? []
            var flat: [UInt64] = []
            for r in rows.prefix(64) where r.count == 3 {
                flat += try r.map(Self.u64)
            }
            return FeeHistory(nextBaseFee: try Self.u64(last), rewards: flat)
        }
        guard let block = try await call("eth_getBlockByNumber", ["latest", false]) as? [String: Any] else {
            throw RPCError(message: "节点没有返回最新区块")
        }
        let base = try (block["baseFeePerGas"] as? String).map(Self.u64)
        return FeeHistory(nextBaseFee: base, rewards: [])
    }

    /// 估算 gas 用量。`data`、`value` 为 "0x…" 文本
    func estimateGas(from: String, to: String, value: String, data: String) async throws -> UInt64 {
        try Self.u64(try await quantity("eth_estimateGas", [["from": from, "to": to, "value": value, "data": data]]))
    }

    /// 广播已签交易，返回交易哈希
    func sendRaw(_ hex: String) async throws -> String {
        guard let h = try await call("eth_sendRawTransaction", [hex]) as? String else {
            throw RPCError(message: "节点没有返回交易哈希")
        }
        return h
    }
}
