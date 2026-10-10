import Foundation

/// 最小 JSON-RPC 客户端（以太坊节点接口）。观察机不信任节点：nonce、手续费只用来构造交易，
/// 交易内容由签名机独立审查；节点返回的余额只用于显示。
struct EvmRPC {
    let url: URL

    struct RPCError: Error {
        let message: String
    }

    private func call(_ method: String, _ params: [Any]) async throws -> Any {
        let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": method, "params": params]
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 20
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

    private static func u64(_ hex: String) throws -> UInt64 {
        guard let v = UInt64(hex.dropFirst(2), radix: 16) else { throw RPCError(message: "数值超出范围") }
        return v
    }

    func chainId() async throws -> UInt64 {
        try Self.u64(try await quantity("eth_chainId", []))
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

    /// EIP-1559 手续费：优先费取节点建议值；最高单价 = 2 × 最新基础费 + 优先费
    func fees() async throws -> EvmFees {
        let prio = try Self.u64(try await quantity("eth_maxPriorityFeePerGas", []))
        guard let block = try await call("eth_getBlockByNumber", ["latest", false]) as? [String: Any],
              let baseHex = block["baseFeePerGas"] as? String
        else { throw RPCError(message: "节点没有返回基础费（该链可能不支持 EIP-1559）") }
        let base = try Self.u64(baseHex)
        let (doubled, o1) = base.multipliedReportingOverflow(by: 2)
        let (maxFee, o2) = doubled.addingReportingOverflow(prio)
        guard !o1, !o2 else { throw RPCError(message: "手续费数值溢出") }
        return EvmFees(maxPriorityFee: prio, maxFee: maxFee)
    }

    /// 广播已签交易，返回交易哈希
    func sendRaw(_ hex: String) async throws -> String {
        guard let h = try await call("eth_sendRawTransaction", [hex]) as? String else {
            throw RPCError(message: "节点没有返回交易哈希")
        }
        return h
    }
}
