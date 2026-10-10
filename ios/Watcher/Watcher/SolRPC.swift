import Foundation

/// 最小 Solana JSON-RPC 客户端（P2c）。观察机不信任节点：余额只用于显示与构造前提示，
/// 最近区块哈希与优先费只用来构造交易；交易内容由签名机独立审查。
struct SolRPC {
    let url: URL
    var timeout: TimeInterval = 20

    struct RPCError: Error {
        let message: String
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

    private static func u64(_ any: Any?) throws -> UInt64 {
        if let n = any as? NSNumber, n.int64Value >= 0 { return n.uint64Value }
        if let s = any as? String, let v = UInt64(s) { return v }
        throw RPCError(message: "节点返回的数值格式不对")
    }

    func genesisHash() async throws -> String {
        guard let s = try await call("getGenesisHash", []) as? String else { throw RPCError(message: "节点返回的数据格式不对") }
        return s
    }

    func slot() async throws -> UInt64 {
        try Self.u64(try await call("getSlot", []))
    }

    /// SOL 余额（lamports）
    func balance(_ address: String) async throws -> UInt64 {
        let r = try await call("getBalance", [address, ["commitment": "confirmed"]]) as? [String: Any]
        return try Self.u64(r?["value"])
    }

    /// 代币账户余额（最小单位）；账户还不存在时为 0
    func tokenBalance(_ tokenAccount: String) async throws -> UInt64 {
        do {
            let r = try await call("getTokenAccountBalance", [tokenAccount, ["commitment": "confirmed"]]) as? [String: Any]
            let v = r?["value"] as? [String: Any]
            return try Self.u64(v?["amount"])
        } catch let e as RPCError where e.message.contains("could not find account") {
            return 0
        }
    }

    func latestBlockhash() async throws -> String {
        let r = try await call("getLatestBlockhash", [["commitment": "confirmed"]]) as? [String: Any]
        guard let v = r?["value"] as? [String: Any], let h = v["blockhash"] as? String else {
            throw RPCError(message: "节点没有返回最近区块哈希")
        }
        return h
    }

    /// 最近区块的优先费样本（微 lamports / 计算单元）；`accounts` 为这笔交易会写入的账户
    func prioritizationFees(_ accounts: [String]) async throws -> [UInt64] {
        guard let list = try await call("getRecentPrioritizationFees", [accounts]) as? [[String: Any]] else {
            throw RPCError(message: "节点返回的数据格式不对")
        }
        return try list.prefix(1024).map { try Self.u64($0["prioritizationFee"]) }
    }

    /// 广播（base64 编码的已签交易），返回交易签名
    func send(base64: String) async throws -> String {
        let opts: [String: Any] = ["encoding": "base64", "preflightCommitment": "confirmed"]
        guard let sig = try await call("sendTransaction", [base64, opts]) as? String else {
            throw RPCError(message: "节点没有返回交易签名")
        }
        return sig
    }
}
