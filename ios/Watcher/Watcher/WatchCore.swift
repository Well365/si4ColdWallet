import AWWatchC
import Foundation

/// 观察机 Rust 核心的 Swift 封装（只含公钥与交易构造，不含任何私钥代码）。
enum WatchCore {
    static let expectedABI: UInt32 = 4

    struct Failure: Error {
        let code: Int32
        var message: String {
            switch code {
            case AW_ERR_TX_REJECT_BASE - 19: return "余额不足（含手续费）"
            case AW_ERR_TX_REJECT_BASE - 20: return "UTXO 与本账户地址不符"
            case AW_ERR_TX_REJECT_BASE - 21: return "代币余额不足"
            case AW_ERR_TX_REJECT_BASE - 17: return "签名机返回的交易与发出的不一致，拒绝"
            case AW_ERR_TX_REJECT_BASE - 18: return "签名无效，拒绝"
            case AW_ERR_UR_OTHER_SET: return "扫到了另一组二维码，请只扫同一组"
            case AW_ERR_UR_TYPE: return "二维码类型不对"
            case AW_ERR_BAD_ARGUMENT: return "输入无效（地址格式或校验和不对、金额格式不对等）"
            case AW_ERR_EVM_REJECT_BASE - 12: return "签名无效或不属于本账户，拒绝"
            case AW_ERR_EVM_REJECT_BASE - 13: return "签名机返回的签名与本次请求不对应，拒绝"
            case AW_ERR_EVM_REJECT_BASE - 6: return "账户不是以太坊账户（m/44'/60'/0'）"
            case AW_ERR_EVM_REJECT_BASE - 1: return "数据无法解析：二维码类型不对，或 JSON 不严谨（重复键、多余或缺少字段、数值越界、引号被输入法改成中文引号等）"
            case AW_ERR_EVM_REJECT_BASE - 2: return "不支持的数据类型"
            case AW_ERR_EVM_REJECT_BASE - 5: return "结构化数据里的链 ID 与所选网络不一致"
            case AW_ERR_EVM_REJECT_BASE - 8: return "Safe 多签的 DELEGATECALL（operation ≠ 0）一律拒绝"
            case AW_ERR_EVM_REJECT_BASE - 14: return "疑似盲签（approveHash、恰好 32 字节的非文字消息等），拒绝"
            case AW_ERR_EVM_REJECT_BASE - 16: return "内容超长（单个字段超过 1024 字节、消息超过 4096 字节或结构太复杂），签名机无法完整显示"
            case AW_ERR_EVM_REJECT_BASE - 17: return "Safe 多签对自身的所有者、阈值、模块、守卫或回退处理器变更会移交多签控制权，拒绝"
            default: return "错误 \(code)"
            }
        }
    }

    static func check(_ rc: Int32) throws {
        guard rc == AW_OK else { throw Failure(code: rc) }
    }

    static func takeBuffer(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int) -> [UInt8] {
        guard let ptr else { return [] }
        defer { aw_buf_free(ptr, len) }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    static func takeString(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int) -> String {
        String(decoding: takeBuffer(ptr, len), as: UTF8.self)
    }
}

/// 观察账户。
@MainActor
final class WatchAccount {
    nonisolated(unsafe) let raw: OpaquePointer

    private init(raw: OpaquePointer) {
        self.raw = raw
    }

    deinit {
        aw_watch_free(raw)
    }

    static func from(scan: URScan) throws -> WatchAccount {
        var out: OpaquePointer?
        try WatchCore.check(aw_watch_from_decoder(scan.raw, &out))
        guard let out else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        return WatchAccount(raw: out)
    }

    static func from(ur: String) throws -> WatchAccount {
        let bytes = Array(ur.utf8)
        var out: OpaquePointer?
        let rc = bytes.withUnsafeBufferPointer { aw_watch_from_ur($0.baseAddress, $0.count, &out) }
        try WatchCore.check(rc)
        guard let out else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        return WatchAccount(raw: out)
    }

    var urString: String {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        guard aw_watch_to_ur(raw, &p, &l) == AW_OK else { return "" }
        return WatchCore.takeString(p, l)
    }

    var fingerprint: String { String(format: "%08x", aw_watch_fingerprint(raw)) }
    var isTestnet: Bool { aw_watch_is_testnet(raw) == 1 }

    func address(change: Bool, index: UInt32) -> String {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        guard aw_watch_address(raw, change ? 1 : 0, index, &p, &l) == AW_OK else { return "" }
        return WatchCore.takeString(p, l)
    }

    func buildPayment(utxos: [UTXO], to: String, amount: UInt64, feeRate: UInt64, changeIndex: UInt32) throws -> PendingPayment {
        var blob = [UInt8]()
        blob.append(contentsOf: UInt32(utxos.count).bigEndianBytes)
        for u in utxos {
            blob.append(u.change ? 1 : 0)
            blob.append(contentsOf: u.index.bigEndianBytes)
            blob.append(contentsOf: u.vout.bigEndianBytes)
            blob.append(contentsOf: UInt32(u.rawTx.count).bigEndianBytes)
            blob.append(contentsOf: u.rawTx)
        }
        let toBytes = Array(to.utf8)
        var pending: OpaquePointer?
        var jp: UnsafeMutablePointer<UInt8>?
        var jl = 0
        let rc = blob.withUnsafeBufferPointer { b in
            toBytes.withUnsafeBufferPointer { t in
                aw_watch_build_payment(raw, b.baseAddress, b.count, t.baseAddress, t.count, amount, feeRate, changeIndex, &pending, &jp, &jl)
            }
        }
        try WatchCore.check(rc)
        guard let pending else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let summary = try decoder.decode(PaymentSummary.self, from: Data(WatchCore.takeBuffer(jp, jl)))
        return PendingPayment(raw: pending, account: self, summary: summary)
    }
}

struct UTXO {
    let txid: String
    let vout: UInt32
    let value: UInt64
    let change: Bool
    let index: UInt32
    let rawTx: [UInt8]
}

struct PaymentSummary: Decodable {
    let inputs: Int
    let amountSat: UInt64
    let feeSat: UInt64
    let changeSat: UInt64?
    let vsizeEstimate: UInt64
}

@MainActor
final class PendingPayment {
    private nonisolated(unsafe) let raw: OpaquePointer
    private let account: WatchAccount
    let summary: PaymentSummary

    init(raw: OpaquePointer, account: WatchAccount, summary: PaymentSummary) {
        self.raw = raw
        self.account = account
        self.summary = summary
    }

    deinit {
        aw_pending_free(raw)
    }

    func frames() throws -> URFrames {
        var enc: OpaquePointer?
        try WatchCore.check(aw_pending_encoder(raw, &enc))
        guard let enc else { throw WatchCore.Failure(code: AW_ERR_STATE) }
        return URFrames(raw: enc)
    }

    /// 合并签名，返回可广播交易的十六进制。
    func finalize(signedPSBT: [UInt8]) throws -> String {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        let rc = signedPSBT.withUnsafeBufferPointer { aw_pending_finalize(account.raw, raw, $0.baseAddress, $0.count, &p, &l) }
        try WatchCore.check(rc)
        return WatchCore.takeString(p, l)
    }
}

final class URFrames: QRFrameSource {
    private nonisolated(unsafe) let raw: OpaquePointer
    let partCount: Int

    init(raw: OpaquePointer) {
        self.raw = raw
        partCount = aw_ur_encoder_seq_len(raw)
    }

    deinit {
        aw_ur_encoder_free(raw)
    }

    func nextFrame() -> String? {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        guard aw_ur_encoder_next(raw, &p, &l) == AW_OK else { return nil }
        return String(bytes: WatchCore.takeBuffer(p, l), encoding: .ascii)
    }
}

@MainActor
final class URScan {
    nonisolated(unsafe) let raw: OpaquePointer = aw_ur_decoder_new()

    deinit {
        aw_ur_decoder_free(raw)
    }

    func receive(_ text: String) throws -> Bool {
        let bytes = Array(text.utf8)
        let rc = bytes.withUnsafeBufferPointer { aw_ur_decoder_receive(raw, $0.baseAddress, $0.count) }
        if rc < 0 { throw WatchCore.Failure(code: rc) }
        return rc == 1
    }

    var progress: (got: Int, total: Int) {
        var got = 0
        var total = 0
        _ = aw_ur_decoder_progress(raw, &got, &total)
        return (got, total)
    }

    func takePSBT() throws -> [UInt8] {
        var p: UnsafeMutablePointer<UInt8>?
        var l = 0
        try WatchCore.check(aw_ur_decoder_take_psbt(raw, &p, &l))
        return WatchCore.takeBuffer(p, l)
    }
}

extension UInt32 {
    var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian) { Array($0) } }
}
