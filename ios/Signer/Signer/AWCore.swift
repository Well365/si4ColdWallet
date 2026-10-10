import AWSignerC
import Foundation
import Security

/// Rust 核心的 Swift 薄封装。所有对 C 接口的调用都集中在这里。
/// 秘密只存在于 Rust 会话中；Swift 只传单词序号，passphrase 由 SecureField 输入后立即交给 Rust。
enum AWCore {
    static let expectedABI: UInt32 = 4

    enum Failure: Error, Equatable {
        case abiMismatch(found: UInt32)
        case selftest(code: Int32)
        case random(status: OSStatus)
        case core(code: Int32)

        var message: String {
            switch self {
            case .abiMismatch(let v): return "核心接口版本不符（\(v)），请重新构建"
            case .selftest(let c): return "启动自检失败（\(c)），已停止"
            case .random(let s): return "系统随机数不可用（\(s)），已停止"
            case .core(let c): return AWCore.describe(code: c)
            }
        }
    }

    static func startupCheck() -> Result<Void, Failure> {
        let abi = aw_abi_version()
        guard abi == expectedABI else { return .failure(.abiMismatch(found: abi)) }
        let rc = aw_selftest()
        guard rc == AW_OK else { return .failure(.selftest(code: rc)) }
        guard words.count == 2048, words.first == "abandon", words.last == "zoo" else {
            return .failure(.selftest(code: AW_ERR_SELFTEST))
        }
        return .success(())
    }

    /// 32 字节系统安全随机数（威胁 T1：检查返回值，绝不静默回退）。
    static func systemRandom32() throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw Failure.random(status: status) }
        guard bytes.contains(where: { $0 != 0 }) else { throw Failure.random(status: errSecInternalError) }
        return bytes
    }

    /// BIP39 英文词表（公开数据，来自 Rust 侧，与官方哈希核对过）。
    static let words: [String] = (0..<2048).map { i in
        var len = 0
        guard let p = aw_wordlist_word(UInt16(i), &len) else { return "" }
        return String(decoding: UnsafeBufferPointer(start: p, count: len), as: UTF8.self)
    }

    static func check(_ rc: Int32) throws {
        guard rc == AW_OK else { throw Failure.core(code: rc) }
    }

    static func takeBuffer(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int) -> [UInt8] {
        guard let ptr else { return [] }
        defer { aw_buf_free(ptr, len) }
        return Array(UnsafeBufferPointer(start: ptr, count: len))
    }

    /// 错误码 → 中文说明（交易拒绝原因与 Rust 侧 btc_error_code 一一对应）。
    static func describe(code: Int32) -> String {
        let reasons: [Int32: String] = [
            1: "交易数据无法解析", 2: "交易没有输入或输出", 3: "输入或输出数量过多",
            4: "交易已被最终化", 5: "缺少完整的前序交易（可能是手续费欺骗），拒绝签名",
            6: "前序交易与输入不符，拒绝签名", 7: "输入金额与前序交易不一致（手续费欺骗），拒绝签名",
            8: "包含不支持的输入类型", 9: "包含不属于本钱包的输入，拒绝签名",
            10: "要求非 SIGHASH_ALL 签名类型，拒绝签名", 11: "找零地址与声称的路径不符（找零被替换），拒绝签名",
            12: "包含无法显示为地址的输出", 13: "输出总额大于输入总额", 14: "金额溢出",
            15: "密钥派生失败", 16: "签名自检失败", 19: "余额不足", 20: "UTXO 不属于本钱包",
        ]
        let evmReasons: [Int32: String] = [
            1: "请求数据无法解析，或数据类型与内容不符", 2: "不支持的交易或数据类型",
            3: "EIP-7702 授权交易：会把你的账户委托给别的合约，拒绝签名",
            4: "交易没有链 ID，可被跨链重放，拒绝签名", 5: "请求声明的链与交易内的链不一致，拒绝签名",
            6: "签名路径不属于本钱包的地址，拒绝签名", 7: "请求声明的地址与本钱包不符，拒绝签名",
            8: "Safe 多签的 DELEGATECALL 可改写多签合约本身，拒绝签名", 9: "数值溢出",
            10: "密钥派生失败", 11: "签名自检失败", 12: "签名无效", 13: "签名与请求不对应",
            14: "预先批准一笔看不到内容的多签交易（Safe approveHash），拒绝签名",
        ]
        if code <= AW_ERR_EVM_REJECT_BASE, let r = evmReasons[AW_ERR_EVM_REJECT_BASE - code] { return r }
        if code <= AW_ERR_TX_REJECT_BASE, let r = reasons[AW_ERR_TX_REJECT_BASE - code] { return r }
        switch code {
        case AW_ERR_UNSUPPORTED_REQUEST: return "这不是签名请求二维码（例如是账户公钥），请扫描观察机上的待签请求"
        case AW_ERR_NEEDS_CONFIRMATION: return "这笔请求含高风险警告，请先勾选确认"
        case AW_ERR_BAD_MNEMONIC: return "助记词无效（校验和不符）"
        case AW_ERR_FINGERPRINT_MISMATCH: return "解锁得到的钱包指纹与你填写的预期指纹不一致，多半是 passphrase 输错了。助记词已保留，请重新输入 passphrase"
        case AW_ERR_RNG_HEALTH: return "系统随机数没有通过健康检查（可能是设备故障或被篡改），已停止生成。请改用\"纯骰子\"模式"
        case AW_ERR_DICE_TOO_FEW: return "骰子次数不够：12 词至少 50 次，24 词至少 100 次"
        case AW_ERR_DICE_POOR: return "骰子点数看起来不像真实掷出的（某一面过多、长串相同或有规律），请用真实骰子重新掷"
        case AW_ERR_BAD_ARGUMENT: return "参数无效"
        case AW_ERR_STATE: return "当前状态不允许此操作"
        case AW_ERR_UR_OTHER_SET: return "扫到了另一组二维码，请只扫同一组"
        case AW_ERR_UR_TYPE: return "二维码类型不对"
        case AW_ERR_UR: return "二维码内容无效"
        default: return "错误 \(code)"
        }
    }
}

/// 签名机会话。释放时 Rust 侧清零全部秘密。
@MainActor
final class SignerSession {
    private nonisolated(unsafe) let raw: OpaquePointer

    init() {
        raw = aw_session_new()
    }

    deinit {
        aw_session_free(raw)
    }

    /// 生成新助记词：系统随机数 + 可选骰子点数（只含 1–6）。
    func generate(dice: [UInt8], wordCount: Int) throws {
        var sys = try AWCore.systemRandom32()
        defer { sys.withUnsafeMutableBufferPointer { $0.update(repeating: 0) } }
        let rc = sys.withUnsafeBufferPointer { s in
            dice.withUnsafeBufferPointer { d in
                aw_session_generate(raw, s.baseAddress, d.baseAddress, d.count, UInt8(wordCount))
            }
        }
        try AWCore.check(rc)
    }

    /// 纯骰子模式：熵 = SHA-256(骰子点数字符串)，不使用设备随机数，可在任何电脑上独立复算。
    func generateFromDice(_ dice: [UInt8], wordCount: Int) throws {
        let rc = dice.withUnsafeBufferPointer { aw_session_generate_dice(raw, $0.baseAddress, $0.count, UInt8(wordCount)) }
        try AWCore.check(rc)
    }

    func setWords(_ indices: [UInt16]) throws {
        let rc = indices.withUnsafeBufferPointer { aw_session_set_words(raw, $0.baseAddress, $0.count) }
        try AWCore.check(rc)
    }

    /// 只用于备份抄写。
    var wordIndices: [Int] {
        (0..<aw_session_word_count(raw)).map { Int(aw_session_word_at(raw, $0)) }
    }

    func setPassphrase(_ text: String) throws {
        var bytes = Array(text.decomposedStringWithCompatibilityMapping.utf8)
        defer { bytes.withUnsafeMutableBufferPointer { $0.update(repeating: 0) } }
        let rc = bytes.withUnsafeBufferPointer { aw_session_set_passphrase(raw, $0.baseAddress, $0.count) }
        try AWCore.check(rc)
        usesPassphrase = !bytes.isEmpty
    }

    /// 是否用 passphrase 解锁（只用于界面显示钱包类型）
    private(set) var usesPassphrase = false

    var walletKind: String { usesPassphrase ? "passphrase 钱包" : "标准钱包" }

    /// 解锁时核对的预期指纹；nil 表示不核对。不符时 Rust 拒绝解锁并保留助记词。
    func expectFingerprint(_ fp: UInt32?) throws {
        try AWCore.check(aw_session_expect_fingerprint(raw, fp == nil ? 0 : 1, fp ?? 0))
    }

    func unlock(testnet: Bool) throws {
        var rand = try AWCore.systemRandom32()
        defer { rand.withUnsafeMutableBufferPointer { $0.update(repeating: 0) } }
        let rc = rand.withUnsafeBufferPointer { aw_session_unlock(raw, testnet ? 1 : 0, $0.baseAddress) }
        try AWCore.check(rc)
    }

    /// 第 index 个收款地址（Rust 生成）
    func address(chain: AddressChain, index: UInt32) throws -> AddressInfo {
        var ptr: UnsafeMutablePointer<UInt8>?
        var len = 0
        try AWCore.check(aw_session_address(raw, chain.rawValue, index, &ptr, &len))
        return try JSONDecoder().decode(AddressInfo.self, from: Data(AWCore.takeBuffer(ptr, len)))
    }

    var fingerprint: String {
        String(format: "%08x", aw_session_fingerprint(raw))
    }

    func exportAccount(_ chain: AccountChain) throws -> URFrames {
        var enc: OpaquePointer?
        try AWCore.check(aw_session_export_account(raw, chain.rawValue, &enc))
        guard let enc else { throw AWCore.Failure.core(code: AW_ERR_STATE) }
        return URFrames(raw: enc)
    }

    /// 审查已扫描完成的请求（BTC 的 PSBT 或 EVM 的 eth-sign-request），返回通用显示模型。
    func review(_ scan: URScan) throws -> DisplayModel {
        var ptr: UnsafeMutablePointer<UInt8>?
        var len = 0
        try AWCore.check(aw_session_review_ur(raw, scan.raw, &ptr, &len))
        let json = AWCore.takeBuffer(ptr, len)
        return try JSONDecoder().decode(DisplayModel.self, from: Data(json))
    }

    /// `confirmedDanger`：用户已勾选"已阅读高风险警告"。Rust 侧会再次检查，界面无法绕过。
    func sign(_ scan: URScan, confirmedDanger: Bool) throws -> URFrames {
        var enc: OpaquePointer?
        try AWCore.check(aw_session_sign_ur(raw, scan.raw, confirmedDanger ? 1 : 0, &enc))
        guard let enc else { throw AWCore.Failure.core(code: AW_ERR_STATE) }
        return URFrames(raw: enc)
    }
}

/// 动画二维码帧（Rust 喷泉码编码器）。
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
        var ptr: UnsafeMutablePointer<UInt8>?
        var len = 0
        guard aw_ur_encoder_next(raw, &ptr, &len) == AW_OK else { return nil }
        let bytes = AWCore.takeBuffer(ptr, len)
        return String(bytes: bytes, encoding: .ascii)
    }
}

/// 可以显示收款地址的链（与 aw_session_address 的 chain 参数一致）
enum AddressChain: UInt32, CaseIterable, Identifiable {
    case btc = 0, evm = 1, sol = 2, doge = 3, tron = 4, near = 5

    var id: UInt32 { rawValue }

    var title: String {
        switch self {
        case .btc: return "BTC"
        case .evm: return "ETH / BNB"
        case .sol: return "SOL"
        case .doge: return "DOGE"
        case .tron: return "TRON"
        case .near: return "NEAR"
        }
    }

    /// Solana / NEAR 只预先计算了前 20 个账户
    var maxIndex: UInt32 { self == .sol || self == .near ? 19 : 999 }
}

struct AddressInfo: Decodable {
    let chain: String
    let path: String
    let address: String
    let note: String
    /// 只用于显示：签名机不联网，网址由用户在别的设备上输入
    let explorers: [ExplorerLink]
}

struct ExplorerLink: Decodable, Identifiable {
    let name: String
    let url: String
    var id: String { url }
}

/// passphrase 输入的检查（只给提醒，不替用户做决定）
enum PassphraseCheck {
    static func cautions(_ p: String) -> [String] {
        var out: [String] = []
        if p.unicodeScalars.contains(where: { !$0.isASCII }) {
            out.append("含中文、全角或其他非 ASCII 字符：换设备或换输入法时，可能输不出完全相同的字符")
        }
        if p.first?.isWhitespace == true || p.last?.isWhitespace == true {
            out.append("首尾有空格：下次输入时很容易漏掉")
        }
        if !p.isEmpty && p.count < 8 {
            out.append("少于 8 个字符：如果助记词泄露，短 passphrase 可以被暴力猜出")
        }
        return out
    }

    /// "73c5da0a" → 0x73c5da0a；允许空格与大写；空串返回 .none，格式错误返回 .invalid
    enum Fingerprint: Equatable { case none, invalid, value(UInt32) }

    static func fingerprint(_ text: String) -> Fingerprint {
        let t = text.filter { !$0.isWhitespace }.lowercased()
        if t.isEmpty { return .none }
        guard t.count == 8, t.allSatisfy(\.isHexDigit), let v = UInt32(t, radix: 16) else { return .invalid }
        return .value(v)
    }
}

/// 签名机可以导出的账户（与 aw_session_export_account 的 chain 参数一致）
enum AccountChain: UInt32, CaseIterable, Identifiable {
    case btc = 0
    case evm = 1

    var id: UInt32 { rawValue }

    var title: String {
        switch self {
        case .btc: return "比特币（BTC）"
        case .evm: return "以太坊 / BNB 等 EVM 链"
        }
    }

    var pathNote: String {
        switch self {
        case .btc: return "只包含账户公钥（m/84'/…/0'），不包含任何私钥。"
        case .evm: return "只包含账户公钥（m/44'/60'/0'），不包含任何私钥。ETH、BNB Smart Chain 等所有 EVM 链共用同一组地址。"
        }
    }
}

/// 扫码解码器。收齐后整体交给 Rust 审查/签名，Swift 不解析请求内容。
@MainActor
final class URScan {
    nonisolated(unsafe) let raw: OpaquePointer = aw_ur_decoder_new()

    deinit {
        aw_ur_decoder_free(raw)
    }

    /// 返回 true 表示已收齐。
    func receive(_ text: String) throws -> Bool {
        let bytes = Array(text.utf8)
        let rc = bytes.withUnsafeBufferPointer { aw_ur_decoder_receive(raw, $0.baseAddress, $0.count) }
        if rc < 0 { throw AWCore.Failure.core(code: rc) }
        return rc == 1
    }

    var progress: (got: Int, total: Int) {
        var got = 0
        var total = 0
        _ = aw_ur_decoder_progress(raw, &got, &total)
        return (got, total)
    }
}

/// 通用显示模型（与 Rust aw-common::display 一一对应）：Rust 决定显示什么，这里只负责渲染。
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

    var hasDanger: Bool { warnings.contains { $0.level == "danger" } }
}
