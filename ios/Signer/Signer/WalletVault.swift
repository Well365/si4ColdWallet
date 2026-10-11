import CryptoKit
import Foundation
import Security

/// 本机加密保存的钱包（决策 D39，用户要求）：开机输 6 位 PIN 解锁，PIN 输错一次就从本机清除。
///
/// 保存的内容：助记词的单词序号、（用户选择保存时）passphrase、网络、钱包指纹。
/// 加密：
/// - Secure Enclave 里的 P-256 密钥（不可导出、只属于本机；钥匙串里只有它的加密句柄）；
/// - 每次保存生成一个临时 P-256 公钥，与 Secure Enclave 密钥做 ECDH，再用 HKDF-SHA256 混入 PIN 与随机盐，得到 256 位密钥；
/// - AES-256-GCM 加密内容，附加数据为格式标识。
/// 钥匙串项都是"设置了锁屏密码时才可用、仅本机"：手机取消锁屏密码时系统会删除它们；不进 iCloud 备份与同步。
/// 解锁失败（GCM 校验不过）一律视为 PIN 错误，立即删除密文与 Secure Enclave 密钥。
enum WalletVault {
    struct Contents {
        var words: [UInt16]
        /// 这个钱包用了 passphrase（不论有没有一起保存）
        var usesPassphrase: Bool
        /// 用户选择一起保存时才有；否则每次解锁后再输入
        var passphrase: String?
        var testnet: Bool
        var fingerprint: UInt32
    }

    enum Failure: Error, Equatable {
        /// PIN 错误：本机保存的钱包已清除
        case wrongPinWiped
        /// 本机没有 Secure Enclave，或系统拒绝创建密钥（例如没有设置锁屏密码）
        case unavailable
        /// 保存的数据损坏，已清除
        case corruptWiped
        case keychain(OSStatus)
    }

    private static let service = "org.airgapwallet.signer.vault"
    private static let blobAccount = "wallet-v1"
    private static let keyAccount = "enclave-key-v1"
    private static let aad = Data("airgap-wallet vault v1".utf8)
    private static let magic: UInt8 = 1

    // MARK: 钥匙串

    private static func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private static func save(_ data: Data, account: String) throws {
        SecItemDelete(query(account) as CFDictionary)
        var q = query(account)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        q[kSecAttrSynchronizable as String] = false
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw Failure.keychain(st) }
    }

    private static func load(_ account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    /// 本机有没有保存的钱包
    static var exists: Bool { load(blobAccount) != nil }

    /// 从本机删除保存的钱包与 Secure Enclave 密钥句柄（句柄删掉后，那把密钥再也用不到）
    static func wipe() {
        SecItemDelete(query(blobAccount) as CFDictionary)
        SecItemDelete(query(keyAccount) as CFDictionary)
    }

    // MARK: 加密

    private static func kek(shared: SharedSecret, salt: Data, pin: String) -> SymmetricKey {
        var info = Data("airgap-wallet vault kek v1|".utf8)
        info.append(Data(pin.utf8))
        return shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
    }

    /// 内容编码：版本 | 标志（位 0 测试网，位 1 用了 passphrase）| 指纹(4) | 单词数(1) | 单词序号(2 × n)
    /// | passphrase 长度(2) | passphrase UTF-8（没保存时长度为 0）
    private static func encode(_ c: Contents) -> Data {
        var b: [UInt8] = [magic, (c.testnet ? 1 : 0) | (c.usesPassphrase ? 2 : 0)]
        for shift in stride(from: 24, through: 0, by: -8) { b.append(UInt8(truncatingIfNeeded: c.fingerprint >> shift)) }
        b.append(UInt8(c.words.count))
        for w in c.words {
            b.append(UInt8(truncatingIfNeeded: w >> 8))
            b.append(UInt8(truncatingIfNeeded: w))
        }
        let p = [UInt8]((c.passphrase ?? "").utf8)
        b.append(UInt8(truncatingIfNeeded: p.count >> 8))
        b.append(UInt8(truncatingIfNeeded: p.count))
        b += p
        defer { b.withUnsafeMutableBufferPointer { $0.update(repeating: 0) } }
        return Data(b)
    }

    private static func decode(_ d: Data) -> Contents? {
        let b = [UInt8](d)
        guard b.count >= 7, b[0] == magic, b[1] <= 3 else { return nil }
        let fp = b[2..<6].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let n = Int(b[6])
        guard [12, 24].contains(n), b.count >= 7 + 2 * n + 2 else { return nil }
        var words: [UInt16] = []
        for i in 0..<n { words.append(UInt16(b[7 + 2 * i]) << 8 | UInt16(b[8 + 2 * i])) }
        let at = 7 + 2 * n
        let plen = Int(UInt16(b[at]) << 8 | UInt16(b[at + 1]))
        guard b.count == at + 2 + plen, words.allSatisfy({ $0 < 2048 }) else { return nil }
        let pass = String(decoding: b[(at + 2)...], as: UTF8.self)
        let uses = b[1] & 2 != 0
        guard uses || plen == 0 else { return nil }
        return Contents(words: words, usesPassphrase: uses, passphrase: plen > 0 ? pass : nil,
                        testnet: b[1] & 1 != 0, fingerprint: fp)
    }

    /// 保存（覆盖本机原有的钱包）。PIN 必须是 6 位数字
    static func store(_ contents: Contents, pin: String) throws {
        guard isValidPin(pin), SecureEnclave.isAvailable, [12, 24].contains(contents.words.count),
              (contents.passphrase ?? "").utf8.count <= Int(UInt16.max) else { throw Failure.unavailable }
        wipe()
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .privateKeyUsage, nil
        ) else { throw Failure.unavailable }
        let enclave: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        } catch {
            throw Failure.unavailable
        }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try enclave.sharedSecretFromKeyAgreement(with: ephemeral.publicKey)
        var salt = Data(count: 16)
        let st = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard st == errSecSuccess else { throw Failure.unavailable }
        var plain = encode(contents)
        defer { plain.resetBytes(in: 0..<plain.count) }
        let sealed = try AES.GCM.seal(plain, using: kek(shared: shared, salt: salt, pin: pin), authenticating: aad)
        guard let combined = sealed.combined else { throw Failure.unavailable }
        var blob = Data([magic])
        blob.append(salt)
        blob.append(ephemeral.publicKey.x963Representation)
        blob.append(combined)
        try save(enclave.dataRepresentation, account: keyAccount)
        try save(blob, account: blobAccount)
    }

    /// 解锁。PIN 错误（或数据被改动）时立即清除本机保存的钱包
    static func unlock(pin: String) throws -> Contents {
        guard let blob = load(blobAccount), let keyData = load(keyAccount) else { throw Failure.unavailable }
        let b = [UInt8](blob)
        guard b.count > 1 + 16 + 65 + 28, b[0] == magic,
              let enclave = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData),
              let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: b[17..<82])
        else {
            wipe()
            throw Failure.corruptWiped
        }
        let salt = Data(b[1..<17])
        guard isValidPin(pin),
              let shared = try? enclave.sharedSecretFromKeyAgreement(with: ephemeral),
              let box = try? AES.GCM.SealedBox(combined: b[82...]),
              var plain = try? AES.GCM.open(box, using: kek(shared: shared, salt: salt, pin: pin), authenticating: aad)
        else {
            wipe()
            throw Failure.wrongPinWiped
        }
        defer { plain.resetBytes(in: 0..<plain.count) }
        guard let c = decode(plain) else {
            wipe()
            throw Failure.corruptWiped
        }
        return c
    }

    static func isValidPin(_ pin: String) -> Bool {
        pin.count == 6 && pin.allSatisfy { $0.isASCII && $0.isNumber }
    }
}
