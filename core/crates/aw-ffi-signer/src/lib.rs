//! 签名机 C 接口（决策 D2）。头文件：`include/aw_signer.h`，两者必须同步修改。
//!
//! 秘密（助记词、passphrase、账户私钥）只存在于 Rust 管理的会话对象 `AwSession` 中；
//! Swift 只持有不透明指针（P1 安全审查 M13）。每个处理秘密的调用返回前清洗栈（P1 审查 M1）。
#![allow(unsafe_code)]

mod addresses;
mod entropy;
mod selftest;

use aw_bip39::{wordlist, Mnemonic};
use aw_chain_btc::account_ur::account_to_hdkey;
use aw_chain_btc::review::review;
use aw_chain_btc::sign::{sign_psbt, SigningAccount};
use aw_chain_btc::BtcError;
use aw_chain_evm::request::{decode_request, encode_signature, SIGN_REQUEST};
use aw_chain_evm::sign::{sign as evm_sign, EvmSigner};
use aw_chain_evm::EvmError;
use aw_chain_sol::sign::SolSigner;
use aw_chain_sol::SolError;
use aw_common::display::Display;
use aw_common::secret::{scrub_stack, SecretBytes, SecretVec};
use aw_ffi_common::{
    clear_out, decoded_ur, hand_out, input, new_encoder, AwUrDecoder, AwUrEncoder,
    AW_ERR_BAD_ARGUMENT, AW_ERR_BAD_MNEMONIC, AW_ERR_DERIVATION, AW_ERR_DICE_POOR,
    AW_ERR_DICE_TOO_FEW, AW_ERR_EVM_REJECT_BASE, AW_ERR_FINGERPRINT_MISMATCH,
    AW_ERR_NEEDS_CONFIRMATION, AW_ERR_NULL_POINTER, AW_ERR_RNG_HEALTH, AW_ERR_SELFTEST,
    AW_ERR_STATE, AW_ERR_TX_REJECT_BASE, AW_ERR_UNSUPPORTED_REQUEST, AW_OK,
};
use aw_ur::registry::{decode_psbt, encode_hdkey, encode_psbt, Style};
use aw_ur::ur::Ur;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::Network;

aw_ffi_common::define_common_ffi!();

pub const AW_ABI_VERSION: u32 = 5;
const MAX_PASSPHRASE: usize = 1024;
const MAX_DICE: usize = 1024;
const MAX_PSBT: usize = 512 * 1024;
/// 导出账户：链编号
const CHAIN_BTC: u32 = 0;
const CHAIN_EVM: u32 = 1;

#[no_mangle]
pub extern "C" fn aw_abi_version() -> u32 {
    AW_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn aw_selftest() -> i32 {
    let ok = selftest::run_all();
    scrub_stack();
    if ok {
        AW_OK
    } else {
        AW_ERR_SELFTEST
    }
}

/// 词表中第 idx 个单词（静态数据，无需释放）。越界返回 NULL。
///
/// # Safety
/// `out_len` 必须有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_wordlist_word(idx: u16, out_len: *mut usize) -> *const u8 {
    if out_len.is_null() {
        return core::ptr::null();
    }
    let w = wordlist::word(idx).unwrap_or("");
    // SAFETY: 已检查非空。
    unsafe { *out_len = w.len() };
    if w.is_empty() {
        core::ptr::null()
    } else {
        w.as_ptr()
    }
}

/// 签名机会话：持有助记词、passphrase、解锁后的账户。释放时全部清零。
pub struct AwSession {
    mnemonic: Option<Mnemonic>,
    passphrase: Option<SecretVec>,
    signer: Option<SigningAccount>,
    evm: Option<EvmSigner>,
    /// Solana：m/44'/501' 节点（D34 三种方案的共同父节点）
    sol: Option<SolSigner>,
    /// 其他链的地址（只含公开信息）
    addresses: Option<addresses::Addresses>,
    secp: Option<Secp256k1<All>>,
    /// 上一次系统随机数的哈希（检测随机数源卡住，不保存原值）
    last_system: Option<[u8; 32]>,
    /// 解锁时要核对的预期指纹（passphrase 输错会静默得到另一个钱包）
    expected_fingerprint: Option<u32>,
}

#[no_mangle]
pub extern "C" fn aw_session_new() -> *mut AwSession {
    Box::into_raw(Box::new(AwSession {
        mnemonic: None,
        passphrase: None,
        signer: None,
        evm: None,
        sol: None,
        addresses: None,
        secp: None,
        last_system: None,
        expected_fingerprint: None,
    }))
}

/// # Safety
/// `s` 必须来自 `aw_session_new` 且只释放一次；可为 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_session_free(s: *mut AwSession) {
    if !s.is_null() {
        // SAFETY: 调用方保证来源与唯一释放；各字段的 Drop 负责清零。
        drop(unsafe { Box::from_raw(s) });
        scrub_stack();
    }
}

/// # Safety
/// `s` 为有效会话指针或 NULL。
unsafe fn session<'a>(s: *mut AwSession) -> Result<&'a mut AwSession, i32> {
    // SAFETY: 调用方保证。
    unsafe { s.as_mut() }.ok_or(AW_ERR_NULL_POINTER)
}

fn status(r: Result<(), i32>) -> i32 {
    match r {
        Ok(()) => AW_OK,
        Err(e) => e,
    }
}

fn entropy_code(e: entropy::EntropyError) -> i32 {
    match e {
        entropy::EntropyError::Health => AW_ERR_RNG_HEALTH,
        entropy::EntropyError::TooFewDice => AW_ERR_DICE_TOO_FEW,
        entropy::EntropyError::BadDice => AW_ERR_BAD_ARGUMENT,
        entropy::EntropyError::PoorDice => AW_ERR_DICE_POOR,
    }
}

fn entropy_bytes(word_count: u8) -> Result<usize, i32> {
    match word_count {
        12 => Ok(16),
        24 => Ok(32),
        _ => Err(AW_ERR_BAD_ARGUMENT),
    }
}

fn set_mnemonic(sess: &mut AwSession, ent: &SecretBytes<32>, bytes: usize) -> Result<(), i32> {
    let m = Mnemonic::from_entropy(ent.expose().get(..bytes).ok_or(AW_ERR_BAD_ARGUMENT)?)
        .map_err(|_| AW_ERR_BAD_MNEMONIC)?;
    sess.mnemonic = Some(m);
    sess.signer = None;
    sess.evm = None;
    sess.sol = None;
    sess.addresses = None;
    Ok(())
}

/// 生成新助记词（混合模式，见 `entropy.rs`）：系统随机数先过健康检查，再与可选的骰子点数哈希混合（威胁 T1）。
/// `dice` 只能含字符 '1'..'6'，可为空（此时完全依赖系统随机数）。
///
/// # Safety
/// `s` 为有效会话；`system32` 指向 32 字节；`dice` 指向 `dice_len` 字节。
#[no_mangle]
pub unsafe extern "C" fn aw_session_generate(
    s: *mut AwSession,
    system32: *const u8,
    dice: *const u8,
    dice_len: usize,
    word_count: u8,
) -> i32 {
    let r = (|| -> Result<(), i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        // SAFETY: 调用方保证。
        let sys: &[u8; 32] = unsafe { input(system32, 32, 32) }?
            .try_into()
            .map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        entropy::system_health(sys, sess.last_system.as_ref()).map_err(entropy_code)?;
        sess.last_system = Some(entropy::digest(sys));
        // SAFETY: 调用方保证。
        let dice = unsafe { input(dice, dice_len, MAX_DICE) }?;
        let bytes = entropy_bytes(word_count)?;
        let ent = entropy::mixed(sys, dice, bytes).map_err(entropy_code)?;
        set_mnemonic(sess, &ent, bytes)
    })();
    scrub_stack();
    status(r)
}

/// 纯骰子模式（可独立验证）：熵 = SHA-256(骰子点数字符串)，不使用任何设备随机数。
/// 12 词至少 50 次、24 词至少 100 次，否则返回 `AW_ERR_DICE_TOO_FEW`。
///
/// # Safety
/// `s` 为有效会话；`dice` 指向 `dice_len` 字节。
#[no_mangle]
pub unsafe extern "C" fn aw_session_generate_dice(
    s: *mut AwSession,
    dice: *const u8,
    dice_len: usize,
    word_count: u8,
) -> i32 {
    let r = (|| -> Result<(), i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        // SAFETY: 调用方保证。
        let dice = unsafe { input(dice, dice_len, MAX_DICE) }?;
        let bytes = entropy_bytes(word_count)?;
        let ent = entropy::dice_only(dice, bytes).map_err(entropy_code)?;
        set_mnemonic(sess, &ent, bytes)
    })();
    scrub_stack();
    status(r)
}

/// 设置助记词（单词序号），校验校验和。
///
/// # Safety
/// `s` 为有效会话；`idx` 指向 `n` 个 u16（2 字节对齐）。
#[no_mangle]
pub unsafe extern "C" fn aw_session_set_words(s: *mut AwSession, idx: *const u16, n: usize) -> i32 {
    let r = (|| -> Result<(), i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        if idx.is_null() || n > 24 || !idx.cast::<u8>().addr().is_multiple_of(2) {
            return Err(AW_ERR_BAD_ARGUMENT);
        }
        // SAFETY: 已检查非空、对齐、长度。
        let words = unsafe { core::slice::from_raw_parts(idx, n) };
        sess.mnemonic = Some(Mnemonic::from_indices(words).map_err(|_| AW_ERR_BAD_MNEMONIC)?);
        sess.signer = None;
        sess.evm = None;
        sess.sol = None;
        sess.addresses = None;
        Ok(())
    })();
    scrub_stack();
    status(r)
}

/// 当前助记词的单词数（0 表示尚未设置）。
///
/// # Safety
/// `s` 为有效会话或 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_session_word_count(s: *const AwSession) -> usize {
    // SAFETY: 调用方保证。
    unsafe { s.as_ref() }
        .and_then(|x| x.mnemonic.as_ref())
        .map_or(0, Mnemonic::word_count)
}

/// 第 i 个单词的序号（只用于备份时抄写；-1 表示越界）。
///
/// # Safety
/// `s` 为有效会话或 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_session_word_at(s: *const AwSession, i: usize) -> i32 {
    // SAFETY: 调用方保证。
    unsafe { s.as_ref() }
        .and_then(|x| x.mnemonic.as_ref())
        .and_then(|m| m.indices().get(i).copied())
        .map_or(-1, i32::from)
}

/// 设置 passphrase（UTF-8，调用方已做 NFKD）。
///
/// # Safety
/// `s` 为有效会话；`p` 指向 `len` 字节。
#[no_mangle]
pub unsafe extern "C" fn aw_session_set_passphrase(
    s: *mut AwSession,
    p: *const u8,
    len: usize,
) -> i32 {
    let r = (|| -> Result<(), i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        // SAFETY: 调用方保证。
        let bytes = unsafe { input(p, len, MAX_PASSPHRASE) }?;
        core::str::from_utf8(bytes).map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        sess.passphrase = Some(SecretVec::copy_from(bytes));
        sess.signer = None;
        sess.evm = None;
        sess.sol = None;
        sess.addresses = None;
        Ok(())
    })();
    scrub_stack();
    status(r)
}

/// 设置解锁时核对的预期指纹（大端 u32）。`has` 为 0 表示不核对。
///
/// # Safety
/// `s` 为有效会话。
#[no_mangle]
pub unsafe extern "C" fn aw_session_expect_fingerprint(s: *mut AwSession, has: u8, fp: u32) -> i32 {
    let r = (|| -> Result<(), i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        sess.expected_fingerprint = match has {
            0 => None,
            1 => Some(fp),
            _ => return Err(AW_ERR_BAD_ARGUMENT),
        };
        Ok(())
    })();
    status(r)
}

/// 解锁：由助记词 + passphrase 派生 BIP84 账户（种子用完即清零）。
///
/// # Safety
/// `s` 为有效会话；`rand32` 指向 32 字节系统随机数（用于 secp256k1 侧信道防护）。
#[no_mangle]
pub unsafe extern "C" fn aw_session_unlock(
    s: *mut AwSession,
    testnet: u8,
    rand32: *const u8,
) -> i32 {
    let r = (|| -> Result<(), i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        // SAFETY: 调用方保证。
        let rand: &[u8; 32] = unsafe { input(rand32, 32, 32) }?
            .try_into()
            .map_err(|_| AW_ERR_BAD_ARGUMENT)?;
        let network = match testnet {
            0 => Network::Bitcoin,
            1 => Network::Testnet,
            _ => return Err(AW_ERR_BAD_ARGUMENT),
        };
        // 审查 L4：无论成功与否，先丢弃上一次解锁留下的一切，失败时不会残留旧账户
        sess.signer = None;
        sess.evm = None;
        sess.sol = None;
        sess.addresses = None;
        sess.secp = None;
        let m = sess.mnemonic.as_ref().ok_or(AW_ERR_STATE)?;
        let pass = match &sess.passphrase {
            Some(p) => core::str::from_utf8(p.expose()).map_err(|_| AW_ERR_BAD_ARGUMENT)?,
            None => "",
        };
        let secp = aw_keys::secp_context(rand);
        let mut seed = SecretBytes::<64>::zeroed();
        m.to_seed_into(pass, &mut seed)
            .map_err(|_| AW_ERR_BAD_MNEMONIC)?;
        let master = aw_keys::master(&seed, network).map_err(|_| AW_ERR_DERIVATION)?;
        let fp = u32::from_be_bytes(aw_keys::master_fingerprint(&secp, &master).to_bytes());
        if sess.expected_fingerprint.is_some_and(|want| want != fp) {
            // 指纹不符：多半是 passphrase 输错。清除 passphrase、保留助记词，让用户重输；
            // 种子与根私钥在离开作用域时清零
            sess.passphrase = None;
            return Err(AW_ERR_FINGERPRINT_MISMATCH);
        }
        let addrs = addresses::Addresses::derive(&secp, &master, &seed, testnet == 1)
            .ok_or(AW_ERR_DERIVATION)?;
        let sol = SolSigner::from_seed(&seed).map_err(|_| AW_ERR_DERIVATION)?;
        drop(seed);
        let signer = SigningAccount::from_master(&secp, &master, network, 0)
            .map_err(|_| AW_ERR_DERIVATION)?;
        let evm = EvmSigner::from_master(&secp, &master).map_err(|_| AW_ERR_DERIVATION)?;
        sess.signer = Some(signer);
        sess.evm = Some(evm);
        sess.sol = Some(sol);
        sess.addresses = Some(addrs);
        // 随机数审查 M2：解锁后不再需要助记词与 passphrase，立即清除（各自的 Drop 负责清零）
        sess.mnemonic = None;
        sess.passphrase = None;
        sess.expected_fingerprint = None;
        sess.secp = Some(secp);
        Ok(())
    })();
    scrub_stack();
    status(r)
}

/// 根指纹（大端 u32），用于让用户核对"是不是同一个钱包"。未解锁返回 0。
///
/// # Safety
/// `s` 为有效会话或 NULL。
#[no_mangle]
pub unsafe extern "C" fn aw_session_fingerprint(s: *const AwSession) -> u32 {
    // SAFETY: 调用方保证。
    unsafe { s.as_ref() }
        .and_then(|x| x.signer.as_ref())
        .map_or(0, |sig| {
            u32::from_be_bytes(sig.account.master_fingerprint.to_bytes())
        })
}

/// 导出账户公钥二维码（crypto-hdkey）。`chain`：0 = BTC（BIP84），1 = EVM（m/44'/60'/0'）。
///
/// # Safety
/// `s` 为有效会话；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_session_export_account(
    s: *mut AwSession,
    chain: u32,
    out: *mut *mut AwUrEncoder,
) -> i32 {
    if out.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 已检查非空。
    unsafe { *out = core::ptr::null_mut() };
    let r = (|| -> Result<*mut AwUrEncoder, i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        let hd = match chain {
            CHAIN_BTC => account_to_hdkey(&sess.signer.as_ref().ok_or(AW_ERR_STATE)?.account),
            CHAIN_EVM => aw_chain_evm::account_ur::account_to_hdkey(
                &sess.evm.as_ref().ok_or(AW_ERR_STATE)?.account,
            ),
            _ => return Err(AW_ERR_BAD_ARGUMENT),
        };
        let ur = encode_hdkey(&hd, Style::Legacy).map_err(aw_ffi_common::ur_error_code)?;
        new_encoder(ur)
    })();
    match r {
        Ok(enc) => {
            // SAFETY: 已检查非空。
            unsafe { *out = enc };
            AW_OK
        }
        Err(e) => e,
    }
}

/// 第 `index` 个收款地址（通用 JSON：chain、path、address、note）。
/// `chain`：0 BTC、1 EVM、2 SOL、3 DOGE、4 TRON、5 NEAR；Solana / NEAR 的 index 须小于 20。
/// `scheme`：账户类型（D34）——SOL 为 0 Phantom/Solflare/Trezor `m/44'/501'/i'/0'`、1 Ledger Live `m/44'/501'/i'`、
/// 2 Ledger Live 主账户 `m/44'/501'`（index 必须为 0）；其他链必须为 0。
///
/// # Safety
/// `s` 为有效会话；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_session_address(
    s: *const AwSession,
    chain: u32,
    scheme: u32,
    index: u32,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(code) = unsafe { clear_out(out_ptr, out_len) } {
        return code;
    }
    let r = (|| -> Result<Vec<u8>, i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { s.as_ref() }.ok_or(AW_ERR_NULL_POINTER)?;
        let secp = sess.secp.as_ref().ok_or(AW_ERR_STATE)?;
        let btc = &sess.signer.as_ref().ok_or(AW_ERR_STATE)?.account;
        let evm = &sess.evm.as_ref().ok_or(AW_ERR_STATE)?.account;
        let addrs = sess.addresses.as_ref().ok_or(AW_ERR_STATE)?;
        let j = addrs
            .describe(secp, btc, evm, chain, scheme, index)
            .ok_or(AW_ERR_BAD_ARGUMENT)?;
        Ok(j.to_string_compact().into_bytes())
    })();
    match r {
        // SAFETY: 输出指针已检查。
        Ok(v) => unsafe { hand_out(v, out_ptr, out_len) },
        Err(e) => e,
    }
}

/// Solana 拒绝原因 → 错误码 AW_ERR_SOL_REJECT_BASE - 序号（Swift 侧有对应的中文说明）
pub(crate) fn sol_error_code(e: SolError) -> i32 {
    let n = match e {
        SolError::Parse => 1,
        SolError::LookupTable => 2,
        SolError::NotSigner => 3,
        SolError::OwnerChange => 4,
        SolError::SetAuthority => 5,
        SolError::Overflow => 6,
        SolError::Unsupported => 7,
        SolError::PathMismatch => 8,
        SolError::AddressMismatch => 9,
        SolError::Derivation => 10,
        SolError::BadSignature => 11,
        SolError::RequestMismatch => 12,
        SolError::AccountLock => 13,
    };
    aw_ffi_common::AW_ERR_SOL_REJECT_BASE - n
}

/// 把交易拒绝原因映射为错误码：AW_ERR_TX_REJECT_BASE - 序号（Swift 侧有对应的中文说明）。
fn btc_error_code(e: BtcError) -> i32 {
    let n = match e {
        BtcError::Parse => 1,
        BtcError::Empty => 2,
        BtcError::TooManyIo => 3,
        BtcError::AlreadyFinalized(_) => 4,
        BtcError::MissingPrevTx(_) => 5,
        BtcError::PrevTxMismatch(_) => 6,
        BtcError::WitnessUtxoMismatch(_) => 7,
        BtcError::UnsupportedInputScript(_) => 8,
        BtcError::ForeignInput(_) => 9,
        BtcError::SighashNotAll(_) => 10,
        BtcError::ChangeMismatch(_) => 11,
        BtcError::UnsupportedOutputScript(_) => 12,
        BtcError::NegativeFee => 13,
        BtcError::AmountOverflow => 14,
        BtcError::Derivation => 15,
        BtcError::SelfCheck => 16,
        BtcError::TxChanged => 17,
        BtcError::BadSignature(_) => 18,
        BtcError::InsufficientFunds => 19,
        BtcError::UtxoNotOurs(_) => 20,
    };
    AW_ERR_TX_REJECT_BASE - n
}

/// EVM 请求拒绝原因 → 错误码 AW_ERR_EVM_REJECT_BASE - 序号（Swift 侧有对应的中文说明）
fn evm_error_code(e: EvmError) -> i32 {
    let n = match e {
        EvmError::Parse => 1,
        EvmError::Unsupported => 2,
        EvmError::Eip7702 => 3,
        EvmError::NoReplayProtection => 4,
        EvmError::ChainMismatch => 5,
        EvmError::PathMismatch => 6,
        EvmError::AddressMismatch => 7,
        EvmError::DelegateCall => 8,
        EvmError::Overflow => 9,
        EvmError::Derivation => 10,
        EvmError::SelfCheck => 11,
        EvmError::BadSignature => 12,
        EvmError::RequestMismatch => 13,
        EvmError::BlindApproval => 14,
        EvmError::NeedsConfirmation => return AW_ERR_NEEDS_CONFIRMATION,
        EvmError::TooLong => 16,
        EvmError::SafeAdmin => 17,
    };
    AW_ERR_EVM_REJECT_BASE - n
}

/// 一个扫到的签名请求：PSBT（BTC）或 eth-sign-request（EVM）
enum Request {
    Btc(bitcoin::psbt::Psbt),
    Evm(aw_chain_evm::request::SignRequest),
    Sol(aw_chain_sol::request::SignRequest),
}

fn parse_request(ur: &Ur) -> Result<Request, i32> {
    if ur.ur_type == SIGN_REQUEST {
        return decode_request(ur)
            .map(Request::Evm)
            .map_err(aw_ffi_common::ur_error_code);
    }
    if ur.ur_type == aw_chain_sol::request::SIGN_REQUEST {
        return aw_chain_sol::request::decode_request(ur)
            .map(Request::Sol)
            .map_err(aw_ffi_common::ur_error_code);
    }
    match decode_psbt(ur) {
        Ok(bytes) if bytes.len() <= MAX_PSBT => aw_chain_btc::review::parse(&bytes)
            .map(Request::Btc)
            .map_err(btc_error_code),
        Ok(_) => Err(AW_ERR_BAD_ARGUMENT),
        Err(aw_ur::UrError::UnexpectedType) => Err(AW_ERR_UNSUPPORTED_REQUEST),
        Err(e) => Err(aw_ffi_common::ur_error_code(e)),
    }
}

fn review_request(sess: &AwSession, req: &Request) -> Result<Display, i32> {
    let secp = sess.secp.as_ref().ok_or(AW_ERR_STATE)?;
    match req {
        Request::Btc(p) => {
            let signer = sess.signer.as_ref().ok_or(AW_ERR_STATE)?;
            review(secp, &signer.account, p)
                .map(|r| r.to_display())
                .map_err(btc_error_code)
        }
        Request::Evm(r) => {
            let evm = sess.evm.as_ref().ok_or(AW_ERR_STATE)?;
            aw_chain_evm::review::review(secp, &evm.account, r)
                .map(|x| x.display)
                .map_err(evm_error_code)
        }
        Request::Sol(r) => {
            let sol = sess.sol.as_ref().ok_or(AW_ERR_STATE)?;
            sol.review(r).map(|x| x.display).map_err(sol_error_code)
        }
    }
}

/// 审查解码器中已收齐的签名请求，输出通用显示模型 JSON（UTF-8，见 aw-common::display）。
///
/// # Safety
/// `s` 为有效会话；`d` 为有效解码器；输出指针有效。
#[no_mangle]
pub unsafe extern "C" fn aw_session_review_ur(
    s: *mut AwSession,
    d: *const AwUrDecoder,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: 调用方保证。
    if let Err(code) = unsafe { clear_out(out_ptr, out_len) } {
        return code;
    }
    let r = (|| -> Result<Vec<u8>, i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        // SAFETY: 调用方保证。
        let req = parse_request(unsafe { decoded_ur(d) }?)?;
        Ok(review_request(sess, &req)?
            .to_json()
            .to_string_compact()
            .into_bytes())
    })();
    scrub_stack();
    match r {
        // SAFETY: 输出指针已检查。
        Ok(v) => unsafe { hand_out(v, out_ptr, out_len) },
        Err(e) => e,
    }
}

/// 审查并签名解码器中的请求；成功时返回结果（已签 PSBT 或 eth-signature）的动画二维码编码器。
/// 审查结果含高风险警告时，必须传入 `confirm_danger = 1`（表示用户已在界面上确认），
/// 否则返回 `AW_ERR_NEEDS_CONFIRMATION`——确认要求在 Rust 中强制，不依赖界面（EVM 审查 LOW-5）。
///
/// # Safety
/// `s` 为有效会话；`d` 为有效解码器；`out` 有效可写。
#[no_mangle]
pub unsafe extern "C" fn aw_session_sign_ur(
    s: *mut AwSession,
    d: *const AwUrDecoder,
    confirm_danger: u8,
    out: *mut *mut AwUrEncoder,
) -> i32 {
    if out.is_null() {
        return AW_ERR_NULL_POINTER;
    }
    // SAFETY: 已检查非空。
    unsafe { *out = core::ptr::null_mut() };
    let r = (|| -> Result<*mut AwUrEncoder, i32> {
        // SAFETY: 调用方保证。
        let sess = unsafe { session(s) }?;
        let secp = sess.secp.as_ref().ok_or(AW_ERR_STATE)?;
        // SAFETY: 调用方保证。
        let req = parse_request(unsafe { decoded_ur(d) }?)?;
        if review_request(sess, &req)?.has_danger() && confirm_danger != 1 {
            return Err(AW_ERR_NEEDS_CONFIRMATION);
        }
        let ur = match req {
            Request::Btc(mut p) => {
                let signer = sess.signer.as_ref().ok_or(AW_ERR_STATE)?;
                sign_psbt(secp, signer, &mut p).map_err(btc_error_code)?;
                encode_psbt(&p.serialize(), Style::Legacy)
            }
            Request::Evm(req) => {
                let evm = sess.evm.as_ref().ok_or(AW_ERR_STATE)?;
                let (_, sig) = evm_sign(secp, evm, &req).map_err(evm_error_code)?;
                encode_signature(&sig)
            }
            Request::Sol(req) => {
                let sol = sess.sol.as_ref().ok_or(AW_ERR_STATE)?;
                let (_, sig) = sol.sign(&req).map_err(sol_error_code)?;
                aw_chain_sol::request::encode_signature(&sig)
            }
        }
        .map_err(aw_ffi_common::ur_error_code)?;
        new_encoder(ur)
    })();
    scrub_stack();
    match r {
        Ok(enc) => {
            // SAFETY: 已检查非空。
            unsafe { *out = enc };
            AW_OK
        }
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests;
