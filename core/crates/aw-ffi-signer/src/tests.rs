//! 通过 C 接口本身测试签名机的完整流程。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::*;
use aw_chain_btc::account_ur::account_from_hdkey;
use aw_chain_btc::watch::{build_payment, Utxo};
use aw_ffi_common::AwUrDecoder;
use bitcoin::{absolute, transaction, Address, Amount, OutPoint, Transaction, TxIn, TxOut};

const ABOUT: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];

fn take(ptr: *mut u8, len: usize) -> Vec<u8> {
    let v = unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe { aw_buf_free(ptr, len) };
    v
}

fn unlocked() -> *mut AwSession {
    let s = aw_session_new();
    assert_eq!(
        unsafe { aw_session_set_words(s, ABOUT.as_ptr(), 12) },
        AW_OK
    );
    assert_eq!(
        unsafe { aw_session_unlock(s, 1, [7u8; 32].as_ptr()) },
        AW_OK
    );
    s
}

/// 把编码器的帧逐个喂给解码器，直到完成
fn pump(enc: *mut AwUrEncoder) -> *mut AwUrDecoder {
    let d = aw_ur_decoder_new();
    for _ in 0..10_000 {
        let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
        assert_eq!(unsafe { aw_ur_encoder_next(enc, &mut p, &mut l) }, AW_OK);
        let frame = take(p, l);
        let rc = unsafe { aw_ur_decoder_receive(d, frame.as_ptr(), frame.len()) };
        assert!(rc >= 0, "{rc}");
        if rc == 1 {
            unsafe { aw_ur_encoder_free(enc) };
            return d;
        }
    }
    panic!("未完成");
}

#[test]
fn selftest_and_abi() {
    assert_eq!(aw_selftest(), AW_OK);
    assert_eq!(aw_abi_version(), 3);
}

#[test]
fn wordlist_access() {
    let mut l = 0;
    let p = unsafe { aw_wordlist_word(2047, &mut l) };
    assert_eq!(unsafe { core::slice::from_raw_parts(p, l) }, b"zoo");
    assert!(unsafe { aw_wordlist_word(2048, &mut l) }.is_null());
}

#[test]
fn rejects_bad_mnemonic_and_state() {
    let s = aw_session_new();
    assert_eq!(
        unsafe { aw_session_set_words(s, [0u16; 12].as_ptr(), 12) },
        AW_ERR_BAD_MNEMONIC
    );
    assert_eq!(
        unsafe { aw_session_unlock(s, 1, [7u8; 32].as_ptr()) },
        AW_ERR_STATE
    );
    let mut e = core::ptr::null_mut();
    assert_eq!(
        unsafe { aw_session_export_account(s, 0, &mut e) },
        AW_ERR_STATE
    );
    assert!(e.is_null());
    unsafe { aw_session_free(s) };
    unsafe { aw_session_free(core::ptr::null_mut()) };
}

/// 看起来随机的 32 字节（测试用；真实环境来自 SecRandomCopyBytes）
fn sys_random(tag: u8) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(&[tag]).to_byte_array()
}

#[test]
fn generate_with_dice_is_deterministic_given_inputs() {
    let sys = sys_random(1);
    let dice = b"1234561234561234561234561234561234561234561234561234";
    let a = aw_session_new();
    let b = aw_session_new();
    assert_eq!(
        unsafe { aw_session_generate(a, sys.as_ptr(), dice.as_ptr(), dice.len(), 24) },
        AW_OK
    );
    assert_eq!(
        unsafe { aw_session_generate(b, sys.as_ptr(), dice.as_ptr(), dice.len(), 24) },
        AW_OK
    );
    assert_eq!(unsafe { aw_session_word_count(a) }, 24);
    for i in 0..24 {
        assert_eq!(unsafe { aw_session_word_at(a, i) }, unsafe {
            aw_session_word_at(b, i)
        });
    }
    // 骰子不同 → 助记词不同
    let c = aw_session_new();
    assert_eq!(
        unsafe { aw_session_generate(c, sys.as_ptr(), b"1".as_ptr(), 1, 24) },
        AW_OK
    );
    assert!((0..24).any(|i| unsafe { aw_session_word_at(a, i) != aw_session_word_at(c, i) }));
    // 同一会话里系统随机数重复（随机数源卡住）→ 拒绝
    assert_eq!(
        unsafe { aw_session_generate(c, sys.as_ptr(), b"2".as_ptr(), 1, 24) },
        AW_ERR_RNG_HEALTH
    );
    // 坏掉的系统随机数：全零、全相同
    for bad in [[0u8; 32], [0x42u8; 32]] {
        assert_eq!(
            unsafe { aw_session_generate(c, bad.as_ptr(), core::ptr::null(), 0, 12) },
            AW_ERR_RNG_HEALTH
        );
    }
    // 非法骰子字符、非法词数
    let sys2 = sys_random(2);
    assert_eq!(
        unsafe { aw_session_generate(c, sys2.as_ptr(), b"7".as_ptr(), 1, 24) },
        AW_ERR_BAD_ARGUMENT
    );
    let sys3 = sys_random(3);
    assert_eq!(
        unsafe { aw_session_generate(c, sys3.as_ptr(), core::ptr::null(), 0, 13) },
        AW_ERR_BAD_ARGUMENT
    );
    for s in [a, b, c] {
        unsafe { aw_session_free(s) };
    }
}

#[test]
fn dice_only_generation_is_verifiable() {
    let s = aw_session_new();
    let rolls = crate::entropy::tests::DICE_100;
    assert_eq!(
        unsafe { aw_session_generate_dice(s, rolls.as_ptr(), 99, 24) },
        AW_ERR_DICE_TOO_FEW
    );
    let fake = [b'1'; 100];
    assert_eq!(
        unsafe { aw_session_generate_dice(s, fake.as_ptr(), 100, 24) },
        AW_ERR_DICE_POOR
    );
    assert_eq!(
        unsafe { aw_session_generate_dice(s, rolls.as_ptr(), 100, 24) },
        AW_OK
    );
    // 与 tools/testvectors/verify_dice.py（Python hashlib）算出的助记词一致：piano nasty …
    let w = |i| {
        aw_bip39::wordlist::word(u16::try_from(unsafe { aw_session_word_at(s, i) }).unwrap())
            .unwrap()
    };
    assert_eq!((w(0), w(1)), ("piano", "nasty"));
    let rolls50 = crate::entropy::tests::DICE_50;
    assert_eq!(
        unsafe { aw_session_generate_dice(s, rolls50.as_ptr(), 50, 12) },
        AW_OK
    );
    assert_eq!((w(0), w(1)), ("trend", "humble"));
    unsafe { aw_session_free(s) };
}

#[test]
fn export_account_review_and_sign_through_c_abi() {
    let s = unlocked();
    assert_ne!(unsafe { aw_session_fingerprint(s) }, 0);

    // 导出账户 → 动画二维码 → 观察机解码
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_session_export_account(s, 0, &mut enc) }, AW_OK);
    let d = pump(enc);
    let hd = match unsafe { &*d }.0.result() {
        Some(Ok(ur)) => aw_ur::registry::decode_hdkey(ur).unwrap(),
        other => panic!("{other:?}"),
    };
    unsafe { aw_ur_decoder_free(d) };
    let watch = account_from_hdkey(&hd).unwrap();
    assert_eq!(
        u32::from_be_bytes(watch.master_fingerprint.to_bytes()),
        unsafe { aw_session_fingerprint(s) }
    );

    // 观察机构造 PSBT
    let secp = Secp256k1::new();
    let funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(80_000),
            script_pubkey: watch.script_for(&secp, false, 0).unwrap(),
        }],
    };
    let to: Address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .unwrap()
        .require_network(Network::Testnet)
        .unwrap();
    let utxos = [Utxo {
        prev_tx: funding,
        vout: 0,
        change: false,
        index: 0,
    }];
    let (psbt, _) = build_payment(&secp, &watch, &utxos, &to, 50_000, 3, 0).unwrap();
    let req = scanned(encode_psbt(&psbt.serialize(), Style::Legacy).unwrap());

    // 审查：通用显示模型 JSON
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_session_review_ur(s, req, &mut p, &mut l) },
        AW_OK
    );
    let json = String::from_utf8(take(p, l)).unwrap();
    assert!(json.contains("\"title\":\"发送 BTC\""), "{json}");
    assert!(json.contains("0.0005 tBTC"), "{json}");
    assert!(json.contains("找零地址"), "{json}");

    // 签名 → 动画二维码 → 取回 PSBT
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_session_sign_ur(s, req, 0, &mut enc) }, AW_OK);
    unsafe { aw_ur_decoder_free(req) };
    let d = pump(enc);
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(unsafe { aw_ur_decoder_take_psbt(d, &mut p, &mut l) }, AW_OK);
    let signed = bitcoin::psbt::Psbt::deserialize(&take(p, l)).unwrap();
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
    unsafe { aw_ur_decoder_free(d) };

    // 篡改的交易被拒，错误码可映射
    let mut bad = psbt.clone();
    bad.inputs[0].non_witness_utxo = None;
    let req = scanned(encode_psbt(&bad.serialize(), Style::Legacy).unwrap());
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_session_review_ur(s, req, &mut p, &mut l) },
        AW_ERR_TX_REJECT_BASE - 5
    );
    assert!(p.is_null());
    unsafe { aw_ur_decoder_free(req) };
    unsafe { aw_session_free(s) };
}

/// 观察机生成的请求经动画二维码到达签名机后的解码器
fn scanned(ur: aw_ur::ur::Ur) -> *mut AwUrDecoder {
    pump(aw_ffi_common::new_encoder(ur).unwrap())
}

#[test]
fn evm_export_review_and_sign_through_c_abi() {
    use aw_chain_evm::request::{decode_signature, encode_request, DataType};
    use aw_chain_evm::uint::U256;
    use aw_chain_evm::watch::{build_eip1559, build_request, finalize, Eip1559};
    let s = unlocked();
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_session_export_account(s, 1, &mut enc) }, AW_OK);
    let d = pump(enc);
    let hd = aw_ur::registry::decode_hdkey(unsafe { decoded_ur(d) }.unwrap()).unwrap();
    unsafe { aw_ur_decoder_free(d) };
    let watch = aw_chain_evm::account_ur::account_from_hdkey(&hd).unwrap();
    let secp = Secp256k1::new();
    assert_eq!(
        aw_chain_evm::checksum_address(&watch.address(&secp, 0).unwrap()),
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
    let tx = build_eip1559(&Eip1559 {
        chain_id: 1,
        nonce: 0,
        max_priority_fee: U256::from_u64(1_000_000_000),
        max_fee: U256::from_u64(20_000_000_000),
        gas_limit: 21_000,
        to: [0x35; 20],
        value: U256::from_u64(1_000_000_000_000_000_000),
        data: vec![],
    })
    .unwrap();
    let req = build_request(&secp, &watch, 0, tx, DataType::TypedTx, Some(1), [3; 16]).unwrap();
    let dec = scanned(encode_request(&req).unwrap());
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_session_review_ur(s, dec, &mut p, &mut l) },
        AW_OK
    );
    let json = String::from_utf8(take(p, l)).unwrap();
    assert!(
        json.contains("\"title\":\"发送 ETH\"") && json.contains("1 ETH"),
        "{json}"
    );
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_session_sign_ur(s, dec, 0, &mut enc) }, AW_OK);
    unsafe { aw_ur_decoder_free(dec) };
    let back = pump(enc);
    let sig = decode_signature(unsafe { decoded_ur(back) }.unwrap()).unwrap();
    unsafe { aw_ur_decoder_free(back) };
    assert!(finalize(&secp, &watch, &req, &sig).is_ok());

    // 危险请求：EIP-7702 → 拒签，错误码可映射
    let mut bad = req;
    bad.sign_data = vec![0x04, 0xc0];
    let dec = scanned(encode_request(&bad).unwrap());
    let mut enc = core::ptr::null_mut();
    assert_eq!(
        unsafe { aw_session_sign_ur(s, dec, 1, &mut enc) },
        AW_ERR_EVM_REJECT_BASE - 3
    );
    assert!(enc.is_null());
    unsafe { aw_ur_decoder_free(dec) };
    // 含高风险警告（未知合约调用）：不确认就不签，确认后才签
    let mut risky = bad.clone();
    risky.sign_data = build_eip1559(&Eip1559 {
        chain_id: 1,
        nonce: 1,
        max_priority_fee: U256::from_u64(1_000_000_000),
        max_fee: U256::from_u64(20_000_000_000),
        gas_limit: 90_000,
        to: [0x35; 20],
        value: U256::ZERO,
        data: vec![0xde, 0xad, 0xbe, 0xef],
    })
    .unwrap();
    let dec = scanned(encode_request(&risky).unwrap());
    let mut enc = core::ptr::null_mut();
    assert_eq!(
        unsafe { aw_session_sign_ur(s, dec, 0, &mut enc) },
        AW_ERR_NEEDS_CONFIRMATION
    );
    assert!(enc.is_null());
    assert_eq!(
        unsafe { aw_session_sign_ur(s, dec, 2, &mut enc) },
        AW_ERR_NEEDS_CONFIRMATION
    );
    assert_eq!(unsafe { aw_session_sign_ur(s, dec, 1, &mut enc) }, AW_OK);
    unsafe { aw_ur_encoder_free(enc) };
    unsafe { aw_ur_decoder_free(dec) };
    // 不是签名请求的二维码（账户公钥）
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_session_export_account(s, 0, &mut enc) }, AW_OK);
    let other = pump(enc);
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_session_review_ur(s, other, &mut p, &mut l) },
        AW_ERR_UNSUPPORTED_REQUEST
    );
    unsafe { aw_ur_decoder_free(other) };
    unsafe { aw_session_free(s) };
}

#[test]
fn decoder_reports_other_set_and_garbage() {
    let d = aw_ur_decoder_new();
    let garbage = b"hello";
    assert!(unsafe { aw_ur_decoder_receive(d, garbage.as_ptr(), garbage.len()) } < 0);
    let mut p = core::ptr::null_mut();
    let mut l = 7usize;
    assert_eq!(
        unsafe { aw_ur_decoder_take_psbt(d, &mut p, &mut l) },
        AW_ERR_STATE
    );
    assert_eq!(l, 0);
    unsafe { aw_ur_decoder_free(d) };
}

/// 随机数审查 M2：解锁后助记词与 passphrase 立即从会话中清除
#[test]
fn mnemonic_and_passphrase_cleared_after_unlock() {
    let s = unlocked();
    assert_eq!(unsafe { aw_session_word_count(s) }, 0);
    assert_eq!(unsafe { aw_session_word_at(s, 0) }, -1);
    let sess = unsafe { &*s };
    assert!(sess.mnemonic.is_none() && sess.passphrase.is_none());
    // 签名用的账户仍在
    assert_ne!(unsafe { aw_session_fingerprint(s) }, 0);
    unsafe { aw_session_free(s) };
}

#[test]
fn addresses_for_all_chains() {
    let s = unlocked(); // 测试网
    let get = |chain: u32, index: u32| -> Result<String, i32> {
        let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
        let rc = unsafe { aw_session_address(s, chain, index, &mut p, &mut l) };
        if rc != AW_OK {
            return Err(rc);
        }
        Ok(String::from_utf8(take(p, l)).unwrap())
    };
    // 与 tools/testvectors/chain_addresses.py（独立 Python 实现）一致
    assert!(get(0, 0)
        .unwrap()
        .contains("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"));
    assert!(get(1, 0)
        .unwrap()
        .contains("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"));
    assert!(get(2, 1)
        .unwrap()
        .contains("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"));
    assert!(get(3, 0)
        .unwrap()
        .contains("nZVmfmUtKPmskB9Ds4P9GUJy9eYFqPKHqH"));
    assert!(get(4, 0)
        .unwrap()
        .contains("TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"));
    let near = get(5, 0).unwrap();
    assert!(
        near.contains("5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412"),
        "{near}"
    );
    assert!(near.contains("ed25519:6j4b6zUaty6fD1awqcGCCU9JYGCWYUgdJhQrzfZhqE25"));
    // 越界与未知链
    assert_eq!(get(2, 20), Err(AW_ERR_BAD_ARGUMENT));
    assert_eq!(get(9, 0), Err(AW_ERR_BAD_ARGUMENT));
    assert_eq!(get(1, 0x8000_0000), Err(AW_ERR_BAD_ARGUMENT));
    unsafe { aw_session_free(s) };
    // 未解锁
    let fresh = aw_session_new();
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_session_address(fresh, 0, 0, &mut p, &mut l) },
        AW_ERR_STATE
    );
    unsafe { aw_session_free(fresh) };
}
