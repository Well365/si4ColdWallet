//! 通过 C 接口测试观察机流程（签名一侧用 aw-chain-btc 的 signing 功能模拟签名机）。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::*;
use aw_chain_btc::sign::{sign_psbt, SigningAccount};
use bitcoin::secp256k1::All;
use bitcoin::{absolute, transaction, Amount, Network, OutPoint, TxIn, TxOut};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn take(ptr: *mut u8, len: usize) -> Vec<u8> {
    let v = unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe { aw_buf_free(ptr, len) };
    v
}

fn signer() -> (Secp256k1<All>, SigningAccount) {
    let secp = Secp256k1::new();
    let seed = aw_bip39::Mnemonic::parse(MNEMONIC)
        .unwrap()
        .to_seed("")
        .unwrap();
    let master = aw_keys::master(&seed, Network::Testnet).unwrap();
    let s = SigningAccount::from_master(&secp, &master, Network::Testnet, 0).unwrap();
    (secp, s)
}

fn watch_from(s: &SigningAccount) -> *mut AwWatch {
    let ur =
        aw_ur::ur::encode(&encode_hdkey(&account_to_hdkey(&s.account), Style::Legacy).unwrap());
    let mut w = core::ptr::null_mut();
    assert_eq!(
        unsafe { aw_watch_from_ur(ur.as_ptr(), ur.len(), &mut w) },
        AW_OK
    );
    w
}

fn utxo_blob(txs: &[(&Transaction, u32, bool, u32)]) -> Vec<u8> {
    let mut b = (txs.len() as u32).to_be_bytes().to_vec();
    for (tx, vout, change, index) in txs {
        let raw = serialize(*tx);
        b.push(u8::from(*change));
        b.extend_from_slice(&index.to_be_bytes());
        b.extend_from_slice(&vout.to_be_bytes());
        b.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        b.extend_from_slice(&raw);
    }
    b
}

#[test]
fn import_address_build_finalize() {
    let (secp, s) = signer();
    let w = watch_from(&s);
    assert_eq!(unsafe { aw_watch_is_testnet(w) }, 1);
    assert_eq!(
        unsafe { aw_watch_fingerprint(w) },
        u32::from_be_bytes(s.account.master_fingerprint.to_bytes())
    );

    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(unsafe { aw_watch_address(w, 0, 0, &mut p, &mut l) }, AW_OK);
    let addr = String::from_utf8(take(p, l)).unwrap();
    assert_eq!(
        addr,
        s.account.address(&secp, false, 0).unwrap().to_string()
    );
    assert!(addr.starts_with("tb1q"));

    // 资金交易
    let funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(70_000),
            script_pubkey: s.account.script_for(&secp, false, 0).unwrap(),
        }],
    };
    let blob = utxo_blob(&[(&funding, 0, false, 0)]);
    let to = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let mut pending = core::ptr::null_mut();
    let (mut jp, mut jl) = (core::ptr::null_mut(), 0usize);
    let rc = unsafe {
        aw_watch_build_payment(
            w,
            blob.as_ptr(),
            blob.len(),
            to.as_ptr(),
            to.len(),
            40_000,
            4,
            0,
            &mut pending,
            &mut jp,
            &mut jl,
        )
    };
    assert_eq!(rc, AW_OK);
    let summary = String::from_utf8(take(jp, jl)).unwrap();
    assert!(summary.contains("\"amount_sat\":40000"), "{summary}");

    // 观察机 → 二维码 → 签名机（模拟）→ 观察机
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_pending_encoder(pending, &mut enc) }, AW_OK);
    let d = aw_ur_decoder_new();
    loop {
        let (mut fp, mut fl) = (core::ptr::null_mut(), 0usize);
        assert_eq!(unsafe { aw_ur_encoder_next(enc, &mut fp, &mut fl) }, AW_OK);
        let f = take(fp, fl);
        if unsafe { aw_ur_decoder_receive(d, f.as_ptr(), f.len()) } == 1 {
            break;
        }
    }
    let (mut pp, mut pl) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_ur_decoder_take_psbt(d, &mut pp, &mut pl) },
        AW_OK
    );
    let mut psbt = Psbt::deserialize(&take(pp, pl)).unwrap();
    sign_psbt(&secp, &s, &mut psbt).unwrap();
    let signed = psbt.serialize();

    let (mut hp, mut hl) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_pending_finalize(w, pending, signed.as_ptr(), signed.len(), &mut hp, &mut hl) },
        AW_OK
    );
    let hex = String::from_utf8(take(hp, hl)).unwrap();
    let tx: Transaction = deserialize(&aw_common::hex::decode(&hex).unwrap()).unwrap();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.input[0].witness.len(), 2);

    // 篡改后的签名结果被拒绝
    let mut tampered = psbt.clone();
    tampered.unsigned_tx.output[0].value = Amount::from_sat(1);
    let t = tampered.serialize();
    assert_eq!(
        unsafe { aw_pending_finalize(w, pending, t.as_ptr(), t.len(), &mut hp, &mut hl) },
        AW_ERR_TX_REJECT_BASE - 17
    );

    unsafe {
        aw_ur_encoder_free(enc);
        aw_ur_decoder_free(d);
        aw_pending_free(pending);
        aw_watch_free(w);
    }
}

#[test]
fn rejects_bad_inputs() {
    let (_, s) = signer();
    let w = watch_from(&s);
    let mut pending = core::ptr::null_mut();
    let (mut jp, mut jl) = (core::ptr::null_mut(), 0usize);
    let to = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"; // 主网地址，网络不符
    let blob = [0u8, 0, 0, 1, 9];
    let rc = unsafe {
        aw_watch_build_payment(
            w,
            blob.as_ptr(),
            blob.len(),
            to.as_ptr(),
            to.len(),
            1000,
            1,
            0,
            &mut pending,
            &mut jp,
            &mut jl,
        )
    };
    assert_eq!(rc, AW_ERR_BAD_ARGUMENT);
    assert!(pending.is_null());
    let mut w2 = core::ptr::null_mut();
    let bad = "ur:crypto-hdkey/aeae";
    assert!(unsafe { aw_watch_from_ur(bad.as_ptr(), bad.len(), &mut w2) } < 0);
    assert!(w2.is_null());
    unsafe { aw_watch_free(w) };
}

/// 把编码器的帧逐个喂给新解码器，直到完成
fn pump(enc: *mut AwUrEncoder) -> *mut AwUrDecoder {
    let d = aw_ur_decoder_new();
    for _ in 0..10_000 {
        let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
        assert_eq!(unsafe { aw_ur_encoder_next(enc, &mut p, &mut l) }, AW_OK);
        let frame = take(p, l);
        if unsafe { aw_ur_decoder_receive(d, frame.as_ptr(), frame.len()) } == 1 {
            unsafe { aw_ur_encoder_free(enc) };
            return d;
        }
    }
    panic!("未完成");
}

#[test]
fn evm_import_build_and_finalize() {
    use aw_chain_evm::request::{decode_request, encode_signature};
    use evm::*;
    let secp = Secp256k1::new();
    let seed = aw_bip39::Mnemonic::parse(MNEMONIC)
        .unwrap()
        .to_seed("")
        .unwrap();
    let master = aw_keys::master(&seed, Network::Testnet).unwrap();
    let signer = aw_chain_evm::sign::EvmSigner::from_master(&secp, &master).unwrap();
    let ur = aw_ur::ur::encode(
        &encode_hdkey(
            &aw_chain_evm::account_ur::account_to_hdkey(&signer.account),
            Style::Legacy,
        )
        .unwrap(),
    );
    let mut a = core::ptr::null_mut();
    assert_eq!(
        unsafe { aw_evm_from_ur(ur.as_ptr(), ur.len(), &mut a) },
        AW_OK
    );
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(unsafe { aw_evm_address(a, 0, &mut p, &mut l) }, AW_OK);
    assert_eq!(take(p, l), b"0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    // BTC 账户不能当 EVM 账户导入
    let btc = aw_ur::ur::encode(
        &encode_hdkey(&account_to_hdkey(&signer_btc().account), Style::Legacy).unwrap(),
    );
    let mut bad = core::ptr::null_mut();
    assert!(unsafe { aw_evm_from_ur(btc.as_ptr(), btc.len(), &mut bad) } < 0);
    assert!(bad.is_null());

    let mut value = [0u8; 32];
    assert_eq!(
        unsafe { aw_evm_parse_amount(b"0.01".as_ptr(), 4, 18, value.as_mut_ptr()) },
        AW_OK
    );
    assert_eq!(
        unsafe { aw_evm_parse_amount(b"0.0.1".as_ptr(), 5, 18, value.as_mut_ptr()) },
        AW_ERR_BAD_ARGUMENT
    );
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_evm_format_quantity(b"0x2386f26fc10000".as_ptr(), 16, 18, &mut p, &mut l) },
        AW_OK
    );
    assert_eq!(take(p, l), b"0.01");
    let mut prio = [0u8; 32];
    let mut max = [0u8; 32];
    prio[31] = 1;
    max[28..].copy_from_slice(&30_000_000_000u64.to_be_bytes()[4..]);
    let to = b"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    let (mut pending, mut j, mut jl) = (core::ptr::null_mut(), core::ptr::null_mut(), 0usize);
    let rc = unsafe {
        aw_evm_build_transfer(
            a,
            0,
            11_155_111,
            4,
            prio.as_ptr(),
            max.as_ptr(),
            21_000,
            to.as_ptr(),
            to.len(),
            value.as_ptr(),
            core::ptr::null(),
            0,
            [9u8; 16].as_ptr(),
            &mut pending,
            &mut j,
            &mut jl,
        )
    };
    assert_eq!(rc, AW_OK);
    let json = String::from_utf8(take(j, jl)).unwrap();
    assert!(json.contains("0.01 SepoliaETH"), "{json}");

    // 签名机一侧（用签名代码模拟）
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_evm_pending_encoder(pending, &mut enc) }, AW_OK);
    let d = pump(enc);
    let req = decode_request(unsafe { aw_ffi_common::decoded_ur(d) }.unwrap()).unwrap();
    unsafe { aw_ur_decoder_free(d) };
    let (_, sig) = aw_chain_evm::sign::sign(&secp, &signer, &req).unwrap();
    let back = pump(aw_ffi_common::new_encoder(encode_signature(&sig).unwrap()).unwrap());
    let (mut h, mut hl) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_evm_pending_finalize(a, pending, back, &mut h, &mut hl) },
        AW_OK
    );
    let hex = String::from_utf8(take(h, hl)).unwrap();
    assert!(hex.starts_with("0x02f8"), "{hex}");
    unsafe { aw_ur_decoder_free(back) };

    // 错误的地址文本、未知合约
    let (mut p2, mut j2, mut jl2) = (core::ptr::null_mut(), core::ptr::null_mut(), 0usize);
    let bad_to = b"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"; // 校验和错误
    let rc = unsafe {
        aw_evm_build_transfer(
            a,
            0,
            1,
            0,
            prio.as_ptr(),
            max.as_ptr(),
            21_000,
            bad_to.as_ptr(),
            bad_to.len(),
            value.as_ptr(),
            core::ptr::null(),
            0,
            [9u8; 16].as_ptr(),
            &mut p2,
            &mut j2,
            &mut jl2,
        )
    };
    assert_eq!(rc, AW_ERR_BAD_ARGUMENT);
    assert!(p2.is_null() && j2.is_null());
    unsafe { aw_evm_pending_free(pending) };
    unsafe { aw_evm_free(a) };
}

fn signer_btc() -> SigningAccount {
    signer().1
}

#[test]
fn evm_message_requests() {
    use aw_chain_evm::request::{decode_request, encode_signature};
    use aw_ffi_common::AW_ERR_EVM_REJECT_BASE;
    use evm::*;
    use evm_message::aw_evm_build_message;
    let secp = Secp256k1::new();
    let seed = aw_bip39::Mnemonic::parse(MNEMONIC)
        .unwrap()
        .to_seed("")
        .unwrap();
    let master = aw_keys::master(&seed, Network::Testnet).unwrap();
    let signer = aw_chain_evm::sign::EvmSigner::from_master(&secp, &master).unwrap();
    let ur = aw_ur::ur::encode(
        &encode_hdkey(
            &aw_chain_evm::account_ur::account_to_hdkey(&signer.account),
            Style::Legacy,
        )
        .unwrap(),
    );
    let mut a = core::ptr::null_mut();
    assert_eq!(
        unsafe { aw_evm_from_ur(ur.as_ptr(), ur.len(), &mut a) },
        AW_OK
    );
    let build = |kind: u8, text: &[u8], chain: u64| {
        let (mut p, mut j, mut jl) = (core::ptr::null_mut(), core::ptr::null_mut(), 0usize);
        let rc = unsafe {
            aw_evm_build_message(
                a,
                0,
                kind,
                text.as_ptr(),
                text.len(),
                chain,
                [4u8; 16].as_ptr(),
                &mut p,
                &mut j,
                &mut jl,
            )
        };
        let json = if rc == AW_OK {
            String::from_utf8(take(j, jl)).unwrap()
        } else {
            assert!(p.is_null() && j.is_null());
            String::new()
        };
        (rc, p, json)
    };
    let typed = br#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],"Hello":[{"name":"text","type":"string"}]},"primaryType":"Hello","domain":{"name":"demo","chainId":11155111},"message":{"text":"hi"}}"#;
    // 观察机先用同一份审查代码检查：显示模型与签名机相同
    let (rc, pending, json) = build(1, typed, 11_155_111);
    assert_eq!(rc, AW_OK);
    assert!(
        json.contains("结构化签名（Hello）") && json.contains("\"danger\""),
        "{json}"
    );
    // 签名机一侧（用签名代码模拟）→ 观察机核对，输出 65 字节签名
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_evm_pending_encoder(pending, &mut enc) }, AW_OK);
    let d = pump(enc);
    let req = decode_request(unsafe { aw_ffi_common::decoded_ur(d) }.unwrap()).unwrap();
    unsafe { aw_ur_decoder_free(d) };
    let (_, sig) = aw_chain_evm::sign::sign(&secp, &signer, &req).unwrap();
    let back = pump(aw_ffi_common::new_encoder(encode_signature(&sig).unwrap()).unwrap());
    let (mut h, mut hl) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_evm_pending_finalize(a, pending, back, &mut h, &mut hl) },
        AW_OK
    );
    let hex = String::from_utf8(take(h, hl)).unwrap();
    assert_eq!(hex.len(), 2 + 130, "{hex}");
    assert!(hex.ends_with("1b") || hex.ends_with("1c"));
    unsafe { aw_ur_decoder_free(back) };
    unsafe { aw_evm_pending_free(pending) };
    // personal_sign
    let (rc, p, json) = build(0, b"Sign in to example.org", 0);
    assert_eq!(rc, AW_OK);
    assert!(json.contains("Sign in to example.org"), "{json}");
    unsafe { aw_evm_pending_free(p) };
    // 链 ID 不符、格式不严谨、未知类型、空文本：观察机上就拒绝
    assert_eq!(build(1, typed, 1).0, AW_ERR_EVM_REJECT_BASE - 5);
    assert_eq!(build(1, b"{}", 0).0, AW_ERR_EVM_REJECT_BASE - 1);
    assert_eq!(build(2, b"x", 0).0, AW_ERR_BAD_ARGUMENT);
    assert_eq!(build(0, b"", 0).0, AW_ERR_BAD_ARGUMENT);
    unsafe { aw_evm_free(a) };
}

/// 与 aw-ffi-signer 的 evm_error_code 同一张表：序号固定，两边不得漂移（审计复审 #6/#9）
#[test]
fn evm_error_codes_match_signer_table() {
    use aw_chain_evm::EvmError as E;
    for (e, n) in [
        (E::Parse, 1),
        (E::Unsupported, 2),
        (E::Eip7702, 3),
        (E::NoReplayProtection, 4),
        (E::ChainMismatch, 5),
        (E::PathMismatch, 6),
        (E::AddressMismatch, 7),
        (E::DelegateCall, 8),
        (E::Overflow, 9),
        (E::Derivation, 10),
        (E::SelfCheck, 11),
        (E::BadSignature, 12),
        (E::RequestMismatch, 13),
        (E::BlindApproval, 14),
        (E::NeedsConfirmation, 15),
        (E::TooLong, 16),
        (E::SafeAdmin, 17),
    ] {
        assert_eq!(
            crate::evm::evm_code(e),
            aw_ffi_common::AW_ERR_EVM_REJECT_BASE - n,
            "{e:?}"
        );
    }
}

/// D35：手续费三档与余额核对经 C 接口往返
#[test]
fn evm_fee_tiers_and_funds() {
    use evm::*;
    const GWEI: u64 = 1_000_000_000;
    let rewards = [
        GWEI,
        2 * GWEI,
        3 * GWEI,
        GWEI,
        2 * GWEI,
        5 * GWEI,
        2 * GWEI,
        3 * GWEI,
        4 * GWEI,
    ];
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    let rc = unsafe {
        aw_evm_fee_tiers(
            1,
            10 * GWEI,
            rewards.as_ptr(),
            rewards.len(),
            2 * GWEI,
            21_000,
            &mut p,
            &mut l,
        )
    };
    assert_eq!(rc, AW_OK);
    let json = String::from_utf8(take(p, l)).unwrap();
    assert!(
        json.starts_with(
            r#"[{"speed":"slow","label":"慢","max_priority_fee":1000000000,"max_fee":13500000000,"#
        ),
        "{json}"
    );
    assert!(
        json.contains(r#""max_fee":17000000000"#) && json.contains(r#""max_fee":24000000000"#),
        "{json}"
    );
    // 标准档最多手续费 = 21000 × 17 gwei = 0.000357
    assert!(json.contains(r#""max_cost":"0.000357""#), "{json}");
    // 旧式链
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_evm_fee_tiers(0, 0, core::ptr::null(), 0, 4 * GWEI, 21_000, &mut p, &mut l) },
        AW_OK
    );
    let json = String::from_utf8(take(p, l)).unwrap();
    assert!(json.contains(r#""max_fee":5000000000"#), "{json}");
    // 参数错误：个数不是 3 的倍数、旧式链带历史、空指针
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_evm_fee_tiers(1, GWEI, rewards.as_ptr(), 4, GWEI, 21_000, &mut p, &mut l) },
        AW_ERR_BAD_ARGUMENT
    );
    assert_eq!(
        unsafe { aw_evm_fee_tiers(0, 0, rewards.as_ptr(), 3, GWEI, 21_000, &mut p, &mut l) },
        AW_ERR_BAD_ARGUMENT
    );
    assert_eq!(
        unsafe { aw_evm_fee_tiers(1, GWEI, core::ptr::null(), 3, GWEI, 21_000, &mut p, &mut l) },
        AW_ERR_NULL_POINTER
    );
    assert!(p.is_null() && l == 0);

    // 余额核对：0.01 ETH + 21000 × 30 gwei = 0.01063 ETH
    let mut value = [0u8; 32];
    value[24..].copy_from_slice(&10_000_000_000_000_000u64.to_be_bytes());
    let mut max_fee = [0u8; 32];
    max_fee[24..].copy_from_slice(&(30 * GWEI).to_be_bytes());
    let check = |native: &str, token: &str| unsafe {
        aw_evm_check_funds(
            native.as_ptr(),
            native.len(),
            token.as_ptr(),
            token.len(),
            value.as_ptr(),
            21_000,
            max_fee.as_ptr(),
        )
    };
    assert_eq!(check("0x25c3edbdf66000", ""), AW_OK); // 恰好 0.01063 ETH
    assert_eq!(check("0x25c3edbdf65fff", ""), AW_ERR_EVM_NATIVE_SHORT);
    // 代币转账：原生币只需 0.00063，代币要 ≥ 数量
    assert_eq!(check("0x2386f26fc10000", "0x2386f26fc10000"), AW_OK);
    assert_eq!(
        check("0x2386f26fc10000", "0x2386f26fc0ffff"),
        AW_ERR_EVM_TOKEN_SHORT
    );
    assert_eq!(check("1234", ""), AW_ERR_BAD_ARGUMENT);
}

/// P2c：观察机经 C 接口构造 Solana 转账 → 签名机（用签名代码模拟）签名 → 观察机核对并拼出交易
#[test]
fn sol_build_sign_finalize_through_c_abi() {
    use aw_chain_sol::request::{decode_request, encode_signature};
    use aw_chain_sol::sign::SolSigner;
    use aw_chain_sol::Scheme;
    use sol::*;
    let seed = aw_bip39::Mnemonic::parse(MNEMONIC)
        .unwrap()
        .to_seed("")
        .unwrap();
    let signer = SolSigner::from_seed(&seed).unwrap();
    let own = signer.public_key(Scheme::LedgerLive, 0).unwrap();
    // 地址文本往返；非规范写法被拒绝
    let text = aw_chain_sol::address(&own);
    let mut back = [0u8; 32];
    assert_eq!(
        unsafe { aw_sol_parse_address(text.as_ptr(), text.len(), back.as_mut_ptr()) },
        AW_OK
    );
    assert_eq!(back, own);
    let bad = format!("1{text}");
    assert_eq!(
        unsafe { aw_sol_parse_address(bad.as_ptr(), bad.len(), back.as_mut_ptr()) },
        AW_ERR_BAD_ARGUMENT
    );
    // 优先费三档
    let samples = [0u64, 500, 2_000, 9_000];
    let (mut p, mut l) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_sol_priority_tiers(samples.as_ptr(), samples.len(), 200_000, &mut p, &mut l) },
        AW_OK
    );
    let json = String::from_utf8(take(p, l)).unwrap();
    assert!(
        json.contains(r#""speed":"standard","label":"标准","price":1000,"max_fee":5200"#),
        "{json}"
    );
    // 构造 USDC 转账
    let usdc = aw_chain_sol::programs::KNOWN_TOKENS[0].mint;
    let to = aw_chain_sol::address(&[0x22; 32]);
    let (mut pending, mut j, mut jl) = (core::ptr::null_mut(), core::ptr::null_mut(), 0usize);
    let rc = unsafe {
        aw_sol_build_transfer(
            own.as_ptr(),
            1,
            0,
            to.as_ptr(),
            to.len(),
            2_500_000,
            usdc.as_ptr(),
            6,
            0,
            [0x33u8; 32].as_ptr(),
            60_000,
            1_000,
            [8u8; 16].as_ptr(),
            &mut pending,
            &mut j,
            &mut jl,
        )
    };
    assert_eq!(rc, AW_OK);
    let json = String::from_utf8(take(j, jl)).unwrap();
    assert!(
        json.contains("2.5 USDC") && json.contains("已核对归属"),
        "{json}"
    );
    let mut enc = core::ptr::null_mut();
    assert_eq!(unsafe { aw_sol_pending_encoder(pending, &mut enc) }, AW_OK);
    let d = pump(enc);
    let req = decode_request(unsafe { aw_ffi_common::decoded_ur(d) }.unwrap()).unwrap();
    unsafe { aw_ur_decoder_free(d) };
    let (_, sig) = signer.sign(&req).unwrap();
    let back = pump(aw_ffi_common::new_encoder(encode_signature(&sig).unwrap()).unwrap());
    let (mut h, mut hl) = (core::ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { aw_sol_pending_finalize(pending, back, &mut h, &mut hl) },
        AW_OK
    );
    let out = String::from_utf8(take(h, hl)).unwrap();
    assert!(
        out.contains(&format!(
            r#""txid":"{}""#,
            aw_chain_sol::watch::transaction_id(&sig.signature)
        )),
        "{out}"
    );
    assert!(out.contains(r#""tx_hex":"01"#), "{out}");
    unsafe { aw_ur_decoder_free(back) };
    unsafe { aw_sol_pending_free(pending) };
}

/// 与 aw-ffi-signer 的 sol_error_code 同一张表：序号固定
#[test]
fn sol_error_codes_match_signer_table() {
    use aw_chain_sol::SolError as E;
    for (e, n) in [
        (E::Parse, 1),
        (E::LookupTable, 2),
        (E::NotSigner, 3),
        (E::OwnerChange, 4),
        (E::SetAuthority, 5),
        (E::Overflow, 6),
        (E::Unsupported, 7),
        (E::PathMismatch, 8),
        (E::AddressMismatch, 9),
        (E::Derivation, 10),
        (E::BadSignature, 11),
        (E::RequestMismatch, 12),
        (E::AccountLock, 13),
    ] {
        assert_eq!(
            crate::sol::sol_code(e),
            aw_ffi_common::AW_ERR_SOL_REJECT_BASE - n,
            "{e:?}"
        );
    }
}
