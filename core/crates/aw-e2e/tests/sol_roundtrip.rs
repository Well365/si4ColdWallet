//! Solana 端到端（P2c）：观察机构造 → sol-sign-request 动画二维码 → 签名机审查并签名 → sol-signature →
//! 观察机核对签名并拼出交易。三种派生方案（D34）都跑一遍；签名可用公钥独立核对。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use aw_bip39::Mnemonic;
use aw_chain_sol::programs::{KNOWN_TOKENS, TOKEN};
use aw_chain_sol::request::{decode_request, decode_signature, encode_request, encode_signature};
use aw_chain_sol::sign::SolSigner;
use aw_chain_sol::watch::{
    build_request, build_transfer, finalize, transaction_id, TokenSpec, Transfer,
};
use aw_chain_sol::{address, Scheme, SolError};
use aw_ur::ur::{Ur, UrDecoder, UrEncoder};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn signer() -> SolSigner {
    let seed = Mnemonic::parse(MNEMONIC).unwrap().to_seed("").unwrap();
    SolSigner::from_seed(&seed).unwrap()
}

/// 模拟摄像头：逐帧传输，丢掉每 3 帧中的 1 帧
fn transmit(ur: Ur) -> Ur {
    let mut enc = UrEncoder::new(ur, 80, 0, 10).unwrap();
    let mut dec = UrDecoder::new();
    for frame in 1..=10_000 {
        let part = enc.next_part().to_uppercase();
        if frame % 3 != 0 {
            dec.receive(&part).unwrap();
        }
        if let Some(r) = dec.result() {
            return r.clone().unwrap();
        }
    }
    panic!("动画二维码没有解码完成");
}

#[test]
fn all_schemes_round_trip_and_match_the_address_vectors() {
    let s = signer();
    // 地址与 tools/testvectors/chain_addresses.py（独立实现）一致
    for (scheme, index, want) in [
        (
            Scheme::Phantom,
            0,
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        ),
        (
            Scheme::LedgerLive,
            1,
            "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi",
        ),
        (
            Scheme::LedgerMain,
            0,
            "D2PPQSYFe83nDzk96FqGumVU8JA7J8vj2Rhjc2oXzEi5",
        ),
    ] {
        let own = s.public_key(scheme, index).unwrap();
        assert_eq!(address(&own), want);
        let msg = build_transfer(&Transfer {
            from: own,
            to: [0x22; 32],
            amount: 250_000_000,
            token: None,
            blockhash: [0x33; 32],
            unit_limit: Some(450),
            unit_price: Some(1_000),
        })
        .unwrap();
        let req = build_request(
            msg,
            scheme,
            index,
            own,
            Some(0x73c5_da0a),
            [index as u8; 16],
        );
        // 观察机 → 签名机
        let got = decode_request(&transmit(encode_request(&req).unwrap())).unwrap();
        assert_eq!(got, req);
        let (reviewed, sig) = s.sign(&got).unwrap();
        assert_eq!(reviewed.native_out, 250_000_000);
        assert!(
            !reviewed.display.has_danger(),
            "{:?}",
            reviewed.display.warnings
        );
        // 签名机 → 观察机
        let back = decode_signature(&transmit(encode_signature(&sig).unwrap())).unwrap();
        let tx = finalize(&req, &back).unwrap();
        assert_eq!(tx[0], 1);
        assert_eq!(&tx[1..65], &sig.signature);
        assert_eq!(&tx[65..], req.sign_data.as_slice());
        assert_eq!(transaction_id(&sig.signature).len() > 80, true);
        // Ed25519 确定性签名：同一请求两次签名完全相同
        assert_eq!(s.sign(&got).unwrap().1, sig);
    }
}

#[test]
fn usdc_transfer_shows_verified_recipient() {
    let s = signer();
    let own = s.public_key(Scheme::Phantom, 0).unwrap();
    let usdc = &KNOWN_TOKENS[0];
    let msg = build_transfer(&Transfer {
        from: own,
        to: [0x22; 32],
        amount: 5_000_000,
        token: Some(TokenSpec {
            mint: usdc.mint,
            decimals: 6,
            program: TOKEN,
        }),
        blockhash: [0x33; 32],
        unit_limit: Some(60_000),
        unit_price: Some(10_000),
    })
    .unwrap();
    let req = build_request(msg, Scheme::Phantom, 0, own, None, [1; 16]);
    let (r, _) = s.sign(&req).unwrap();
    let rows = &r.display.rows;
    assert!(
        rows.iter()
            .any(|x| x.label == "　数量" && x.value == "5 USDC"),
        "{rows:?}"
    );
    assert!(rows
        .iter()
        .any(|x| x.label == "　收款人" && x.value == address(&[0x22; 32])));
    assert!(!r.display.has_danger(), "{:?}", r.display.warnings);
}

#[test]
fn signer_and_watcher_refuse_inconsistent_requests() {
    let s = signer();
    let own = s.public_key(Scheme::Phantom, 0).unwrap();
    let other = s.public_key(Scheme::Phantom, 1).unwrap();
    let msg = build_transfer(&Transfer {
        from: own,
        to: [0x22; 32],
        amount: 1,
        token: None,
        blockhash: [0x33; 32],
        unit_limit: None,
        unit_price: None,
    })
    .unwrap();
    // 路径是另一个账户：派生出的地址不是消息里的签名者
    let req = build_request(msg.clone(), Scheme::Phantom, 1, other, None, [2; 16]);
    assert_eq!(s.sign(&req).map(|_| ()), Err(SolError::NotSigner));
    // 声明的地址与路径不符
    let req = build_request(msg.clone(), Scheme::Phantom, 0, other, None, [2; 16]);
    assert_eq!(s.sign(&req).map(|_| ()), Err(SolError::AddressMismatch));
    // 路径不是三种方案之一
    let mut req = build_request(msg.clone(), Scheme::Phantom, 0, own, None, [2; 16]);
    req.path.components = vec![(44, true), (501, true), (0, true), (0, true), (0, true)];
    assert_eq!(s.sign(&req).map(|_| ()), Err(SolError::PathMismatch));
    // 观察机：请求号不对、签名被改
    let req = build_request(msg, Scheme::Phantom, 0, own, None, [3; 16]);
    let (_, mut sig) = s.sign(&req).unwrap();
    let mut wrong_id = sig.clone();
    wrong_id.request_id = Some([4; 16]);
    assert_eq!(finalize(&req, &wrong_id), Err(SolError::RequestMismatch));
    sig.signature[10] ^= 1;
    assert_eq!(finalize(&req, &sig), Err(SolError::BadSignature));
}
