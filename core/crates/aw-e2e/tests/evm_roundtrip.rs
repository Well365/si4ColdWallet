//! 端到端（EVM）：签名机导出账户 → 观察机导入 → 观察机构造交易与 eth-sign-request → 动画二维码
//! → 签名机审查并签名 → eth-signature → 观察机核对签名、拼出可广播交易并独立验证。
//! 另外模拟被控制的观察机发来的各种危险请求，确认签名机拒签或给出高风险警告。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use aw_bip39::Mnemonic;
use aw_chain_evm::account_ur::{account_from_hdkey, account_to_hdkey};
use aw_chain_evm::keccak::keccak256;
use aw_chain_evm::request::{
    decode_request, decode_signature, encode_request, encode_signature, DataType, SignRequest,
};
use aw_chain_evm::review::review;
use aw_chain_evm::rlp;
use aw_chain_evm::sign::{sign, EvmSigner};
use aw_chain_evm::uint::U256;
use aw_chain_evm::watch::{build_eip1559, build_request, erc20_transfer, finalize, Eip1559};
use aw_chain_evm::{address_of, checksum_address, parse_address, Account, EvmError};
use aw_common::display::Level;
use aw_ur::registry::{decode_hdkey, encode_hdkey, Style};
use aw_ur::ur::{Ur, UrDecoder, UrEncoder};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::Network;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// 该助记词 m/44'/60'/0'/0/0 的公开地址（MetaMask 等钱包一致）
const ADDRESS0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const RECIPIENT: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const USDT_ETH: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

fn signer(secp: &Secp256k1<All>) -> EvmSigner {
    let seed = Mnemonic::parse(MNEMONIC).unwrap().to_seed("").unwrap();
    let master = aw_keys::master(&seed, Network::Testnet).unwrap();
    EvmSigner::from_master(secp, &master).unwrap()
}

/// 签名机导出 → 观察机导入（经 UR 文本）
fn watcher_account(s: &EvmSigner) -> Account {
    let text =
        aw_ur::ur::encode(&encode_hdkey(&account_to_hdkey(&s.account), Style::Legacy).unwrap());
    account_from_hdkey(&decode_hdkey(&aw_ur::ur::decode(&text).unwrap()).unwrap()).unwrap()
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

fn payment(chain_id: u64, to: &str, value: u64, data: Vec<u8>) -> Vec<u8> {
    build_eip1559(&Eip1559 {
        chain_id,
        nonce: 7,
        max_priority_fee: U256::from_u64(1_500_000_000),
        max_fee: U256::from_u64(40_000_000_000),
        gas_limit: if data.is_empty() { 21_000 } else { 65_000 },
        to: parse_address(to).unwrap(),
        value: U256::from_u64(value),
        data,
    })
    .unwrap()
}

/// 签名机一侧：收到二维码 → 解码请求 → 签名 → 返回二维码
fn signer_side(secp: &Secp256k1<All>, s: &EvmSigner, ur: Ur) -> Result<Ur, EvmError> {
    let req = decode_request(&ur).unwrap();
    let (_review, sig) = sign(secp, s, &req)?;
    Ok(encode_signature(&sig).unwrap())
}

#[test]
fn known_address_and_account_export() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    assert_eq!(
        checksum_address(&s.account.address(&secp, 0).unwrap()),
        ADDRESS0
    );
    let w = watcher_account(&s);
    assert_eq!(w, s.account);
    assert_eq!(checksum_address(&w.address(&secp, 0).unwrap()), ADDRESS0);
    // BTC 的 hdkey 不能被当作 EVM 账户导入，反之亦然
    let mut k = account_to_hdkey(&s.account);
    k.coin_type = 0;
    assert!(account_from_hdkey(&k).is_err());
    assert!(aw_chain_btc::account_ur::account_from_hdkey(&account_to_hdkey(&s.account)).is_err());
}

#[test]
fn eip1559_roundtrip_over_animated_qr() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let tx = payment(11_155_111, RECIPIENT, 10_000_000_000_000_000, vec![]);
    let req = build_request(
        &secp,
        &w,
        0,
        tx.clone(),
        DataType::TypedTx,
        Some(11_155_111),
        [1; 16],
    )
    .unwrap();

    // 签名机看到的内容
    let r = review(
        &secp,
        &s.account,
        &decode_request(&transmit(encode_request(&req).unwrap())).unwrap(),
    )
    .unwrap();
    assert_eq!(r.display.title, "发送 SepoliaETH");
    let rows: Vec<_> = r
        .display
        .rows
        .iter()
        .map(|x| (x.label.as_str(), x.value.as_str()))
        .collect();
    assert!(rows.contains(&("收款地址", RECIPIENT)));
    assert!(rows.contains(&("金额", "0.01 SepoliaETH")));
    assert!(rows.contains(&("最高手续费", "0.00084 SepoliaETH")));
    assert!(rows.contains(&("Nonce", "7")));
    assert!(!r.display.has_danger());

    let sig_ur = signer_side(&secp, &s, transmit(encode_request(&req).unwrap())).unwrap();
    let sig = decode_signature(&transmit(sig_ur)).unwrap();
    let raw = finalize(&secp, &w, &req, &sig).unwrap();

    // 独立核对：拼出的交易 = 0x02 ‖ rlp(9 个字段 + yParity, r, s)，签名恢复出本账户地址
    assert_eq!(raw[0], 0x02);
    let root = rlp::decode(&raw[1..]).unwrap();
    let f = root.list().unwrap();
    assert_eq!(f.len(), 12);
    let mut compact = [0u8; 64];
    compact[32 - f[10].bytes().unwrap().len()..32].copy_from_slice(f[10].bytes().unwrap());
    compact[64 - f[11].bytes().unwrap().len()..].copy_from_slice(f[11].bytes().unwrap());
    let recid = RecoveryId::from_i32(i32::from(
        f[9].bytes().unwrap().first().copied().unwrap_or(0),
    ))
    .unwrap();
    let rs = RecoverableSignature::from_compact(&compact, recid).unwrap();
    let pk = secp
        .recover_ecdsa(&Message::from_digest(keccak256(&tx)), &rs)
        .unwrap();
    assert_eq!(checksum_address(&address_of(&pk)), ADDRESS0);
}

#[test]
fn signatures_are_deterministic_across_devices() {
    let secp_a = Secp256k1::new();
    let secp_b = Secp256k1::new();
    let w = watcher_account(&signer(&secp_a));
    let req = build_request(
        &secp_a,
        &w,
        2,
        payment(1, RECIPIENT, 1, vec![]),
        DataType::TypedTx,
        Some(1),
        [2; 16],
    )
    .unwrap();
    let a = sign(&secp_a, &signer(&secp_a), &req).unwrap().1;
    let b = sign(&secp_b, &signer(&secp_b), &req).unwrap().1;
    assert_eq!(a, b);
}

#[test]
fn legacy_bsc_and_personal_message() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    // BNB Smart Chain 旧式 EIP-155 交易：rlp([nonce, gasPrice, gas, to, value, data, 56, 0, 0])
    let mut f = vec![];
    rlp::encode_uint(&mut f, U256::from_u64(3));
    rlp::encode_uint(&mut f, U256::from_u64(3_000_000_000));
    rlp::encode_uint(&mut f, U256::from_u64(21_000));
    rlp::encode_bytes(&mut f, &parse_address(RECIPIENT).unwrap());
    rlp::encode_uint(&mut f, U256::from_u64(50_000_000_000_000_000));
    rlp::encode_bytes(&mut f, &[]);
    rlp::encode_uint(&mut f, U256::from_u64(56));
    rlp::encode_bytes(&mut f, &[]);
    rlp::encode_bytes(&mut f, &[]);
    let mut tx = vec![];
    rlp::encode_list(&mut tx, &f);
    let req = build_request(&secp, &w, 0, tx, DataType::LegacyTx, Some(56), [3; 16]).unwrap();
    let (r, sig) = sign(&secp, &s, &req).unwrap();
    assert_eq!(r.display.chain, "BNB Smart Chain");
    assert!(r.display.rows.iter().any(|x| x.value == "0.05 BNB"));
    // 审计 P1-11：金额 0.05 + 最高手续费 21000 × 3 gwei = 0.000063，总计最多扣除 0.050063
    assert!(
        r.display
            .rows
            .iter()
            .any(|x| x.label.starts_with("总计最多扣除") && x.value == "0.050063 BNB"),
        "{:?}",
        r.display.rows
    );
    assert!([147, 148].contains(&sig.signature[64])); // v = 56×2 + 35 + recid
    let raw = finalize(&secp, &w, &req, &sig).unwrap();
    assert_eq!(rlp::decode(&raw).unwrap().list().unwrap().len(), 9);

    // personal_sign
    let req = build_request(
        &secp,
        &w,
        0,
        b"Sign in to example.org".to_vec(),
        DataType::PersonalMessage,
        Some(1),
        [4; 16],
    )
    .unwrap();
    let (r, sig) = sign(&secp, &s, &req).unwrap();
    assert!(r
        .display
        .rows
        .iter()
        .any(|x| x.value == "Sign in to example.org"));
    assert!([27, 28].contains(&sig.signature[64]));
    assert_eq!(finalize(&secp, &w, &req, &sig).unwrap(), sig.signature);
    // 32 字节且不能按文字显示的消息：很可能是 safeTxHash 等交易哈希，签它等于盲签 → 拒签（D33）
    let req = build_request(
        &secp,
        &w,
        0,
        vec![0xab; 32],
        DataType::PersonalMessage,
        None,
        [5; 16],
    )
    .unwrap();
    assert_eq!(
        review(&secp, &s.account, &req).map(|_| ()),
        Err(EvmError::BlindApproval)
    );
    // 恰好 32 字节的文字消息同样拒签：攻击者可以调整 SafeTx 的自由字段把 safeTxHash 凑成可打印字符（审计复审 #2）；
    // 31 / 33 字节照常可签
    for (msg, want_ok) in [
        (&b"abcdefghijklmnopqrstuvwxyz012345"[..], false),
        (&b"abcdefghijklmnopqrstuvwxyz01234"[..], true),
        (&b"abcdefghijklmnopqrstuvwxyz0123456"[..], true),
    ] {
        let req = build_request(
            &secp,
            &w,
            0,
            msg.to_vec(),
            DataType::PersonalMessage,
            None,
            [5; 16],
        )
        .unwrap();
        let got = review(&secp, &s.account, &req).map(|_| ());
        if want_ok {
            assert_eq!(got, Ok(()), "{} 字节", msg.len());
        } else {
            assert_eq!(got, Err(EvmError::BlindApproval), "{} 字节", msg.len());
        }
    }
}

#[test]
fn token_calls_are_shown_and_dangers_flagged() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    // USDT 转账：按 6 位小数显示
    let data = erc20_transfer(
        &parse_address(RECIPIENT).unwrap(),
        U256::from_u64(12_500_000),
    );
    let req = build_request(
        &secp,
        &w,
        0,
        payment(1, USDT_ETH, 0, data),
        DataType::TypedTx,
        Some(1),
        [6; 16],
    )
    .unwrap();
    let r = review(&secp, &s.account, &req).unwrap();
    assert_eq!(r.display.title, "代币转账");
    assert!(r
        .display
        .rows
        .iter()
        .any(|x| x.label == "代币数量" && x.value == "12.5 USDT"));
    assert!(!r.display.has_danger());

    // 无限额 approve
    let mut approve = vec![0x09, 0x5e, 0xa7, 0xb3];
    approve.extend([0u8; 12]);
    approve.extend(parse_address(RECIPIENT).unwrap());
    approve.extend([0xff; 32]);
    let req = build_request(
        &secp,
        &w,
        0,
        payment(1, USDT_ETH, 0, approve),
        DataType::TypedTx,
        Some(1),
        [7; 16],
    )
    .unwrap();
    let r = review(&secp, &s.account, &req).unwrap();
    assert!(r
        .display
        .warnings
        .iter()
        .any(|x| x.level == Level::Danger && x.text.contains("无限额授权")));

    // 未知合约调用
    let req = build_request(
        &secp,
        &w,
        0,
        payment(1, RECIPIENT, 0, vec![0xde, 0xad, 0xbe, 0xef, 1]),
        DataType::TypedTx,
        Some(1),
        [8; 16],
    )
    .unwrap();
    let r = review(&secp, &s.account, &req).unwrap();
    assert_eq!(r.display.title, "合约调用");
    assert!(r.display.has_danger());
}

fn reject(secp: &Secp256k1<All>, s: &EvmSigner, req: &SignRequest, want: EvmError) {
    assert_eq!(sign(secp, s, req).map(|_| ()), Err(want), "应拒签");
}

#[test]
fn signer_rejects_dangerous_or_inconsistent_requests() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let good = build_request(
        &secp,
        &w,
        0,
        payment(1, RECIPIENT, 1, vec![]),
        DataType::TypedTx,
        Some(1),
        [9; 16],
    )
    .unwrap();

    // 声明的链 ID 与交易内的不一致
    reject(
        &secp,
        &s,
        &SignRequest {
            chain_id: Some(56),
            ..good.clone()
        },
        EvmError::ChainMismatch,
    );
    // 声明的地址与路径不符
    reject(
        &secp,
        &s,
        &SignRequest {
            address: Some([0x11; 20]),
            ..good.clone()
        },
        EvmError::AddressMismatch,
    );
    // 别的钱包的路径（来源指纹不同）/ 非地址路径
    let mut other = good.clone();
    other.path.source_fingerprint = Some(0xdead_beef);
    reject(&secp, &s, &other, EvmError::PathMismatch);
    let mut hardened = good.clone();
    hardened.path.components = vec![(44, true), (60, true), (0, true)];
    reject(&secp, &s, &hardened, EvmError::PathMismatch);
    // EIP-7702 授权交易
    reject(
        &secp,
        &s,
        &SignRequest {
            sign_data: vec![0x04, 0xc0],
            ..good.clone()
        },
        EvmError::Eip7702,
    );
    // Safe DELEGATECALL
    let mut safe = vec![0x6a, 0x76, 0x12, 0x02];
    safe.extend([0u8; 32 * 3]);
    safe.extend(U256::from_u64(1).to_be_bytes());
    safe.extend([0u8; 32 * 6]);
    let req = build_request(
        &secp,
        &w,
        0,
        payment(1, RECIPIENT, 0, safe),
        DataType::TypedTx,
        Some(1),
        [10; 16],
    )
    .unwrap();
    reject(&secp, &s, &req, EvmError::DelegateCall);
    // 数据类型与内容不符（交易字节冒充 EIP-712 结构化数据）
    reject(
        &secp,
        &s,
        &SignRequest {
            data_type: DataType::TypedData,
            ..good.clone()
        },
        EvmError::Parse,
    );
    // 数据类型与内容不符（类型化交易冒充旧式交易）
    reject(
        &secp,
        &s,
        &SignRequest {
            data_type: DataType::LegacyTx,
            ..good
        },
        EvmError::Parse,
    );
}

#[test]
fn watcher_rejects_bad_signatures() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let req = build_request(
        &secp,
        &w,
        0,
        payment(1, RECIPIENT, 1, vec![]),
        DataType::TypedTx,
        Some(1),
        [11; 16],
    )
    .unwrap();
    let (_, sig) = sign(&secp, &s, &req).unwrap();
    // 请求号不符
    let mut wrong_id = sig.clone();
    wrong_id.request_id = Some([0; 16]);
    assert_eq!(
        finalize(&secp, &w, &req, &wrong_id),
        Err(EvmError::RequestMismatch)
    );
    // 签名被篡改
    let mut tampered = sig.clone();
    tampered.signature[5] ^= 1;
    assert_eq!(
        finalize(&secp, &w, &req, &tampered),
        Err(EvmError::BadSignature)
    );
    // 别的地址的签名（签名机用 #1 签了 #0 的请求）
    let other = build_request(
        &secp,
        &w,
        1,
        req.sign_data.clone(),
        DataType::TypedTx,
        Some(1),
        [11; 16],
    )
    .unwrap();
    let (_, sig1) = sign(&secp, &s, &other).unwrap();
    assert_eq!(
        finalize(&secp, &w, &req, &sig1),
        Err(EvmError::BadSignature)
    );
    // 高 s 值（EIP-2）
    let mut high = sig;
    let n = U256::from_be_bytes(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ]);
    let s_val = U256::from_be_bytes(&high.signature[32..64].try_into().unwrap());
    // n - s：借助加法验证（n - s 的低位）
    let mut neg = [0u8; 32];
    let (nb, sb) = (n.to_be_bytes(), s_val.to_be_bytes());
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(nb[i]) - i16::from(sb[i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        neg[i] = u8::try_from(d).unwrap();
    }
    assert_eq!(U256::from_be_bytes(&neg).checked_add(s_val), Some(n));
    high.signature[32..64].copy_from_slice(&neg);
    high.signature[64] ^= 1;
    assert_eq!(
        finalize(&secp, &w, &req, &high),
        Err(EvmError::BadSignature)
    );
}

/// EVM 安全审查（P2a）发现的问题的回归测试
#[test]
fn review_findings_regressions() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let call = |selector: &str, words: &[[u8; 32]]| {
        let mut d = aw_common::hex::decode(selector).unwrap();
        for x in words {
            d.extend_from_slice(x);
        }
        d
    };
    let addr_word = |a: &str| {
        let mut x = [0u8; 32];
        x[12..].copy_from_slice(&parse_address(a).unwrap());
        x
    };
    let num = |v: U256| v.to_be_bytes();
    let review_of = |to: &str, data: Vec<u8>| {
        let req = build_request(
            &secp,
            &w,
            0,
            payment(1, to, 0, data),
            DataType::TypedTx,
            Some(1),
            [12; 16],
        )
        .unwrap();
        review(&secp, &s.account, &req)
    };
    let nft = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"; // 不在代币表中的合约

    // HIGH-1：未知合约的 approve(x, 0) 可能是"授权 NFT #0"：必须高风险，不得显示"撤销"
    let r = review_of(
        nft,
        call("095ea7b3", &[addr_word(RECIPIENT), num(U256::ZERO)]),
    )
    .unwrap();
    assert!(r.display.has_danger());
    assert!(!r.display.rows.iter().any(|x| x.value.contains("撤销")));
    assert!(r
        .display
        .rows
        .iter()
        .any(|x| x.label == "额度或 NFT 编号" && x.value == "0"));
    // 已知代币 approve 0 才是撤销
    let r = review_of(
        USDT_ETH,
        call("095ea7b3", &[addr_word(RECIPIENT), num(U256::ZERO)]),
    )
    .unwrap();
    assert!(r.display.rows.iter().any(|x| x.value.contains("撤销")) && !r.display.has_danger());
    // NFT transferFrom：显示为"数量或 NFT 编号"
    let r = review_of(
        nft,
        call(
            "23b872dd",
            &[
                addr_word(ADDRESS0),
                addr_word(RECIPIENT),
                num(U256::from_u64(7)),
            ],
        ),
    )
    .unwrap();
    assert!(r.display.rows.iter().any(|x| x.label == "数量或 NFT 编号"));

    // MEDIUM-2：接近无限额（2^254、10^30）也是高风险；正常额度是普通提示
    let mut big = [0u8; 32];
    big[0] = 0x40; // 2^254
    let r = review_of(USDT_ETH, call("095ea7b3", &[addr_word(RECIPIENT), big])).unwrap();
    assert!(r.display.has_danger());
    let r = review_of(
        USDT_ETH,
        call(
            "095ea7b3",
            &[
                addr_word(RECIPIENT),
                num(U256::parse_units("1000000000000000000000000", 6).unwrap()),
            ],
        ),
    )
    .unwrap();
    assert!(r.display.has_danger());
    let r = review_of(
        USDT_ETH,
        call(
            "095ea7b3",
            &[addr_word(RECIPIENT), num(U256::from_u64(5_000_000))],
        ),
    )
    .unwrap();
    assert!(
        !r.display.has_danger() && r.display.warnings.iter().any(|x| x.level == Level::Caution)
    );
    // Permit 额度为 MAX：高风险
    let r = review_of(
        USDT_ETH,
        call(
            "d505accf",
            &[
                addr_word(ADDRESS0),
                addr_word(RECIPIENT),
                num(U256::MAX),
                num(U256::ZERO),
                num(U256::ZERO),
                [0; 32],
                [0; 32],
            ],
        ),
    )
    .unwrap();
    assert!(r.display.has_danger());

    // MEDIUM-4：increaseAllowance、Permit2 approve、DAI permit 被识别；Safe approveHash 拒签
    let r = review_of(
        nft,
        call("39509351", &[addr_word(RECIPIENT), num(U256::from_u64(1))]),
    )
    .unwrap();
    assert_eq!(r.display.title, "增加授权额度");
    assert!(r.display.has_danger());
    let permit2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
    let r = review_of(
        permit2,
        call(
            "87517c45",
            &[
                addr_word(USDT_ETH),
                addr_word(RECIPIENT),
                num(U256::from_u64(1)),
                num(U256::from_u64(1_800_000_000)),
            ],
        ),
    )
    .unwrap();
    assert_eq!(r.display.title, "Permit2 授权");
    assert!(r.display.has_danger());
    let r = review_of(
        nft,
        call(
            "8fcbaf0c",
            &[
                addr_word(ADDRESS0),
                addr_word(RECIPIENT),
                num(U256::ZERO),
                num(U256::ZERO),
                num(U256::from_u64(1)),
                [0; 32],
                [0; 32],
                [0; 32],
            ],
        ),
    )
    .unwrap();
    assert!(r.display.has_danger());
    assert_eq!(
        review_of(nft, call("d4d9bdcd", &[[0x11; 32]])).map(|_| ()),
        Err(EvmError::BlindApproval)
    );

    // MEDIUM-3：含易混淆字母或不可见字符的消息只按十六进制显示
    for msg in [
        "Sign in to ex\u{430}mple.org",
        "Sign in\u{2060}",
        "Sign in \u{e0041}",
    ] {
        let req = build_request(
            &secp,
            &w,
            0,
            msg.as_bytes().to_vec(),
            DataType::PersonalMessage,
            None,
            [13; 16],
        )
        .unwrap();
        let r = review(&secp, &s.account, &req).unwrap();
        assert!(
            r.display.rows.iter().any(|x| x.label == "消息（十六进制）"),
            "{msg:?}"
        );
    }
    // 中文消息照常显示
    let req = build_request(
        &secp,
        &w,
        0,
        "登录确认：example.org".as_bytes().to_vec(),
        DataType::PersonalMessage,
        Some(1),
        [14; 16],
    )
    .unwrap();
    let r = review(&secp, &s.account, &req).unwrap();
    assert!(r
        .display
        .rows
        .iter()
        .any(|x| x.value == "登录确认：example.org"));
    assert_eq!(r.display.chain, "EVM"); // 消息签名不以请求声明的链作标题

    // LOW-6：EIP-155 v 放不进 u64 的超大链 ID 在审查阶段就拒绝
    let mut f = vec![];
    for v in [0u64, 1, 21_000] {
        rlp::encode_uint(&mut f, U256::from_u64(v));
    }
    rlp::encode_bytes(&mut f, &parse_address(RECIPIENT).unwrap());
    rlp::encode_uint(&mut f, U256::from_u64(1));
    rlp::encode_bytes(&mut f, &[]);
    rlp::encode_uint(&mut f, U256::from_u64(u64::MAX - 10));
    rlp::encode_bytes(&mut f, &[]);
    rlp::encode_bytes(&mut f, &[]);
    let mut tx = vec![];
    rlp::encode_list(&mut tx, &f);
    let req = build_request(&secp, &w, 0, tx, DataType::LegacyTx, None, [15; 16]).unwrap();
    assert_eq!(
        review(&secp, &s.account, &req).map(|_| ()),
        Err(EvmError::Overflow)
    );
}

/// 审计 P0-2（T5、D25）：未知合约的调用数据必须完整显示；Safe execTransaction 包着的内层调用必须被解析并按同样规则告警
#[test]
fn unknown_calldata_is_shown_in_full_and_nested_safe_exec_is_decoded() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let addr_word = |a: &str| {
        let mut x = [0u8; 32];
        x[12..].copy_from_slice(&parse_address(a).unwrap());
        x
    };
    let num = |v: u64| U256::from_u64(v).to_be_bytes();
    let review_of = |to: &str, data: Vec<u8>| {
        let req = build_request(
            &secp,
            &w,
            0,
            payment(1, to, 0, data),
            DataType::TypedTx,
            Some(1),
            [13; 16],
        )
        .unwrap();
        review(&secp, &s.account, &req).unwrap()
    };
    let nft = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";

    // 1. 300 字节的未知调用：显示的数据必须包含最后一个字节，且不得被省略号截断
    let mut data = vec![0xde, 0xad, 0xbe, 0xef];
    data.extend(std::iter::repeat_n(0xab, 295));
    data.push(0x17);
    let r = review_of(nft, data);
    let shown = r
        .display
        .rows
        .iter()
        .find(|x| x.label == "调用数据")
        .map(|x| x.value.clone())
        .unwrap();
    assert!(!shown.contains('…'), "{shown}");
    assert!(shown.contains("300 字节"), "{shown}");
    let flat: String = shown.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(flat.ends_with("abab17"), "{shown}");

    // 2. Safe execTransaction(operation = 0) 包着对 USDT 的无限额 approve：内层必须被解析并标为高风险
    let mut inner = aw_common::hex::decode("095ea7b3").unwrap();
    inner.extend_from_slice(&addr_word(RECIPIENT));
    inner.extend_from_slice(&[0xff; 32]);
    assert_eq!(inner.len(), 68);
    let mut exec = aw_common::hex::decode("6a761202").unwrap();
    for word in [
        addr_word(USDT_ETH), // to
        num(0),              // value
        num(320),            // data 偏移（10 个头部字）
        num(0),              // operation = CALL
        num(0),              // safeTxGas
        num(0),              // baseGas
        num(0),              // gasPrice
        [0u8; 32],           // gasToken
        [0u8; 32],           // refundReceiver
        num(448),            // signatures 偏移
    ] {
        exec.extend_from_slice(&word);
    }
    exec.extend_from_slice(&num(68));
    exec.extend_from_slice(&inner);
    exec.extend_from_slice(&[0u8; 28]); // 68 → 96 字节对齐
    exec.extend_from_slice(&num(0)); // signatures 长度 0
    let r = review_of(nft, exec);
    assert!(r.display.title.contains("Safe"), "{}", r.display.title);
    assert!(
        r.display.rows.iter().any(|x| x
            .value
            .contains(&checksum_address(&parse_address(USDT_ETH).unwrap()))),
        "{:?}",
        r.display.rows
    );
    assert!(
        r.display
            .warnings
            .iter()
            .any(|x| x.level == Level::Danger && x.text.contains("无限额")),
        "{:?}",
        r.display.warnings
    );
}

/// Safe execTransaction 的 ABI 编码：to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures
fn exec_calldata(
    selector: &str,
    to: &str,
    inner: &[u8],
    operation: u64,
    gas_price: u64,
    gas_token: &str,
    refund: &str,
) -> Vec<u8> {
    let addr_word = |a: &str| {
        let mut x = [0u8; 32];
        x[12..].copy_from_slice(&parse_address(a).unwrap());
        x
    };
    let num = |v: u64| U256::from_u64(v).to_be_bytes();
    let padded = inner.len().div_ceil(32) * 32;
    let mut d = aw_common::hex::decode(selector).unwrap();
    for word in [
        addr_word(to),
        num(0),
        num(320),
        num(operation),
        num(0),
        num(0),
        num(gas_price),
        addr_word(gas_token),
        addr_word(refund),
        num(320 + 32 + padded as u64),
    ] {
        d.extend_from_slice(&word);
    }
    d.extend_from_slice(&num(inner.len() as u64));
    d.extend_from_slice(inner);
    d.extend(std::iter::repeat_n(0u8, padded - inner.len()));
    d.extend_from_slice(&num(0));
    d
}

const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";
const SAFE_ADDR: &str = "0x1111111111111111111111111111111111111111";
const ATTACKER: &str = "0x6666666666666666666666666666666666666666";

/// D33：Safe 的几条绕行路径都必须拒签或强警告
#[test]
fn safe_bypass_paths_are_closed() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let review_of = |to: &str, data: Vec<u8>| {
        let req = build_request(
            &secp,
            &w,
            0,
            payment(1, to, 0, data),
            DataType::TypedTx,
            Some(1),
            [14; 16],
        )
        .unwrap();
        review(&secp, &s.account, &req)
    };
    let enable_module = {
        let mut d = aw_common::hex::decode("610b5925").unwrap();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(&parse_address(ATTACKER).unwrap());
        d
    };
    // 1. 多签对自身的 enableModule（operation 0）→ 拒签
    let exec = exec_calldata(
        "6a761202",
        SAFE_ADDR,
        &enable_module,
        0,
        0,
        ZERO_ADDR,
        ZERO_ADDR,
    );
    assert_eq!(
        review_of(SAFE_ADDR, exec).map(|_| ()),
        Err(EvmError::SafeAdmin)
    );
    // 2. 模块入口的 DELEGATECALL → 拒签（两个选择器）
    for sel in ["468721a7", "5229073f"] {
        let mut d = aw_common::hex::decode(sel).unwrap();
        let mut w32 = [0u8; 32];
        w32[12..].copy_from_slice(&parse_address(RECIPIENT).unwrap());
        d.extend_from_slice(&w32);
        d.extend_from_slice(&U256::from_u64(0).to_be_bytes());
        d.extend_from_slice(&U256::from_u64(128).to_be_bytes());
        d.extend_from_slice(&U256::from_u64(1).to_be_bytes());
        d.extend_from_slice(&U256::from_u64(0).to_be_bytes());
        assert_eq!(
            review_of(SAFE_ADDR, d).map(|_| ()),
            Err(EvmError::DelegateCall),
            "{sel}"
        );
    }
    // 3. 三层嵌套：exec(0) → exec(0) → exec(1) → 拒签
    let l3 = exec_calldata("6a761202", RECIPIENT, &[], 1, 0, ZERO_ADDR, ZERO_ADDR);
    let l2 = exec_calldata("6a761202", SAFE_ADDR, &l3, 0, 0, ZERO_ADDR, ZERO_ADDR);
    let l1 = exec_calldata("6a761202", SAFE_ADDR, &l2, 0, 0, ZERO_ADDR, ZERO_ADDR);
    assert_eq!(
        review_of(SAFE_ADDR, l1).map(|_| ()),
        Err(EvmError::DelegateCall)
    );
    // 4. 退款参数：gasPrice 非零、gasToken = USDT、refundReceiver = 攻击者 → 显示并强警告
    let transfer = {
        let mut d = aw_common::hex::decode("a9059cbb").unwrap();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(&parse_address(RECIPIENT).unwrap());
        d.extend_from_slice(&U256::from_u64(1_000_000).to_be_bytes());
        d
    };
    let exec = exec_calldata(
        "6a761202",
        USDT_ETH,
        &transfer,
        0,
        1_000_000_000_000,
        USDT_ETH,
        ATTACKER,
    );
    let r = review_of(SAFE_ADDR, exec).unwrap();
    assert!(
        r.display.rows.iter().any(|x| x
            .value
            .contains(&checksum_address(&parse_address(ATTACKER).unwrap()))),
        "{:?}",
        r.display.rows
    );
    assert!(
        r.display
            .warnings
            .iter()
            .any(|x| x.level == Level::Danger && x.text.contains("退款")),
        "{:?}",
        r.display.warnings
    );
    // 5. 内层 approve 给 Permit2 → 与顶层一样强警告
    let approve_permit2 = {
        let mut d = aw_common::hex::decode("095ea7b3").unwrap();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(&aw_chain_evm::chains::PERMIT2);
        d.extend_from_slice(&U256::from_u64(1).to_be_bytes());
        d
    };
    let exec = exec_calldata(
        "6a761202",
        USDT_ETH,
        &approve_permit2,
        0,
        0,
        ZERO_ADDR,
        ZERO_ADDR,
    );
    let r = review_of(SAFE_ADDR, exec).unwrap();
    assert!(
        r.display
            .warnings
            .iter()
            .any(|x| x.level == Level::Danger && x.text.contains("Permit2")),
        "{:?}",
        r.display.warnings
    );
}

/// 审计复审（第二轮之后）：剩下的口子必须全部关上——编码不规范、模块入口、全部管理函数、嵌套深度、
/// 嵌套层的多签身份、退款放大器、内层 transferFrom / permit 的逐项显示
#[test]
fn safe_second_review_gaps_are_closed() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let review_of = |to: &str, data: Vec<u8>| {
        let req = build_request(
            &secp,
            &w,
            0,
            payment(1, to, 0, data),
            DataType::TypedTx,
            Some(1),
            [15; 16],
        )
        .unwrap();
        review(&secp, &s.account, &req)
    };
    let word = |a: &str| {
        let mut x = [0u8; 32];
        x[12..].copy_from_slice(&parse_address(a).unwrap());
        x
    };
    let has_row = |r: &aw_chain_evm::review::Reviewed, label: &str, needle: &str| {
        r.display
            .rows
            .iter()
            .any(|x| x.label == label && x.value.contains(needle))
    };
    let enable_module = {
        let mut d = aw_common::hex::decode("610b5925").unwrap();
        d.extend_from_slice(&word(ATTACKER));
        d
    };

    // 1. 编码不规范（to 字高位非零）的 execTransaction：Safe 会截掉高位照常执行，签名机必须拒签而不是当作未知调用
    let mut dirty = exec_calldata(
        "6a761202",
        SAFE_ADDR,
        &enable_module,
        0,
        0,
        ZERO_ADDR,
        ZERO_ADDR,
    );
    dirty[4] = 0x01;
    assert_eq!(
        review_of(SAFE_ADDR, dirty).map(|_| ()),
        Err(EvmError::Parse)
    );

    // 2. 模块入口 operation = 0：内层同样审查——对多签自身的 enableModule 拒签；转出金额与入口名逐项显示
    let module_call = |sel: &str, to: &str, value: u64, inner: &[u8]| {
        let padded = inner.len().div_ceil(32) * 32;
        let mut d = aw_common::hex::decode(sel).unwrap();
        d.extend_from_slice(&word(to));
        d.extend_from_slice(&U256::from_u64(value).to_be_bytes());
        d.extend_from_slice(&U256::from_u64(128).to_be_bytes());
        d.extend_from_slice(&U256::from_u64(0).to_be_bytes());
        d.extend_from_slice(&U256::from_u64(inner.len() as u64).to_be_bytes());
        d.extend_from_slice(inner);
        d.extend(std::iter::repeat_n(0u8, padded - inner.len()));
        d
    };
    for sel in ["468721a7", "5229073f"] {
        assert_eq!(
            review_of(SAFE_ADDR, module_call(sel, SAFE_ADDR, 0, &enable_module)).map(|_| ()),
            Err(EvmError::SafeAdmin),
            "{sel}"
        );
        let r = review_of(
            SAFE_ADDR,
            module_call(sel, ATTACKER, 10_000_000_000_000_000_000, &[]),
        )
        .unwrap();
        assert!(
            has_row(&r, "内层转出金额", "10 ETH"),
            "{:?}",
            r.display.rows
        );
        assert!(
            has_row(&r, "执行入口", "FromModule"),
            "{:?}",
            r.display.rows
        );
        assert!(
            r.display
                .warnings
                .iter()
                .any(|x| x.text.contains("模块入口")),
            "{:?}",
            r.display.warnings
        );
    }

    // 3. 全部管理函数（含旧版 changeMasterCopy / signMessage）每一个都拒签，不只 enableModule
    for (sel, sig) in &aw_chain_evm::abi::SAFE_ADMIN {
        let mut inner = sel.to_vec();
        inner.extend_from_slice(&[0u8; 32]);
        let exec = exec_calldata("6a761202", SAFE_ADDR, &inner, 0, 0, ZERO_ADDR, ZERO_ADDR);
        assert_eq!(
            review_of(SAFE_ADDR, exec).map(|_| ()),
            Err(EvmError::SafeAdmin),
            "{sig}"
        );
    }

    // 4. 嵌套深度：顶层 + 3 层可以；再多一层按无法完整显示拒签
    let nest = |levels: usize| {
        let mut data: Vec<u8> = vec![];
        for _ in 0..levels {
            data = exec_calldata("6a761202", RECIPIENT, &data, 0, 0, ZERO_ADDR, ZERO_ADDR);
        }
        data
    };
    assert!(review_of(SAFE_ADDR, nest(4)).is_ok());
    assert_eq!(
        review_of(SAFE_ADDR, nest(5)).map(|_| ()),
        Err(EvmError::TooLong)
    );

    // 5. 嵌套层的"多签"是这一层的目标：exec(B, exec(B, enableModule)) 拒签；exec(B, exec(SAFE, enableModule)) 不是自管理
    let b = RECIPIENT;
    let inner_b = exec_calldata("6a761202", b, &enable_module, 0, 0, ZERO_ADDR, ZERO_ADDR);
    let outer = exec_calldata("6a761202", b, &inner_b, 0, 0, ZERO_ADDR, ZERO_ADDR);
    assert_eq!(
        review_of(SAFE_ADDR, outer).map(|_| ()),
        Err(EvmError::SafeAdmin)
    );
    let inner_safe = exec_calldata(
        "6a761202",
        SAFE_ADDR,
        &enable_module,
        0,
        0,
        ZERO_ADDR,
        ZERO_ADDR,
    );
    let outer = exec_calldata("6a761202", b, &inner_safe, 0, 0, ZERO_ADDR, ZERO_ADDR);
    assert!(review_of(SAFE_ADDR, outer).unwrap().display.has_danger());

    // 6. 退款：baseGas 放大器要显示并进入"最多退款"；原生币退款与零地址接收方（tx.origin）也要标明
    let transfer = {
        let mut d = aw_common::hex::decode("a9059cbb").unwrap();
        d.extend_from_slice(&word(RECIPIENT));
        d.extend_from_slice(&U256::from_u64(1_000_000).to_be_bytes());
        d
    };
    let mut exec = exec_calldata("6a761202", USDT_ETH, &transfer, 0, 1, USDT_ETH, ATTACKER);
    exec[4 + 32 * 5 + 10] = 0x01; // baseGas = 2^168
    let r = review_of(SAFE_ADDR, exec).unwrap();
    assert!(
        r.display
            .rows
            .iter()
            .any(|x| x.label == "baseGas" && x.value.len() > 40),
        "{:?}",
        r.display.rows
    );
    assert!(
        r.display
            .rows
            .iter()
            .any(|x| x.label.starts_with("最多退款") && x.value.contains("USDT")),
        "{:?}",
        r.display.rows
    );
    let exec = exec_calldata(
        "6a761202",
        RECIPIENT,
        &[],
        0,
        1_000_000_000,
        ZERO_ADDR,
        ZERO_ADDR,
    );
    let r = review_of(SAFE_ADDR, exec).unwrap();
    assert!(has_row(&r, "退款代币", "原生币"), "{:?}", r.display.rows);
    assert!(
        has_row(&r, "退款接收方", "tx.origin"),
        "{:?}",
        r.display.rows
    );
    assert!(
        r.display
            .warnings
            .iter()
            .any(|x| x.level == Level::Danger && x.text.contains("退款")),
        "{:?}",
        r.display.warnings
    );

    // 7. 内层 transferFrom / permit 与顶层一样逐项列出
    let transfer_from = {
        let mut d = aw_common::hex::decode("23b872dd").unwrap();
        d.extend_from_slice(&word(SAFE_ADDR));
        d.extend_from_slice(&word(ATTACKER));
        d.extend_from_slice(&U256::from_u64(1_000_000).to_be_bytes());
        d
    };
    let exec = exec_calldata(
        "6a761202",
        USDT_ETH,
        &transfer_from,
        0,
        0,
        ZERO_ADDR,
        ZERO_ADDR,
    );
    let r = review_of(SAFE_ADDR, exec).unwrap();
    let safe_cs = checksum_address(&parse_address(SAFE_ADDR).unwrap());
    let attacker_cs = checksum_address(&parse_address(ATTACKER).unwrap());
    assert!(
        has_row(&r, "内层转出地址", &safe_cs),
        "{:?}",
        r.display.rows
    );
    assert!(
        has_row(&r, "内层收款地址", &attacker_cs),
        "{:?}",
        r.display.rows
    );
    assert!(has_row(&r, "内层代币数量", "USDT"), "{:?}", r.display.rows);
    let permit = {
        let mut d = aw_common::hex::decode("d505accf").unwrap();
        d.extend_from_slice(&word(SAFE_ADDR));
        d.extend_from_slice(&word(ATTACKER));
        d.extend_from_slice(&[0xff; 32]);
        d.extend_from_slice(&U256::from_u64(0).to_be_bytes());
        d.extend_from_slice(&U256::from_u64(27).to_be_bytes());
        d.extend_from_slice(&[0u8; 64]);
        d
    };
    let exec = exec_calldata("6a761202", USDT_ETH, &permit, 0, 0, ZERO_ADDR, ZERO_ADDR);
    let r = review_of(SAFE_ADDR, exec).unwrap();
    assert!(
        has_row(&r, "内层被授权方", &attacker_cs),
        "{:?}",
        r.display.rows
    );
    assert!(
        r.display
            .warnings
            .iter()
            .any(|x| x.level == Level::Danger && x.text.contains("permit")),
        "{:?}",
        r.display.warnings
    );
}

/// 审计 P1-9 / P1-11：未知合约 transfer、已知代币大额授权、手续费绝对值过高都要强警告；手续费行有单独样式
#[test]
fn p1_review_warnings() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let review_tx = |tx: Vec<u8>| {
        let req = build_request(&secp, &w, 0, tx, DataType::TypedTx, Some(1), [16; 16]).unwrap();
        review(&secp, &s.account, &req).unwrap().display
    };
    let danger_with = |d: &aw_common::display::Display, needle: &str| {
        d.warnings
            .iter()
            .any(|x| x.level == Level::Danger && x.text.contains(needle))
    };
    let unknown = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
    // 1. 未知合约 transfer
    let d = review_tx(payment(
        1,
        unknown,
        0,
        erc20_transfer(&parse_address(RECIPIENT).unwrap(), U256::from_u64(5)),
    ));
    assert!(danger_with(&d, "未知合约"), "{:?}", d.warnings);
    // 已知代币的普通转账不加这条告警
    let d = review_tx(payment(
        1,
        USDT_ETH,
        0,
        erc20_transfer(&parse_address(RECIPIENT).unwrap(), U256::from_u64(5)),
    ));
    assert!(!d.has_danger(), "{:?}", d.warnings);
    // 2. 已知代币大额授权：999 999 999 999 USDT（不到"无限额"门槛）
    let mut approve = aw_common::hex::decode("095ea7b3").unwrap();
    approve.extend_from_slice(&[0u8; 12]);
    approve.extend_from_slice(&parse_address(RECIPIENT).unwrap());
    approve.extend_from_slice(&U256::from_u64(999_999_999_999_000_000).to_be_bytes());
    let d = review_tx(payment(1, USDT_ETH, 0, approve));
    assert!(danger_with(&d, "大额授权"), "{:?}", d.warnings);
    // 小额授权仍只是提醒
    let mut small = aw_common::hex::decode("095ea7b3").unwrap();
    small.extend_from_slice(&[0u8; 12]);
    small.extend_from_slice(&parse_address(RECIPIENT).unwrap());
    small.extend_from_slice(&U256::from_u64(100_000_000).to_be_bytes());
    assert!(!review_tx(payment(1, USDT_ETH, 0, small)).has_danger());
    // 3. 手续费绝对值：21000 × 3000 gwei = 0.063 ETH > 0.05
    let tx = build_eip1559(&Eip1559 {
        chain_id: 1,
        nonce: 1,
        max_priority_fee: U256::from_u64(1_000_000_000),
        max_fee: U256::from_u64(3_000_000_000_000),
        gas_limit: 21_000,
        to: parse_address(RECIPIENT).unwrap(),
        value: U256::from_u64(1_000_000_000_000_000_000),
        data: vec![],
    })
    .unwrap();
    let d = review_tx(tx);
    assert!(danger_with(&d, "最高手续费超过"), "{:?}", d.warnings);
    // 4. 手续费行使用单独样式，不与金额混同
    let fee_row = d.rows.iter().find(|r| r.label == "最高手续费").unwrap();
    assert_eq!(fee_row.style, aw_common::display::Style::Fee);
    let amount_row = d.rows.iter().find(|r| r.label == "金额").unwrap();
    assert_eq!(amount_row.style, aw_common::display::Style::Amount);
}
