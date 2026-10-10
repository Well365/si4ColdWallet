//! 端到端（EIP-712 结构化签名）：观察机构造 eth-sign-request（数据类型 2）→ 动画二维码
//! → 签名机审查（摘要 + 全部字段 + 高风险警告）并签名 → 观察机核对签名能恢复出本地址。
//! 另外覆盖：链 ID 与请求不符拒签、格式不严谨拒签、Seaport 钓鱼挂单、Permit2 无限额。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use aw_bip39::Mnemonic;
use aw_chain_evm::account_ur::{account_from_hdkey, account_to_hdkey};
use aw_chain_evm::eip712::TypedData;
use aw_chain_evm::request::{decode_request, decode_signature, encode_request, encode_signature};
use aw_chain_evm::request::{DataType, SignRequest};
use aw_chain_evm::review::{review, Reviewed};
use aw_chain_evm::sign::{sign, EvmSigner};
use aw_chain_evm::watch::{build_request, finalize};
use aw_chain_evm::{Account, EvmError};
use aw_common::display::Level;
use aw_ur::registry::{decode_hdkey, encode_hdkey, Style};
use aw_ur::ur::{UrDecoder, UrEncoder};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::Network;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OWNER: &str = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
const SPENDER: &str = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const DOMAIN4: &str = r#"[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]"#;

fn signer(secp: &Secp256k1<All>) -> EvmSigner {
    let seed = Mnemonic::parse(MNEMONIC).unwrap().to_seed("").unwrap();
    let master = aw_keys::master(&seed, Network::Testnet).unwrap();
    EvmSigner::from_master(secp, &master).unwrap()
}

fn watcher_account(s: &EvmSigner) -> Account {
    let text =
        aw_ur::ur::encode(&encode_hdkey(&account_to_hdkey(&s.account), Style::Legacy).unwrap());
    account_from_hdkey(&decode_hdkey(&aw_ur::ur::decode(&text).unwrap()).unwrap()).unwrap()
}

fn permit_json(chain_id: u64, value: &str) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":{DOMAIN4},"Permit":[{{"name":"owner","type":"address"}},{{"name":"spender","type":"address"}},{{"name":"value","type":"uint256"}},{{"name":"nonce","type":"uint256"}},{{"name":"deadline","type":"uint256"}}]}},"primaryType":"Permit","domain":{{"name":"USD Coin","version":"2","chainId":{chain_id},"verifyingContract":"{USDC}"}},"message":{{"owner":"{OWNER}","spender":"{SPENDER}","value":"{value}","nonce":0,"deadline":1893456000}}}}"#
    )
}

fn mail_json(domain: &str, domain_types: &str) -> String {
    format!(
        r#"{{"types":{{"EIP712Domain":{domain_types},"Person":[{{"name":"name","type":"string"}},{{"name":"wallet","type":"address"}}],"Mail":[{{"name":"from","type":"Person"}},{{"name":"to","type":"Person"}},{{"name":"contents","type":"string"}}]}},"primaryType":"Mail","domain":{domain},"message":{{"from":{{"name":"Cow","wallet":"0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"}},"to":{{"name":"Bob","wallet":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"contents":"Hello, Bob!"}}}}"#
    )
}

const OFFER_FIELDS: &str = r#"{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"}"#;

fn seaport_json(consideration: &str) -> String {
    let zero32 = format!("0x{}", "00".repeat(32));
    format!(
        r#"{{"types":{{"EIP712Domain":{DOMAIN4},"OrderComponents":[{{"name":"offerer","type":"address"}},{{"name":"zone","type":"address"}},{{"name":"offer","type":"OfferItem[]"}},{{"name":"consideration","type":"ConsiderationItem[]"}},{{"name":"orderType","type":"uint8"}},{{"name":"startTime","type":"uint256"}},{{"name":"endTime","type":"uint256"}},{{"name":"zoneHash","type":"bytes32"}},{{"name":"salt","type":"uint256"}},{{"name":"conduitKey","type":"bytes32"}},{{"name":"counter","type":"uint256"}}],"OfferItem":[{OFFER_FIELDS}],"ConsiderationItem":[{OFFER_FIELDS},{{"name":"recipient","type":"address"}}]}},"primaryType":"OrderComponents","domain":{{"name":"Seaport","version":"1.6","chainId":1,"verifyingContract":"0x0000000000000068f116a894984e2db1123eb395"}},"message":{{"offerer":"{OWNER}","zone":"0x0000000000000000000000000000000000000000","offer":[{{"itemType":2,"token":"0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d","identifierOrCriteria":"1234","startAmount":"1","endAmount":"1"}}],"consideration":[{consideration}],"orderType":0,"startTime":1700000000,"endTime":1893456000,"zoneHash":"{zero32}","salt":"1","conduitKey":"{zero32}","counter":0}}}}"#
    )
}

fn native_item(wei: &str, recipient: &str) -> String {
    format!(
        r#"{{"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":"0","startAmount":"{wei}","endAmount":"{wei}","recipient":"{recipient}"}}"#
    )
}

fn request(secp: &Secp256k1<All>, w: &Account, json: &str, chain: Option<u64>) -> SignRequest {
    build_request(
        secp,
        w,
        0,
        json.as_bytes().to_vec(),
        DataType::TypedData,
        chain,
        [9; 16],
    )
    .unwrap()
}

fn reviewed(json: &str, chain: Option<u64>) -> Reviewed {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    review(&secp, &s.account, &request(&secp, &w, json, chain)).unwrap()
}

fn row<'a>(r: &'a Reviewed, label: &str) -> &'a str {
    r.display
        .rows
        .iter()
        .find(|x| x.label == label)
        .map(|x| x.value.as_str())
        .unwrap_or_else(|| panic!("缺少 {label}：{:#?}", r.display.rows))
}

fn has_warning(r: &Reviewed, level: Level, text: &str) -> bool {
    r.display
        .warnings
        .iter()
        .any(|w| w.level == level && w.text.contains(text))
}

#[test]
fn permit_roundtrip_over_animated_qr() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let json = permit_json(1, "1000000");
    let req = request(&secp, &w, &json, Some(1));
    // 观察机 → 签名机：多帧动画二维码，每 3 帧丢 1 帧
    let mut enc = UrEncoder::new(encode_request(&req).unwrap(), 120, 0, 10).unwrap();
    let mut dec = UrDecoder::new();
    for frame in 1..=10_000 {
        let part = enc.next_part().to_uppercase();
        if frame % 3 != 0 {
            dec.receive(&part).unwrap();
        }
        if dec.result().is_some() {
            break;
        }
    }
    let got = decode_request(&dec.result().unwrap().clone().unwrap()).unwrap();
    assert_eq!(got, req);
    let (r, sig) = sign(&secp, &s, &got).unwrap();
    assert_eq!(r.display.title, "代币 Permit 授权（EIP-2612，链下签名）");
    assert_eq!(r.display.chain, "Ethereum");
    assert_eq!(row(&r, "授权额度"), "1 USDC");
    assert_eq!(
        row(&r, "被授权方（spender）"),
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    );
    assert!(row(&r, "签名有效期至").starts_with("2030-01-01 00:00 UTC"));
    assert_eq!(
        row(&r, "应用名称（对方自称，不能作为信任依据）"),
        "\"USD Coin\""
    );
    assert_eq!(row(&r, "字段 value（uint256）"), "1000000");
    assert!(r.display.has_danger());
    // 签名哈希就是 EIP-712 摘要；v 为 27/28
    assert_eq!(
        r.hash,
        TypedData::parse(&json).unwrap().digest().unwrap().hash
    );
    assert!([27, 28].contains(&sig.signature[64]));
    // 签名机 → 观察机：观察机从签名恢复出本地址
    let sig = decode_signature(&encode_signature(&sig).unwrap()).unwrap();
    assert_eq!(finalize(&secp, &w, &req, &sig).unwrap(), sig.signature);
    // 用同一签名冒充另一份结构化数据：恢复出的地址不符
    let other = request(&secp, &w, &permit_json(1, "2000000"), Some(1));
    assert_eq!(
        finalize(&secp, &w, &other, &sig),
        Err(EvmError::BadSignature)
    );
}

#[test]
fn recognizers_and_warnings() {
    // 无限额 Permit（uint256 最大值）
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let r = reviewed(&permit_json(1, max), Some(1));
    assert!(row(&r, "授权额度").starts_with("无限额或接近无限额"));

    // Permit2 PermitSingle：uint160 最大值即无限额
    let p2 = format!(
        r#"{{"types":{{"EIP712Domain":[{{"name":"name","type":"string"}},{{"name":"chainId","type":"uint256"}},{{"name":"verifyingContract","type":"address"}}],"PermitSingle":[{{"name":"details","type":"PermitDetails"}},{{"name":"spender","type":"address"}},{{"name":"sigDeadline","type":"uint256"}}],"PermitDetails":[{{"name":"token","type":"address"}},{{"name":"amount","type":"uint160"}},{{"name":"expiration","type":"uint48"}},{{"name":"nonce","type":"uint48"}}]}},"primaryType":"PermitSingle","domain":{{"name":"Permit2","chainId":1,"verifyingContract":"0x000000000022d473030f116ddee9f6b43ac78ba3"}},"message":{{"details":{{"token":"{USDC}","amount":"0x{}","expiration":0,"nonce":0}},"spender":"{SPENDER}","sigDeadline":1893456000}}}}"#,
        "f".repeat(40)
    );
    let r = reviewed(&p2, None);
    assert_eq!(r.display.title, "Permit2 授权（PermitSingle）");
    assert!(row(&r, "代币 1").contains("USDC"));
    assert!(row(&r, "代币 1 额度").starts_with("无限额或接近无限额"));
    assert!(row(&r, "代币 1 额度有效期至").contains("只在提交上链的那个区块内有效"));
    assert!(has_warning(&r, Level::Danger, "Permit2"));

    // Seaport 钓鱼挂单：给出 NFT，收款全部付给别人
    let r = reviewed(&seaport_json(&native_item("1", SPENDER)), Some(1));
    assert_eq!(r.display.title, "Seaport 挂单（链下签名）");
    assert!(row(&r, "你给出 1").contains("编号 1234"));
    assert!(row(
        &r,
        "支付给 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed（第 1 项）"
    )
    .contains("0.000000000000000001 ETH"));
    assert!(has_warning(&r, Level::Danger, "什么也收不到"));
    // 正常挂单：自己收到 10 ETH，另付 2.5% 手续费；仍是高风险（需要确认），但没有钓鱼警告
    let both = format!(
        "{},{}",
        native_item("10000000000000000000", OWNER),
        native_item("250000000000000000", SPENDER)
    );
    let r = reviewed(&seaport_json(&both), Some(1));
    assert_eq!(row(&r, "你收到（第 1 项）"), "10 ETH（原生币）");
    assert!(!has_warning(&r, Level::Danger, "什么也收不到"));
    assert!(r.display.has_danger());

    // 无法识别的类型：强警告；字段完整列出
    let domain = r#"{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xcccccccccccccccccccccccccccccccccccccccc"}"#;
    let r = reviewed(&mail_json(domain, DOMAIN4), None);
    assert_eq!(r.display.title, "结构化签名（Mail）");
    assert!(has_warning(&r, Level::Danger, "无法识别"));
    assert_eq!(row(&r, "字段 to.name（string）"), "\"Bob\"");
    assert_eq!(row(&r, "字段 contents（string）"), "\"Hello, Bob!\"");

    // 域里没有链 ID：提醒签名可在任何链上使用
    let r = reviewed(
        &mail_json(
            r#"{"name":"Ether Mail"}"#,
            r#"[{"name":"name","type":"string"}]"#,
        ),
        Some(1),
    );
    assert_eq!(r.display.chain, "EVM");
    assert!(has_warning(&r, Level::Caution, "没有绑定链 ID"));

    // 不能安全显示的字符串：按十六进制显示并提醒
    let r = reviewed(
        &mail_json(
            "{\"name\":\"USD\\u202eCoin\"}",
            r#"[{"name":"name","type":"string"}]"#,
        ),
        None,
    );
    assert!(
        row(&r, "应用名称（对方自称，不能作为信任依据）").starts_with("（含不能安全显示的字符）0x")
    );
    assert!(has_warning(&r, Level::Caution, "不能安全显示"));
}

#[test]
fn signer_rejects_inconsistent_typed_data() {
    let secp = Secp256k1::new();
    let s = signer(&secp);
    let w = watcher_account(&s);
    let reject = |json: &[u8], chain: Option<u64>, want: EvmError| {
        let mut req = request(&secp, &w, "{}", chain);
        req.sign_data = json.to_vec();
        assert_eq!(
            sign(&secp, &s, &req).map(|_| ()),
            Err(want),
            "{}",
            String::from_utf8_lossy(json)
        );
    };
    // 域的链 ID 是以太坊，请求声称是 BNB Smart Chain
    reject(
        permit_json(1, "1").as_bytes(),
        Some(56),
        EvmError::ChainMismatch,
    );
    // 数值超出 uint256、多一个字段、重复键、非 UTF-8、空对象
    let mut too_big = permit_json(1, "1");
    too_big = too_big.replace(
        r#""value":"1""#,
        &format!(r#""value":"{}""#, "9".repeat(80)),
    );
    reject(too_big.as_bytes(), Some(1), EvmError::Parse);
    let extra = permit_json(1, "1").replace(r#""nonce":0,"#, r#""nonce":0,"memo":"x","#);
    reject(extra.as_bytes(), Some(1), EvmError::Parse);
    let dup = permit_json(1, "1").replace(r#""nonce":0,"#, r#""nonce":0,"nonce":1,"#);
    reject(dup.as_bytes(), Some(1), EvmError::Parse);
    reject(&[0xff, 0xfe, b'{', b'}'], Some(1), EvmError::Parse);
    reject(b"{}", Some(1), EvmError::Parse);
    // 地址大小写混合但校验和错误
    let bad_case =
        permit_json(1, "1").replace(SPENDER, "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    reject(bad_case.as_bytes(), Some(1), EvmError::Parse);
}
