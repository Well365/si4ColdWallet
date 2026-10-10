//! 端到端：签名机导出账户 → 观察机导入 → 观察机构造 PSBT → 动画二维码 → 签名机审查并签名
//! → 动画二维码 → 观察机合并签名、提取交易并独立验证签名。
//! 另外模拟"观察机被控制"的各种篡改，确认签名机全部拒签。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use aw_bip39::Mnemonic;
use aw_chain_btc::account_ur::{account_from_hdkey, account_to_hdkey};
use aw_chain_btc::review::{review, OutputKind, Warning};
use aw_chain_btc::sign::{sign_psbt, SigningAccount};
use aw_chain_btc::watch::{build_payment, finalize, Utxo};
use aw_chain_btc::{Account, BtcError};
use aw_ur::registry::{decode_hdkey, decode_psbt, encode_hdkey, encode_psbt, Style};
use aw_ur::ur::{Ur, UrDecoder, UrEncoder};
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::{
    absolute, transaction, Address, Amount, EcdsaSighashType, Network, OutPoint, ScriptBuf,
    Transaction, TxIn, TxOut,
};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP173 测试向量中的测试网 P2WPKH 地址，作为"外部收款人"
const RECIPIENT: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

fn signer(secp: &Secp256k1<All>) -> SigningAccount {
    let seed = Mnemonic::parse(MNEMONIC).unwrap().to_seed("").unwrap();
    let master = aw_keys::master(&seed, Network::Testnet).unwrap();
    SigningAccount::from_master(secp, &master, Network::Testnet, 0).unwrap()
}

/// 模拟摄像头：编码器逐帧输出（转大写，模拟二维码字母数字模式），解码器逐帧接收，
/// 并故意丢掉每 4 帧中的 1 帧。
fn transmit(ur: Ur, max_fragment: usize) -> Ur {
    let mut enc = UrEncoder::new(ur, max_fragment, 0, 10).unwrap();
    let mut dec = UrDecoder::new();
    for frame in 1..=10_000 {
        let part = enc.next_part().to_uppercase();
        if frame % 4 != 0 {
            dec.receive(&part).unwrap();
        }
        if let Some(r) = dec.result() {
            return r.clone().unwrap();
        }
    }
    panic!("动画二维码在 10000 帧内没有解码完成");
}

fn funding_tx(watch: &Account, secp: &Secp256k1<All>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..TxIn::default()
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: watch.script_for(secp, false, 0).unwrap(),
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: watch.script_for(secp, false, 1).unwrap(),
            },
            TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::new_op_return([1u8, 2, 3]),
            },
        ],
    }
}

struct Setup {
    secp: Secp256k1<All>,
    signer: SigningAccount,
    watch: Account,
    psbt: Psbt,
    fee: u64,
    change: u64,
}

fn setup(fee_rate: u64) -> Setup {
    setup_with(120_000, fee_rate)
}

fn setup_with(amount: u64, fee_rate: u64) -> Setup {
    let secp = Secp256k1::new();
    let signer = signer(&secp);

    // 1. 签名机导出账户公钥（旧式 crypto-hdkey，兼容面最广），观察机扫码导入
    let ur = encode_hdkey(&account_to_hdkey(&signer.account), Style::Legacy).unwrap();
    let watch = account_from_hdkey(&decode_hdkey(&transmit(ur, 40)).unwrap()).unwrap();
    assert_eq!(
        watch, signer.account,
        "观察机导入的账户必须与签名机完全一致"
    );

    // 2. 观察机构造付款：12 万聪给外部地址，5 sat/vB，找零到 m/84'/1'/0'/1/0
    let funding = funding_tx(&watch, &secp);
    let utxos = vec![
        Utxo {
            prev_tx: funding.clone(),
            vout: 0,
            change: false,
            index: 0,
        },
        Utxo {
            prev_tx: funding,
            vout: 1,
            change: false,
            index: 1,
        },
    ];
    let to = Address::from_str_checked(RECIPIENT, Network::Testnet);
    let (psbt, summary) = build_payment(&secp, &watch, &utxos, &to, amount, fee_rate, 0).unwrap();
    assert!(summary.inputs >= 1);
    Setup {
        secp,
        signer,
        watch,
        psbt,
        fee: summary.fee,
        change: summary.change.unwrap_or(0),
    }
}

trait AddrExt {
    fn from_str_checked(s: &str, n: Network) -> Address;
}
impl AddrExt for Address {
    fn from_str_checked(s: &str, n: Network) -> Address {
        s.parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap()
            .require_network(n)
            .unwrap()
    }
}

#[test]
fn full_roundtrip_over_animated_qr() {
    let s = setup(5);
    assert_eq!(s.psbt.inputs.len(), 2, "12 万聪需要两个 UTXO");

    // 3. PSBT 经动画二维码送到签名机
    let ur = encode_psbt(&s.psbt.serialize(), Style::Legacy).unwrap();
    let received = decode_psbt(&transmit(ur, 120)).unwrap();
    let mut on_signer = Psbt::deserialize(&received).unwrap();

    // 4. 签名机审查：外部付款、找零、手续费都与观察机构造的一致
    let r = review(&s.secp, &s.signer.account, &on_signer).unwrap();
    assert_eq!(r.external_total, 120_000);
    assert_eq!(r.fee, s.fee);
    assert_eq!(r.outputs[0].address, RECIPIENT);
    assert_eq!(r.outputs[0].kind, OutputKind::External);
    assert_eq!(r.outputs[1].kind, OutputKind::Change(0));
    assert_eq!(r.outputs[1].amount, s.change);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert!(r.rbf);
    assert!(r.to_json().to_string_compact().contains(RECIPIENT));

    // 5. 签名，经动画二维码送回观察机
    sign_psbt(&s.secp, &s.signer, &mut on_signer).unwrap();
    let back = decode_psbt(&transmit(
        encode_psbt(&on_signer.serialize(), Style::V2).unwrap(),
        120,
    ))
    .unwrap();

    // 6. 观察机合并、提取，并在测试里再独立验证一遍每个输入
    let tx = finalize(&s.secp, &s.watch, &s.psbt, &back).unwrap();
    assert_eq!(tx.input.len(), 2);
    let mut cache = SighashCache::new(&tx);
    for (i, input) in tx.input.iter().enumerate() {
        let prev = s.psbt.inputs[i].witness_utxo.as_ref().unwrap();
        let w: Vec<&[u8]> = input.witness.iter().collect();
        assert_eq!(w.len(), 2);
        let pk = bitcoin::secp256k1::PublicKey::from_slice(w[1]).unwrap();
        let compressed = bitcoin::CompressedPublicKey(pk);
        assert_eq!(
            ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash()),
            prev.script_pubkey,
            "公钥哈希与输出脚本不符"
        );
        let sig = bitcoin::ecdsa::Signature::from_slice(w[0]).unwrap();
        assert_eq!(sig.sighash_type, EcdsaSighashType::All);
        let h = cache
            .p2wpkh_signature_hash(i, &prev.script_pubkey, prev.value, EcdsaSighashType::All)
            .unwrap();
        s.secp
            .verify_ecdsa(
                &Message::from_digest(h.to_byte_array()),
                &sig.signature,
                &pk,
            )
            .unwrap();
    }
    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(150_000 - total_out, s.fee);
}

/// RFC6979：同一笔交易在两台独立设备上应得到逐字节相同的签名（威胁 T7 的比对手段）
#[test]
fn signatures_are_deterministic_across_devices() {
    let s = setup(5);
    let mut a = s.psbt.clone();
    let mut b = s.psbt.clone();
    sign_psbt(&s.secp, &s.signer, &mut a).unwrap();
    let other_device = signer(&Secp256k1::new());
    sign_psbt(&s.secp, &other_device, &mut b).unwrap();
    assert_eq!(a.serialize(), b.serialize());
}

fn signer_rejects(mutate: impl FnOnce(&mut Psbt), expected: BtcError) {
    let s = setup(5);
    let mut p = s.psbt.clone();
    mutate(&mut p);
    let wire = Psbt::deserialize(&p.serialize()).unwrap();
    assert_eq!(
        review(&s.secp, &s.signer.account, &wire).unwrap_err(),
        expected
    );
    let mut wire2 = wire.clone();
    assert_eq!(
        sign_psbt(&s.secp, &s.signer, &mut wire2).unwrap_err(),
        expected
    );
}

#[test]
fn rejects_change_output_swapped_to_attacker() {
    signer_rejects(
        |p| {
            p.unsigned_tx.output[1].script_pubkey =
                ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros())
        },
        BtcError::ChangeMismatch(1),
    );
}

#[test]
fn rejects_missing_previous_transaction() {
    signer_rejects(
        |p| p.inputs[0].non_witness_utxo = None,
        BtcError::MissingPrevTx(0),
    );
}

#[test]
fn rejects_substituted_previous_transaction() {
    signer_rejects(
        |p| {
            let mut fake = p.inputs[0].non_witness_utxo.clone().unwrap();
            fake.output[0].value = Amount::from_sat(10_000_000);
            p.inputs[0].non_witness_utxo = Some(fake);
        },
        BtcError::PrevTxMismatch(0),
    );
}

#[test]
fn rejects_inflated_witness_utxo_amount() {
    signer_rejects(
        |p| p.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_sat(5_000_000),
        BtcError::WitnessUtxoMismatch(1),
    );
}

#[test]
fn rejects_non_all_sighash() {
    signer_rejects(
        |p| {
            p.inputs[0].sighash_type =
                Some(PsbtSighashType::from_u32(EcdsaSighashType::None as u32))
        },
        BtcError::SighashNotAll(0),
    );
}

#[test]
fn rejects_input_claimed_by_other_wallet() {
    signer_rejects(
        |p| {
            let (pk, (_, path)) = p.inputs[0]
                .bip32_derivation
                .iter()
                .next()
                .map(|(k, v)| (*k, v.clone()))
                .unwrap();
            p.inputs[0]
                .bip32_derivation
                .insert(pk, (bitcoin::bip32::Fingerprint::from([1, 2, 3, 4]), path));
        },
        BtcError::ForeignInput(0),
    );
}

#[test]
fn watcher_rejects_signer_that_changes_the_transaction() {
    let s = setup(5);
    let mut p = s.psbt.clone();
    sign_psbt(&s.secp, &s.signer, &mut p).unwrap();
    p.unsigned_tx.output[0].value = Amount::from_sat(119_000);
    assert_eq!(
        finalize(&s.secp, &s.watch, &s.psbt, &p.serialize()).unwrap_err(),
        BtcError::TxChanged
    );
}

#[test]
fn watcher_rejects_invalid_signature() {
    let s = setup(5);
    let mut p = s.psbt.clone();
    sign_psbt(&s.secp, &s.signer, &mut p).unwrap();
    let (k, sig) = p.inputs[1]
        .partial_sigs
        .iter()
        .next()
        .map(|(k, v)| (*k, *v))
        .unwrap();
    let mut other = s.psbt.clone();
    sign_psbt(&s.secp, &s.signer, &mut other).unwrap();
    // 把输入 0 的签名放到输入 1 的公钥下：签名有效但对应的消息不同
    let wrong = *other.inputs[0].partial_sigs.values().next().unwrap();
    p.inputs[1].partial_sigs.insert(k, wrong);
    assert_ne!(sig, wrong);
    assert_eq!(
        finalize(&s.secp, &s.watch, &s.psbt, &p.serialize()).unwrap_err(),
        BtcError::BadSignature(1)
    );
}

#[test]
fn absurd_fee_rate_is_flagged() {
    let s = setup_with(10_000, 600);
    let r = review(&s.secp, &s.signer.account, &s.psbt).unwrap();
    assert!(
        r.warnings.contains(&Warning::HighFeeRate),
        "{:?}",
        r.warnings
    );
}
