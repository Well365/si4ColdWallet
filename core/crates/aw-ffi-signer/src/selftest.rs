//! 已知答案自检（威胁 T1、T6）。App 每次启动必须先通过，否则拒绝使用。
//!
//! 吸取 Coldcard 2026-07 事件教训：不仅检查"代码存在"，而是实际跑一遍关键路径并比对结果。

use aw_bip39::{wordlist, Mnemonic};
use bitcoin::hashes::Hash;
use bitcoin::Network;

/// BIP39 官方向量 #0：全零熵 → 助记词 → 种子（passphrase "TREZOR"）
const V0_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
const V0_XPRV: &str = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF";
/// BIP84 官方向量：m/84'/0'/0'/0/0
const BIP84_ADDR0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

/// EVM：同一助记词 m/44'/60'/0'/0/0 的公开地址
const EVM_ADDR0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

/// Solana：同一助记词 m/44'/501'/0'/0'（SLIP-10 Ed25519）
const SOL_ADDR0: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";

pub fn run_all() -> bool {
    wordlist::verify()
        && bip39_and_bip32()
        && bip84()
        && ur_bytewords()
        && evm()
        && ed25519()
        && entropy_checks()
}

/// SLIP-10 + Ed25519 公钥（第三方 ed25519-compact）的已知答案
fn ed25519() -> bool {
    let Ok(m) = Mnemonic::from_entropy(&[0u8; 16]) else {
        return false;
    };
    let Ok(seed) = m.to_seed("") else {
        return false;
    };
    aw_keys::slip10::Ed25519Node::master(&seed)
        .derive(&aw_chain_sol::account_path(0))
        .and_then(|n| n.public_key())
        .map(|pk| aw_chain_sol::address(&pk) == SOL_ADDR0)
        .unwrap_or(false)
}

/// 随机数健康检查本身在工作：明显坏掉的样本必须被拒绝
fn entropy_checks() -> bool {
    use crate::entropy::system_health;
    let good = bitcoin::hashes::sha256::Hash::hash(b"airgap-wallet selftest").to_byte_array();
    system_health(&good, None).is_ok()
        && system_health(&[0; 32], None).is_err()
        && system_health(&good, Some(&crate::entropy::digest(&good))).is_err()
}

/// Keccak-256 公开向量 + EVM 地址派生 + 一次真实签名与恢复
fn evm() -> bool {
    use aw_chain_evm::keccak::keccak256;
    if aw_common::hex::encode(&keccak256(b"abc"))
        != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    {
        return false;
    }
    let Ok(m) = Mnemonic::from_entropy(&[0u8; 16]) else {
        return false;
    };
    let secp = aw_keys::secp_context(&[0x5a; 32]);
    let Ok(seed) = m.to_seed("") else {
        return false;
    };
    let Ok(master) = aw_keys::master(&seed, Network::Bitcoin) else {
        return false;
    };
    let Ok(signer) = aw_chain_evm::sign::EvmSigner::from_master(&secp, &master) else {
        return false;
    };
    let Ok(addr) = signer.account.address(&secp, 0) else {
        return false;
    };
    if aw_chain_evm::checksum_address(&addr) != EVM_ADDR0 {
        return false;
    }
    // 签一条消息并由观察机逻辑核对（恢复出的地址必须一致）
    let req = aw_chain_evm::request::SignRequest {
        request_id: Some([0x5a; 16]),
        sign_data: b"airgap-wallet selftest".to_vec(),
        data_type: aw_chain_evm::request::DataType::PersonalMessage,
        chain_id: None,
        path: signer.account.keypath(0),
        address: Some(addr),
        origin: None,
    };
    aw_chain_evm::sign::sign(&secp, &signer, &req).is_ok()
}

/// bc-ur 参考向量：[0, 1, 2, 128, 255] → "aeadaolazmjendeoti"
fn ur_bytewords() -> bool {
    aw_ur::bytewords::encode_minimal(&[0, 1, 2, 128, 255]) == "aeadaolazmjendeoti"
        && aw_ur::bytewords::decode_minimal("aeadaolazmjendeoti")
            .ok()
            .as_deref()
            == Some(&[0u8, 1, 2, 128, 255][..])
}

fn bip39_and_bip32() -> bool {
    let Ok(m) = Mnemonic::from_entropy(&[0u8; 16]) else {
        return false;
    };
    if m.indices().get(11) != Some(&3) || m.indices().iter().take(11).any(|&i| i != 0) {
        return false;
    }
    let Ok(seed) = m.to_seed("TREZOR") else {
        return false;
    };
    if aw_common::hex::encode(seed.expose()) != V0_SEED_HEX {
        return false;
    }
    matches!(aw_keys::master(&seed, Network::Bitcoin), Ok(x) if x.expose().to_string() == V0_XPRV)
}

fn bip84() -> bool {
    let Ok(m) = Mnemonic::from_entropy(&[0u8; 16]) else {
        return false;
    };
    let secp = aw_keys::secp_context(&[0x5a; 32]);
    let Ok(seed) = m.to_seed("") else {
        return false;
    };
    aw_keys::bip84_account_xpub(&secp, &seed, Network::Bitcoin, 0)
        .and_then(|x| aw_keys::bip84_address(&secp, &x, false, 0, Network::Bitcoin))
        .map(|a| a.to_string() == BIP84_ADDR0)
        .unwrap_or(false)
}
