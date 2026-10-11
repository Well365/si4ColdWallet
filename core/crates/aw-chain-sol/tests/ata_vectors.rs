//! 差分测试：60 组关联代币账户（含 Token-2022）由独立的 Python 实现（tools/testvectors/sol_ata.py，
//! 自己做 Ed25519 点解压）推导，Rust 结果必须逐条一致（地址与 bump）。
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use aw_chain_sol::programs::{associated_token_account, find_program_address, ATA};

fn h32(s: &str) -> [u8; 32] {
    aw_common::hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn ata_matches_independent_python_derivation() {
    let mut n = 0;
    for line in include_str!("vectors/ata.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (owner, mint, prog, ata) = (h32(f[0]), h32(f[1]), h32(f[2]), h32(f[3]));
        let bump: u8 = f[4].parse().unwrap();
        assert_eq!(
            associated_token_account(&owner, &mint, &prog),
            Some(ata),
            "{line}"
        );
        assert_eq!(
            find_program_address(&[&owner, &prog, &mint], &ATA),
            Some((ata, bump))
        );
        n += 1;
    }
    assert_eq!(n, 60);
}

/// 真实主网的关联代币账户（21 个，来自真实交易的 postTokenBalances：钱包、mint、代币程序 → 账户地址）
#[test]
fn real_mainnet_atas() {
    let mut n = 0;
    for line in include_str!("vectors/real_atas.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(
            associated_token_account(&h32(f[0]), &h32(f[1]), &h32(f[2])),
            Some(h32(f[3])),
            "{line}"
        );
        n += 1;
    }
    assert_eq!(n, 21);
}

/// "是否在曲线上"与 Solana（curve25519-dalek decompress）语义一致：含 y ≥ p 的非规范值与两种符号位
#[test]
fn on_curve_matches_dalek_semantics() {
    for line in include_str!("vectors/curve.txt").lines() {
        let (hex, want) = line.split_once(' ').unwrap();
        assert_eq!(
            aw_chain_sol::programs::is_on_curve(&h32(hex)),
            want == "1",
            "{hex}"
        );
    }
}
