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
