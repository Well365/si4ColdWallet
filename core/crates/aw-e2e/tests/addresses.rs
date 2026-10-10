//! 各链地址：同一测试助记词派生的地址，必须与 tools/testvectors/chain_addresses.py（纯 Python 独立实现，
//! 与 Rust 没有共享代码）的输出逐字一致。该助记词的 BTC / ETH / DOGE / TRON / SOL 地址也与社区通用钱包一致。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use aw_bip39::Mnemonic;
use aw_keys::slip10::Ed25519Node;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn path(p: &[(u32, bool)]) -> DerivationPath {
    DerivationPath::from(
        p.iter()
            .map(|&(i, h)| {
                if h {
                    ChildNumber::from_hardened_idx(i).unwrap()
                } else {
                    ChildNumber::from_normal_idx(i).unwrap()
                }
            })
            .collect::<Vec<_>>(),
    )
}

#[test]
fn addresses_match_independent_python_implementation() {
    let secp = Secp256k1::new();
    let seed = Mnemonic::parse(MNEMONIC).unwrap().to_seed("").unwrap();
    let master = aw_keys::master(&seed, Network::Bitcoin).unwrap();
    let pk = |p: &[(u32, bool)]| {
        bitcoin::bip32::Xpub::from_priv(&secp, master.derive(&secp, &path(p)).unwrap().expose())
            .public_key
    };

    // DOGE m/44'/3'/0'/0/i，测试网 m/44'/1'/0'/0/0
    assert_eq!(
        aw_chain_btc::doge::address(
            &pk(&[(44, true), (3, true), (0, true), (0, false), (0, false)]),
            false
        ),
        "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"
    );
    assert_eq!(
        aw_chain_btc::doge::address(
            &pk(&[(44, true), (3, true), (0, true), (0, false), (1, false)]),
            false
        ),
        "DAcDAtJRztxBHyA6D6h8du1HguyTR43Mas"
    );
    assert_eq!(
        aw_chain_btc::doge::address(
            &pk(&[(44, true), (1, true), (0, true), (0, false), (0, false)]),
            true
        ),
        "nZVmfmUtKPmskB9Ds4P9GUJy9eYFqPKHqH"
    );
    // TRON m/44'/195'/0'/0/i
    assert_eq!(
        aw_chain_tron::address(&pk(&[
            (44, true),
            (195, true),
            (0, true),
            (0, false),
            (0, false)
        ])),
        "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"
    );
    assert_eq!(
        aw_chain_tron::address(&pk(&[
            (44, true),
            (195, true),
            (0, true),
            (0, false),
            (1, false)
        ])),
        "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK"
    );

    // Ed25519（SLIP-10）
    let ed = Ed25519Node::master(&seed);
    let sol = |i| {
        aw_chain_sol::address(
            &ed.derive(&aw_chain_sol::account_path(i))
                .unwrap()
                .public_key()
                .unwrap(),
        )
    };
    assert_eq!(sol(0), "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
    assert_eq!(sol(1), "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb");
    // D34：Ledger Live 的两种 Solana 方案 m/44'/501'/i'（solanaSub）与 m/44'/501'（solanaMain）
    let sol_scheme = |s: aw_chain_sol::Scheme, i| {
        aw_chain_sol::address(&ed.derive(&s.account_path(i)).unwrap().public_key().unwrap())
    };
    assert_eq!(
        sol_scheme(aw_chain_sol::Scheme::Phantom, 0),
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
    assert_eq!(
        sol_scheme(aw_chain_sol::Scheme::LedgerLive, 0),
        "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL"
    );
    assert_eq!(
        sol_scheme(aw_chain_sol::Scheme::LedgerLive, 1),
        "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi"
    );
    assert_eq!(
        sol_scheme(aw_chain_sol::Scheme::LedgerMain, 0),
        "D2PPQSYFe83nDzk96FqGumVU8JA7J8vj2Rhjc2oXzEi5"
    );
    let near = |i| {
        ed.derive(&aw_chain_near::account_path(i))
            .unwrap()
            .public_key()
            .unwrap()
    };
    assert_eq!(
        aw_chain_near::implicit_account(&near(0)),
        "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412"
    );
    assert_eq!(
        aw_chain_near::public_key_text(&near(0)),
        "ed25519:6j4b6zUaty6fD1awqcGCCU9JYGCWYUgdJhQrzfZhqE25"
    );
    assert_eq!(
        aw_chain_near::implicit_account(&near(1)),
        "3b93b03253b9715213ec314eb50ecc99d25602ccb5b059f91f51d24710d54326"
    );
}
