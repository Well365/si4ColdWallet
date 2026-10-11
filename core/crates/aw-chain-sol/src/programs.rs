//! 已知程序与代币、程序派生地址（PDA）与关联代币账户（ATA），以及观察机构造交易用的指令（P2c-T2）。
//!
//! 程序地址以字节常量保存，单元测试逐个与 Base58 文本核对。

use crate::message::encode_shortvec;
use bitcoin_hashes::{sha256, Hash, HashEngine};

pub const SYSTEM: [u8; 32] = [0; 32];
pub const TOKEN: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];
pub const TOKEN_2022: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];
pub const ATA: [u8; 32] = [
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
];
pub const COMPUTE_BUDGET: [u8; 32] = [
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
];
pub const MEMO: [u8; 32] = [
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d,
];
pub const SYSVAR_RECENT_BLOCKHASHES: [u8; 32] = [
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e, 0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
    0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3, 0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
];

/// 签名校验预编译程序：每条指令里的签名数各收 5000 lamports 手续费
pub const SIG_PRECOMPILES: [[u8; 32]; 3] = [
    // Ed25519SigVerify111111111111111111111111111
    [
        0x03, 0x7d, 0x46, 0xd6, 0x7c, 0x93, 0xfb, 0xbe, 0x12, 0xf9, 0x42, 0x8f, 0x83, 0x8d, 0x40,
        0xff, 0x05, 0x70, 0x74, 0x49, 0x27, 0xf4, 0x8a, 0x64, 0xfc, 0xca, 0x70, 0x44, 0x80, 0x00,
        0x00, 0x00,
    ],
    // KeccakSecp256k11111111111111111111111111111
    [
        0x04, 0xc6, 0xfc, 0x20, 0xf0, 0x50, 0xcc, 0xf0, 0x55, 0x84, 0xd7, 0x21, 0x1c, 0x9f, 0x8c,
        0xf5, 0x9e, 0xc1, 0x47, 0x85, 0xbb, 0x16, 0x6a, 0x1e, 0x28, 0x30, 0xe8, 0x12, 0x20, 0x00,
        0x00, 0x00,
    ],
    // Secp256r1SigVerify1111111111111111111111111
    [
        0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5, 0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9,
        0x03, 0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56, 0x8e, 0x75, 0x47, 0x80, 0x20, 0x00,
        0x00, 0x00,
    ],
];

/// 主网上的已知代币（mint 地址、符号、小数位）
pub struct KnownToken {
    pub mint: [u8; 32],
    pub symbol: &'static str,
    pub decimals: u8,
}

pub const KNOWN_TOKENS: [KnownToken; 2] = [
    KnownToken {
        mint: [
            0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9,
            0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03,
            0x45, 0x2f, 0x5d, 0x61,
        ],
        symbol: "USDC",
        decimals: 6,
    },
    KnownToken {
        mint: [
            0xce, 0x01, 0x0e, 0x60, 0xaf, 0xed, 0xb2, 0x27, 0x17, 0xbd, 0x63, 0x19, 0x2f, 0x54,
            0x14, 0x5a, 0x3f, 0x96, 0x5a, 0x33, 0xbb, 0x82, 0xd2, 0xc7, 0x02, 0x9e, 0xb2, 0xce,
            0x1e, 0x20, 0x82, 0x7c,
        ],
        symbol: "USDT",
        decimals: 6,
    },
];

pub fn known_token(mint: &[u8; 32]) -> Option<&'static KnownToken> {
    KNOWN_TOKENS.iter().find(|t| t.mint == *mint)
}

/// 32 字节是否是 Ed25519 曲线上的点，语义与 Solana（curve25519-dalek 的 `decompress`）一致：
/// 忽略符号位、y 按模 p 取值。先把输入规范化（清符号位、y ≥ p 时减 p），再借用 ed25519-compact 的公开校验：
/// 签名标量为 0（规范）时，只有公钥解不出曲线点才会返回 `InvalidPublicKey`
/// （恒等元与全零也是曲线上的点，返回 `WeakPublicKey`）。规范化后，ed25519-compact 拒绝"非规范 y"
/// 与"x = 0 且符号位为 1"这两条额外规则不再起作用。
pub fn is_on_curve(bytes: &[u8; 32]) -> bool {
    let mut y = *bytes;
    if let Some(last) = y.last_mut() {
        *last &= 0x7f;
    }
    // y ≥ p = 2^255 − 19：只可能是 0x7fff…ff 结尾、首字节 ≥ 0xed 的 19 个值，减去 p 后只剩首字节
    let high_ones =
        y.get(1..31).is_some_and(|s| s.iter().all(|&b| b == 0xff)) && y.get(31) == Some(&0x7f);
    if let Some(first) = y.first().copied().filter(|&b| high_ones && b >= 0xed) {
        y = [0u8; 32];
        if let Some(f) = y.first_mut() {
            *f = first - 0xed;
        }
    }
    let pk = ed25519_compact::PublicKey::new(y);
    let zero = ed25519_compact::Signature::new([0u8; 64]);
    !matches!(
        pk.verify_incremental(&zero),
        Err(ed25519_compact::Error::InvalidPublicKey)
    )
}

/// find_program_address：bump 从 255 往下，第一个不在曲线上的 SHA-256(种子… ‖ bump ‖ 程序 ‖ "ProgramDerivedAddress")
pub fn find_program_address(seeds: &[&[u8]], program: &[u8; 32]) -> Option<([u8; 32], u8)> {
    (0..=255u8).rev().find_map(|bump| {
        let mut e = sha256::HashEngine::default();
        for s in seeds {
            e.input(s);
        }
        e.input(&[bump]);
        e.input(program);
        e.input(b"ProgramDerivedAddress");
        let h = sha256::Hash::from_engine(e).to_byte_array();
        (!is_on_curve(&h)).then_some((h, bump))
    })
}

/// 关联代币账户：PDA(钱包, 代币程序, mint) 于 ATA 程序之下
pub fn associated_token_account(
    owner: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
) -> Option<[u8; 32]> {
    find_program_address(&[owner, token_program, mint], &ATA).map(|(a, _)| a)
}

/// 指令中的一个账户：地址、是否签名、是否可写
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountMeta {
    pub key: [u8; 32],
    pub signer: bool,
    pub writable: bool,
}

impl AccountMeta {
    pub fn new(key: [u8; 32], signer: bool, writable: bool) -> Self {
        Self {
            key,
            signer,
            writable,
        }
    }
}

/// 未编译的指令
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ix {
    pub program: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

pub fn system_transfer(from: &[u8; 32], to: &[u8; 32], lamports: u64) -> Ix {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Ix {
        program: SYSTEM,
        accounts: vec![
            AccountMeta::new(*from, true, true),
            AccountMeta::new(*to, false, true),
        ],
        data,
    }
}

pub fn compute_unit_limit(units: u32) -> Ix {
    let mut data = vec![2];
    data.extend_from_slice(&units.to_le_bytes());
    Ix {
        program: COMPUTE_BUDGET,
        accounts: vec![],
        data,
    }
}

pub fn compute_unit_price(micro_lamports: u64) -> Ix {
    let mut data = vec![3];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Ix {
        program: COMPUTE_BUDGET,
        accounts: vec![],
        data,
    }
}

/// 按需创建收款方的关联代币账户（已存在时什么也不做）。观察机发代币时总是带上这一条，
/// 签名机才能从中核对"收款代币账户确实属于显示的收款人"（决策 D37）
pub fn create_ata_idempotent(
    payer: &[u8; 32],
    ata: &[u8; 32],
    owner: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
) -> Ix {
    Ix {
        program: ATA,
        accounts: vec![
            AccountMeta::new(*payer, true, true),
            AccountMeta::new(*ata, false, true),
            AccountMeta::new(*owner, false, false),
            AccountMeta::new(*mint, false, false),
            AccountMeta::new(SYSTEM, false, false),
            AccountMeta::new(*token_program, false, false),
        ],
        data: vec![1],
    }
}

pub fn token_transfer_checked(
    token_program: &[u8; 32],
    source: &[u8; 32],
    mint: &[u8; 32],
    dest: &[u8; 32],
    owner: &[u8; 32],
    amount: u64,
    decimals: u8,
) -> Ix {
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Ix {
        program: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false, true),
            AccountMeta::new(*mint, false, false),
            AccountMeta::new(*dest, false, true),
            AccountMeta::new(*owner, true, false),
        ],
        data,
    }
}

/// 把指令编译成 legacy 消息。账户表顺序与 Solana 相同：付款人、其余可写签名者、只读签名者、
/// 可写非签名者、只读非签名者（同一账户多次出现时权限取并集）；程序账户为只读非签名者
pub fn compile_legacy(payer: &[u8; 32], ixs: &[Ix], blockhash: &[u8; 32]) -> Option<Vec<u8>> {
    let mut metas: Vec<AccountMeta> = vec![AccountMeta::new(*payer, true, true)];
    let mut add = |m: AccountMeta| match metas.iter_mut().find(|x| x.key == m.key) {
        Some(x) => {
            x.signer |= m.signer;
            x.writable |= m.writable;
        }
        None => metas.push(m),
    };
    for ix in ixs {
        for a in &ix.accounts {
            add(*a);
        }
        add(AccountMeta::new(ix.program, false, false));
    }
    let rank = |m: &AccountMeta| match (m.signer, m.writable) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    let payer_meta = *metas.first()?;
    let mut rest: Vec<AccountMeta> = metas.into_iter().skip(1).collect();
    rest.sort_by_key(rank);
    let keys: Vec<AccountMeta> = core::iter::once(payer_meta).chain(rest).collect();
    let req = keys.iter().filter(|m| m.signer).count();
    let ro_signed = keys.iter().filter(|m| m.signer && !m.writable).count();
    let ro_unsigned = keys.iter().filter(|m| !m.signer && !m.writable).count();
    let mut out = vec![
        u8::try_from(req).ok()?,
        u8::try_from(ro_signed).ok()?,
        u8::try_from(ro_unsigned).ok()?,
    ];
    encode_shortvec(&mut out, u16::try_from(keys.len()).ok()?);
    for k in &keys {
        out.extend_from_slice(&k.key);
    }
    out.extend_from_slice(blockhash);
    encode_shortvec(&mut out, u16::try_from(ixs.len()).ok()?);
    let index = |key: &[u8; 32]| {
        keys.iter()
            .position(|m| m.key == *key)
            .and_then(|i| u8::try_from(i).ok())
    };
    for ix in ixs {
        out.push(index(&ix.program)?);
        encode_shortvec(&mut out, u16::try_from(ix.accounts.len()).ok()?);
        for a in &ix.accounts {
            out.push(index(&a.key)?);
        }
        encode_shortvec(&mut out, u16::try_from(ix.data.len()).ok()?);
        out.extend_from_slice(&ix.data);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::message::Message;

    #[test]
    fn program_constants_match_base58() {
        for (k, s) in [
            (TOKEN, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            (TOKEN_2022, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
            (ATA, "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
            (
                COMPUTE_BUDGET,
                "ComputeBudget111111111111111111111111111111",
            ),
            (MEMO, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
            (
                SYSVAR_RECENT_BLOCKHASHES,
                "SysvarRecentB1ockHashes11111111111111111111",
            ),
            (
                KNOWN_TOKENS[0].mint,
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            ),
            (
                KNOWN_TOKENS[1].mint,
                "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYb",
            ),
        ] {
            assert_eq!(crate::address(&k), s);
        }
        assert_eq!(crate::address(&SYSTEM), "11111111111111111111111111111111");
    }

    #[test]
    fn curve_check() {
        // 基点 B（y = 4/5）在曲线上；把 y 设为 2 不在曲线上（2 不满足 x² 有解，见 Python 向量）
        let mut base = [0x66u8; 32];
        base[0] = 0x58;
        assert!(is_on_curve(&base));
        assert!(is_on_curve(&[0u8; 32]));
        let mut two = [0u8; 32];
        two[0] = 2;
        assert!(!is_on_curve(&two));
    }

    #[test]
    fn compiled_transfer_parses_back() {
        let from = [0x11; 32];
        let to = [0x22; 32];
        let ixs = [
            compute_unit_limit(300),
            compute_unit_price(7),
            system_transfer(&from, &to, 5),
        ];
        let bytes = compile_legacy(&from, &ixs, &[0x33; 32]).unwrap();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.account_keys[0], from);
        assert_eq!(m.required_signatures, 1);
        assert_eq!(m.readonly_unsigned, 2); // System 与 ComputeBudget
        assert_eq!(m.instructions.len(), 3);
        assert_eq!(m.key(m.instructions[2].program), Some(&SYSTEM));
    }
}
