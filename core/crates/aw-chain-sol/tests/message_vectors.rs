//! 差分测试：600 条消息（300 条随机合法 + 300 条随机损坏）由独立的 Python 实现
//! （tools/testvectors/sol_message.py，只用标准库）解析，结果必须与 Rust 逐条一致。
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use aw_chain_sol::message::{Message, Version};

fn summary(m: &Message) -> String {
    let v = match m.version {
        Version::Legacy => "legacy",
        Version::V0 => "v0",
    };
    let ix: Vec<String> = m
        .instructions
        .iter()
        .map(|i| {
            let a: Vec<String> = i.accounts.iter().map(u8::to_string).collect();
            format!(
                "{}:{}:{}",
                i.program,
                a.join(","),
                aw_common::hex::encode(&i.data)
            )
        })
        .collect();
    let lk: Vec<String> = m
        .lookups
        .iter()
        .map(|l| {
            format!(
                "{:02x}:{}:{}",
                l.table[0],
                l.writable.len(),
                l.readonly.len()
            )
        })
        .collect();
    format!(
        "{v}|{}|{}|{}|{}|{}|{}",
        m.required_signatures,
        m.readonly_signed,
        m.readonly_unsigned,
        m.account_keys.len(),
        ix.join(";"),
        lk.join(";")
    )
}

#[test]
fn rust_parser_matches_independent_python_parser() {
    let text = include_str!("vectors/messages.txt");
    let mut n = 0;
    for line in text.lines() {
        let (hex, want) = line.split_once(' ').unwrap();
        let bytes = aw_common::hex::decode(hex).unwrap();
        let got = Message::parse(&bytes).map_or_else(|_| "REJECT".to_owned(), |m| summary(&m));
        assert_eq!(got, want, "{hex}");
        n += 1;
    }
    assert_eq!(n, 600);
}

/// 真实主网交易（2026-10-11 从 USDC 相关交易取的 8 笔，legacy 与 v0 都有）：解析结果必须与节点 JSON 一致
#[test]
fn real_mainnet_transactions_parse_like_the_node() {
    let mut n = 0;
    for line in include_str!("vectors/real_messages.txt").lines() {
        let (hex, want) = line.split_once(' ').unwrap();
        let bytes = aw_common::hex::decode(hex).unwrap();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(summary(&m), want, "{hex}");
        n += 1;
    }
    assert_eq!(n, 8);
}
