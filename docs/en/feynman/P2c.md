> English translation of docs/feynman/P2c.md. The Chinese original is authoritative.

# P2c Feynman report: Solana can now be signed offline too

Date: 2026-10-11 · Status: code complete, all tests pass, both apps compile; an actual send between the phones needs devnet test coins (see Section 7)

## 1. In one sentence

The offline Signer can now read a Solana transaction, explain it item by item and then sign it; the online Watcher builds the transaction, fetches fees and broadcasts it.

## 2. Explained to a layperson

A Solana transaction is like an "operations list": first every account involved, then instructions one by one ("send 1 SOL from A to B", "create a token account", "send 5 USDC"). Signing means putting your fingerprint on the whole list.

The danger is not "transfer" but whatever else is slipped into the list:
- **changing an account's owner program** (System Assign) hands your account to someone else's program — the Signer refuses;
- **handing over token control** (SetAuthority) — refused;
- **address lookup tables**: the list only says "address number N", the real address lives on chain and cannot be checked offline — refused;
- **approvals, closing token accounts, unknown programs** — red warnings that must be confirmed.

A subtler problem: tokens are not sent to a "wallet address" but to the recipient's "token account". How does the Signer know that token account really belongs to the person you are paying? The Watcher adds "create the recipient's token account if missing", which names the wallet and the token; the Signer redoes the public derivation itself and only shows "recipient (ownership verified)" when it matches.

## 3. What was actually done

| Deliverable | Location | Notes |
|---|---|---|
| Message parsing | `core/crates/aw-chain-sol/src/message.rs` | legacy and v0, strict checks |
| Programs and ATA derivation | `programs.rs` | known programs, USDC / USDT, PDA |
| Review | `review.rs` | refusal and warning rules, fees, recipient verification |
| Sign request and signature | `request.rs`, `sign.rs`, `watch.rs` | `sol-sign-request` / `sol-signature`, three path schemes |
| C interface | `aw-ffi-signer`, `aw-ffi-watch/src/sol.rs` | error-code range -400 |
| Watcher UI | `ios/Watcher/Watcher/Sol*.swift` | import, balances, nodes, priority tiers, send, broadcast |
| Independent implementations | `tools/testvectors/sol_message.py`, `sol_ata.py` | Python standard library only |
| Decision | `docs/en/05-decisions.md` D37 | rules and boundaries |

## 4. How we prove it is correct

- All Rust tests pass (measured locally). Solana-specific: the parser matches the independent Python implementation on 600 vectors, ATA derivation on 60, signatures match the RFC 8032 official vectors, the end-to-end flow (Watcher → QR → Signer → QR → Watcher) passes for all three path schemes, and arbitrary truncation / byte mutation never panics.
- C-interface tests: on the Signer side review, signing, refusal without confirmation for high-risk requests, refusal for a wrong account type; on the Watcher side building, verifying and the transaction id.
- Simulator: the Watcher's Solana tab imports an address, verifies the devnet node by genesis hash, fetches the three priority tiers, and shows the correct message when the balance is short.
- Independent review: verdict BLOCK (2 high, 2 medium, 6 low, 17 places where removing a check still passed the tests); everything was fixed with tests, and re-running 6 of those "remove the check" experiments in a copy now fails the tests. Real mainnet data was added: 8 real transactions and 21 real token accounts.
- **Not verified**: an actual send and broadcast between the real devices.

## 5. Knowledge gaps

| Gap | Why unclear | How to close | When |
|---|---|---|---|
| Is the "on curve" test identical to the Solana node's? | 26 extreme values used to differ (not exploitable) | now has the node's semantics, with edge vectors | closed |
| Is the fee formula identical to the node's? | Solana's fee rules keep evolving (e.g. charging by loaded account data size) | send a few transactions on device and compare with the fee shown by the explorer | once test coins are available |

## 6. Compared with the plan

T1–T5 of `docs/plans/2026-10-11-p2c-solana-signing.md` are done; address lookup tables were tightened from "strong warning" to "refused" (D37).

## 7. Next steps

1. Get some devnet SOL at faucet.solana.com, send one transaction from the Watcher's Solana tab to another of your addresses, and compare the Signer's display with the block explorer.
2. Apply the independent review's findings.
3. Next chain: TRON or NEAR (P2d).
