> English translation of docs/06-p2-plan.md. The Chinese original is authoritative.

# 06 · P2 Plan: Multi-chain (EVM / BNB, DOGE, TRON, SOL, NEAR)

Status: drafted 2026-10-10 · the BTC framework from P1 (review → sign → Watcher re-verification, animated QR codes, C1–C11 checks) is reused as is

Progress: P2a part 1 complete (see `docs/en/feynman/P2a.md`); P2b complete (`docs/en/feynman/P2b.md`); P2a part 2, EIP-712, complete (`docs/en/feynman/P2a-2.md`, decision D29); in addition, passphrase mode (D30) and block explorer URLs (D31) were added at the user's request.

**Adjustment (2026-10-10, user request)**: "Strict random number generation" and "per-chain address generation" are done first (P2b, see `docs/en/feynman/P2b.md`); EIP-712 is paused (the strict JSON parser is complete); transaction review and signing for DOGE / TRON / SOL / NEAR are postponed to P2c–P2e.

## Breakdown and order

Proceed in order of "new audit surface", from smallest to largest; each sub-stage ends with a Chinese-language Feynman report (`docs/en/feynman/P2a.md` …) and an independent review:

| Sub-stage | Scope | Newly introduced third-party source | Main new code |
|---|---|---|---|
| **P2a** | ETH, BNB Chain, and other EVM chains (distinguished by chain-id) | Keccak-f[1600]: RustCrypto `keccak` v0.1.2 (zero dependencies, see below) | RLP, transaction parsing (legacy / EIP-155 / EIP-2930 / EIP-1559), ERC-20 recognition, EIP-191 messages, EIP-712 structured data, generic display model, UR `eth-sign-request` / `eth-signature` |
| **P2b** | DOGE | None (reuses rust-bitcoin) | Legacy P2PKH signing, DOGE addresses, fee rules |
| **P2c** | TRON | None (reuses Keccak, secp256k1) | Minimal protobuf decoder, TRX / TRC-20 transfers, always refuse to sign permission-modifying contracts |
| **P2d** | SOL, NEAR | Ed25519: `ed25519-compact` 2.6.0 (maintained by the author of libsodium, all optional dependencies disabled) | SLIP-10, Solana messages (legacy / v0), SPL Token, NEAR borsh transactions and actions |

## Third-party source selection

| Need | Candidates | Conclusion |
|---|---|---|
| Keccak-f[1600] | Starting with 0.1.3, RustCrypto `keccak` unconditionally depends on `cpufeatures` on aarch64, which on Apple platforms depends on `libc` (large, with a build.rs); `tiny-keccak` depends on `crunchy` (generates code with build.rs) | Take RustCrypto `keccak` **v0.1.2** (tag `keccak-v0.1.2`, commit `b59a4d5a`): zero dependencies, two source files; the changes in 0.1.3–0.1.6 only involve a newly added ARMv8 assembly backend and new functions, and the pure-Rust permutation function is unchanged (CHANGELOG and diff compared). The Keccak-256 sponge padding is hand-written (about 30 lines) and differentially tested with Ethereum's public vectors + the Python standard library's `hashlib.sha3_256` (an independent implementation) |
| Ed25519 | `ed25519-dalek` (long dependency chain, including the proc macro `curve25519-dalek-derive`), `ed25519-compact` (zero required dependencies), Monocypher (C) | `ed25519-compact` 2.6.0, `default-features = false`, with `self-verify` enabled (verify after signing, to guard against fault injection); deterministic signatures (RFC 8032), cross-checked against the official RFC 8032 vectors and the Python reference implementation included in the RFC |

Both are imported per R1 (pinned upstream git commit, proof that it is an ancestor of a tag, MANIFEST registration, review-scan list, release only after review by two people), and the decisions are recorded in `docs/en/05`.

## Shared rework (completed as part of P2a)

1. **Generic display model**: Rust outputs a chain-agnostic review result (a title, a number of "label / value / type (address, amount, data)" rows, and a list of warnings with their levels), and Swift is responsible only for rendering. BTC review results are also migrated to the same model. The Signer UI no longer has a separate set of screens for each chain, reducing the error surface on the Swift side.
2. **Multi-chain account export**: After unlock, the Signer exports account QR codes per chain (EVM: crypto-hdkey for `m/44'/60'/0'`; SOL/NEAR: the public key of each address); the Watcher imports them per chain.
3. **Dangerous operations**: Implemented strictly according to the "Per-chain dangerous operations" table in `docs/en/01` — "refuse to sign by default" items return an error code directly in Rust, which Swift cannot bypass; "strong warning" items become red warnings in the display model and require additional confirmation from the user.
4. **Watcher networking**: One minimal HTTP client per chain (JSON-RPC / REST), with configurable node addresses; before broadcasting, the signed transaction is re-parsed locally and compared with the review result.

## P2a acceptance criteria (EVM)

- Keccak: Ethereum public vectors, FIPS 202 KATs (via SHA3 padding), and differential testing against Python `hashlib` on 1000 random inputs all agree.
- RLP: Ethereum's official `RLPTests` vectors (encoding + rejection of non-canonical encodings).
- Signing: the official EIP-155 example transaction matches byte for byte; EIP-1559 transactions match go-ethereum test data; secp256k1 recovery of the signature yields this account's address (self-verification after signing).
- ERC-20: decoding of `transfer` / `approve` / `transferFrom`; strong warning for unlimited `approve`, `setApprovalForAll`, and `permit` / Permit2; refuse to sign EIP-7702 authorizations (type 4 transactions) by default.
- EIP-712: a hand-written strict JSON parser (rejecting duplicate keys, deep nesting, and overly long numbers); `hashStruct` matches the EIP-712 specification example (Mail).
- End to end: Watcher builds → `eth-sign-request` animated QR code → Signer reviews and signs → `eth-signature` → Watcher assembles and verifies locally.
- Supply chain: C1–C11 all pass; new third-party entries have a review-scan list; reproducible per C6.

## What we need from you (same as P1; can proceed in parallel)

Two iPhones + a developer account, a second Mac, testnet tokens (the Sepolia ETH / BSC Testnet BNB faucets likewise require human verification), and third-party source reviewers.
