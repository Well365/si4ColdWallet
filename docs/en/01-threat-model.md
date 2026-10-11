> English translation of docs/01-threat-model.md. The Chinese original is authoritative.

# 01 · Threat Model

Status: P0 frozen · 2026-10-10

## What we protect

1. **Seed / private keys**: leaked = all assets lost
2. **Signing intent**: the user thinks they are signing A but actually signs B = assets lost
3. **Build artifact integrity**: the App the user installs must be exactly the one compiled from the public source code

## Trust boundary (what we must trust and cannot eliminate)

| Component | Why it cannot be eliminated | Our mitigation |
|---|---|---|
| iOS, Secure Enclave | Running on an iPhone means they must be trusted | The Signer never goes online and never signs in to an Apple ID |
| Xcode / clang / ld / codesign | The only way to compile an iOS App | Download only from Apple's official website and verify signatures; pin versions |
| Official Rust compiler (rustc) | Bootstrapping still depends on the previous version's binary (Trusting Trust) | Pin versions; download on two machines over two networks, then compare hashes |
| Apple system frameworks (SwiftUI, AVFoundation, CoreImage, Security) | Same as iOS | Allowlist; CI checks that only these frameworks are linked |

Beyond these, **nothing is trusted**: package registries, third-party authors' accounts, our own CI, the Watcher, and the nodes the Watcher connects to.

## Attacker assumptions

- The Watcher is fully compromised (it can alter amounts, addresses, transaction contents, QR code contents)
- The network / RPC nodes will lie (balances, nonces, block hashes, previous transactions)
- The publishing account of any third-party dependency will be hijacked and used to publish malicious versions carrying valid signatures/attestations
- The GitHub account of one of our own developers will be hijacked
- Devices will be stolen; the attacker has lab-grade equipment (fault injection, side channels)
- Attackers will use AI to review our open-source code line by line in search of vulnerabilities

## Threats and countermeasures

| # | Threat | Real-world cases | Countermeasures (where implemented) |
|---|---|---|---|
| T1 | Predictable random numbers | Coldcard 2026-07 (a build misconfiguration fell back to a software PRNG), Milk Sad, Profanity | Check the return value of `SecRandomCopyBytes`; optional dice-entropy mixing; known-answer self-test at startup; offline recomputation offered after generation |
| T2 | Dependency poisoning / tampering by intermediary repositories | Trust Wallet extension 2025-12, @solana/web3.js 2024, TanStack 2026-05 (with valid SLSA attestations) | Third-party source is taken from pinned upstream git commits and checked into the repository; offline builds; binary scan; see `02-supply-chain-policy.md` |
| T3 | Precompiled binaries smuggled into dependencies | serde_derive 1.0.172 (2023-08) | CI scans third_party/ for all Mach-O/ELF/PE/static libraries/wasm |
| T4 | Build-time code execution (build.rs, proc macros) | Same as T2 | Minimize such dependencies; no UniFFI/serde derive macros; dedicated, offline build machine |
| T5 | Blind signing / Watcher tampering with transactions | Bybit 2025, Radiant 2024, WazirX 2024 | The Signer fully parses everything locally; refuse to sign if the structure is invalid or parsing is incomplete; no blind-signing toggle. Contract calls / structured data whose structure can be parsed but whose semantics cannot be recognized: display the raw content in full + strong warning + forced confirmation (decision D25) |
| T6 | Bugs in the transaction parser itself | Ledger LSB-024 (2026-08, count overflow) | Rust, explicit bounds checks, fuzzing, Kani proofs of no panics |
| T7 | Malicious versions leaking the seed through signature nonces | Dark Skippy 2024 | BTC: anti-exfil; EVM/TRON: deterministic signatures + two-device comparison for large amounts |
| T8 | Address poisoning / clipboard replacement | 2025-12, about 50 million USDT | Full grouped address display, allowlist, look-alike address warning, no clipboard |
| T9 | Approval phishing / ownership transfer | Permit, EIP-7702, TRON permission changes, SOL SetAuthority, NEAR AddKey | Per-chain "dangerous operations": refuse to sign by default (see the table below) |
| T10 | Seed leaking from the UI layer | Slope logs, SparkCat photo-album OCR, system keyboard learning | Seed only in Rust memory; in-app keyboard; screenshots/screen recording blocked; zero logging; no clipboard |
| T11 | Pre-signed transactions exploited later | Drift 2026-04 (durable nonce) | SOL durable nonce: strong warning; EVM: always display nonce and chain ID |
| T12 | Counterfeit App / fake installation packages | Fake Ledger Live 2026-04, SeaFlower | Only self-compiled installation is supported; build hashes are published for comparison |
| T13 | The Signer secretly going online | General-purpose phones have wireless modules | The Signer binary contains no network symbols (CI check); device procedure: no Apple ID sign-in, SIM card removed, wireless off, Airplane Mode |
| T14 | Physical extraction after device theft | TROPIC01, Tangem (2026) | Stateless by default; optional on-device storage (D39): encrypted with a Secure Enclave key + 6-digit unlock PIN, wiped after one wrong PIN, relies on the device passcode; passphrase not saved unless the user opts in; multisig for large amounts |

## Per-chain "dangerous operations" (refuse to sign by default, or strong warning)

| Chain | Refuse to sign by default | Strong warning |
|---|---|---|
| BTC / DOGE | Change address does not belong to this wallet; DOGE missing previous transactions | Fee exceeds 5% of the amount paid out (all outputs when everything returns to oneself) or exceeds 0.001 BTC in absolute terms (D32); 0-sat external outputs change nothing |
| EVM | EIP-7702 authorization; Safe `DELEGATECALL` (execTransaction / module entry points / `SafeTx`), `approveHash`, messages of exactly 32 bytes, admin calls on the Safe itself, non-canonically encoded or incomplete Safe structures (D33) | Unlimited approve, permit/permit2, setApprovalForAll; unknown contract calls; non-zero Safe refund parameters, module entry points, nested Safe executions |
| SOL | SPL Token `SetAuthority`, System `Assign` / `AssignWithSeed`; v0 address lookup tables (referenced addresses cannot be verified offline; D37 upgrades this from a strong warning to a refusal); this account is not a signer; an associated token account that does not match its derivation | durable nonce; unknown programs; unknown tokens or mismatched decimals; token approvals; closing a token account; fees above 0.01 SOL; a recipient token account whose owner cannot be verified |
| NEAR | `AddKey` (FullAccess), `DeleteAccount` | FunctionCall with a deposit |
| TRON | `AccountPermissionUpdateContract` | TRC20 `approve`; abnormal fee_limit |

## Residual risks (accepted and disclosed to users)

- The iPhone's wireless modules cannot be physically removed → the Signer is "logically isolated"; large funds should use multisig, with one key kept on dedicated radio-free hardware
- The developer certificate may require periodic online verification → to be tested in practice in P1; if it fails, it goes into a design review
- Apple's and Rust's official toolchains are trust roots
