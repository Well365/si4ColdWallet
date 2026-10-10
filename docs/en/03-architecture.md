> English translation of docs/03-architecture.md. The Chinese original is authoritative.

# 03 · Architecture

Status: P0 frozen · 2026-10-10

## Overview

```
┌──── Signer iPhone ────────────────┐      animated QR code (UR)       ┌──── Watcher iPhone ─────────────────────────────┐
│ Signer.app (SwiftUI)              │  ←── unsigned tx / request ────  │ Watcher.app (SwiftUI)                           │
│   └─ libaw_signer.a (Rust)        │  ─── signed tx / public key ──→  │   └─ libaw_watch.a (Rust)                       │
│      seed · derive · parse · sign │                                  │      addresses · build tx · parse receipts      │── HTTPS ─→ nodes / RPC
│   no network code (CI check)      │                                  │   no private-key types (compile-time isolation) │
└───────────────────────────────────┘                                  └─────────────────────────────────────────────────┘
```

## Repository layout

```
airgap-wallet/
├── Cargo.toml              # Rust workspace; all third-party dependencies point to third_party/ via [patch.crates-io]
├── .cargo/config.toml      # net.offline = true; crates.io replaced with the empty directory core/no-registry
├── core/crates/
│   ├── aw-common/          # Secret zeroization, stack scrubbing, minimal JSON output, hex (zero dependencies)
│   ├── aw-bip39/           # BIP39, in-house implementation (official test vectors)
│   ├── aw-keys/            # BIP32 (secp256k1) / SLIP-10 (ed25519) derivation
│   ├── aw-ur/              # UR: bytewords, CRC32, fountain, minimal CBOR (in-house implementation, official test vectors)
│   ├── aw-chain-btc/       # BTC/DOGE: PSBT parsing, display model, signing
│   ├── aw-chain-evm/       # ETH/BNB/EVM (P2a): Keccak, RLP, transaction review/signing, ERC-20, EIP-191, EIP-712, eth-sign-request
│   ├── aw-chain-sol/       # SOL (P2)
│   ├── aw-chain-near/      # NEAR (P2)
│   ├── aw-chain-tron/      # TRON (P2)
│   ├── aw-ffi-common/      # C ABI shared by both sides (buffer freeing, animated QR code encoding/decoding)
│   ├── aw-ffi-signer/      # Signer C ABI (session handles, D16) → staticlib
│   ├── aw-ffi-watch/       # Watcher C ABI → staticlib (does not depend on aw-keys / aw-bip39 / signing code; C3 check)
│   └── aw-e2e/             # End-to-end tests: Watcher ↔ Signer round trips via animated QR codes
├── core/shims/, core/stubs/ # Hand-written shims (D11) and disabled stubs (D12)
├── ios/
│   ├── Signer/             # Xcode project, zero SPM dependencies
│   ├── Watcher/            # Xcode project, zero SPM dependencies
│   └── Shared/             # QR code display and scanning UI shared by both sides, C module map
├── third_party/            # Upstream git source + MANIFEST.toml
├── toolchain/              # Pinned installer hashes, install-directory fingerprint, version records (D14)
├── tools/                  # aw.py + awlib/ (checks C1–C5, C9–C11), cargo-sb (sandbox), bootstrap / vendor / probe / repro / ios scripts
└── docs/                   # Scope, threat model, rules, decisions, Feynman reports
```

## Isolation between the Signer and the Watcher

| Measure | Effect |
|---|---|
| Two FFI crates, each depending only on the modules it needs | No private-key derivation/signing code can appear in the Watcher static library |
| Signing-related functions sit behind the Cargo feature `signing`, which the Watcher does not enable | Same as above, guaranteed at compile time |
| Checks on the Signer binary (C4/C5) and source (C9/C11) | No network code can appear in the Signer |
| The two FFI libraries are built separately, and C3 checks the dependency graph | Prevents Cargo feature unification from bringing signing code into the Watcher (D18) |
| Two independent Xcode projects, different Bundle IDs | Network code cannot be compiled into the Signer by mistake |

## Rust ↔ Swift interface (hand-written C ABI)

- All functions are `extern "C"`; parameters/return values are only integers and pointer + length.
- Returned data is allocated by Rust, and Swift calls `aw_buf_free` to release it when done; buffers containing secrets are zeroed before being freed.
- Complex structures (transaction display models) are returned as JSON bytes: the Rust side uses the minimal JSON writer in `aw-common`, and the Swift side parses them with the system `JSONDecoder`.
- The seed never crosses the interface as a string: secrets exist only in Rust's `AwSession`, and Swift holds only an opaque handle; when a mnemonic is entered manually, only word indices (0–2047) are passed; every interface that touches secrets scrubs 64 KiB of stack before returning (D16).

## QR codes

- Generation: CoreImage `CIQRCodeGenerator` (system).
- Recognition: AVFoundation `AVCaptureMetadataOutput` (system).
- Encoding: UR (BTC uses `crypto-psbt` / `crypto-account`, EVM uses ERC-4527 `eth-sign-request`, SOL/NEAR/TRON use Keystone-compatible UR types).

## Data flow: one BTC transfer

1. Watcher: compute addresses from the xpub, query UTXOs → build the PSBT (including change derivation paths) → UR animated QR code
2. Signer: scan → Rust parses the PSBT → verify that the change belongs to this wallet, compute the fee → generate the display model → user confirms item by item → sign → UR animated QR code
3. Watcher: scan → merge signatures → finalize → broadcast
