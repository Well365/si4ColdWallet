> English translation of docs/00-scope.md. The Chinese original is authoritative.

# 00 · Scope (v1.0)

Status: P0 frozen · 2026-10-10

## Product form

Two independent iPhone Apps, built from the same repository:

| App | Device | Online | Holds private keys | Responsibilities |
|---|---|---|---|---|
| **Signer** (signing device) | Dedicated iPhone, never online after activation | No | Yes (not persisted by default) | Generate/import seed, export public keys, parse transactions awaiting signature, display them in full, sign |
| **Watcher** (watch-only device) | Any iPhone | Yes | No, public keys only | Check balances, build unsigned transactions, display QR codes, scan signatures back, broadcast |

The two devices exchange data **only** via on-screen QR codes + camera (animated QR codes, UR encoding).

## Supported chains (v1.0)

| Chain | Curve | Derivation path | Notes |
|---|---|---|---|
| BTC | secp256k1 (ECDSA + Schnorr) | BIP84 `m/84'/0'/0'`, BIP86 `m/86'/0'/0'` | PSBT; compatible with Sparrow |
| DOGE | secp256k1 | BIP44 `m/44'/3'/0'` | Legacy transactions (no SegWit); the Signer must be given the previous transactions to verify amounts |
| ETH / BNB Chain / other EVM | secp256k1 + Keccak-256 | `m/44'/60'/0'/0/i` | EIP-155 / EIP-1559 / EIP-712; compatible with ERC-4527 |
| SOL | ed25519 | SLIP-10 `m/44'/501'/i'/0'` | legacy and v0 messages |
| NEAR | ed25519 | SLIP-10 `m/44'/397'/0'` | borsh serialization |
| TRON | secp256k1 + Keccak-256 | `m/44'/195'/0'/0/i` | protobuf; USDT-TRC20 |

v2 candidates (not in v1 scope): LTC, BCH (reuse the UTXO module, low cost); TON, SUI, APT, XRP (each one means a new parser and a new audit scope).

## Feature list (v1.0)

- Seed: generation (system random numbers + optional dice entropy), import (manual entry / SeedQR), BIP39 passphrase (never saved)
- Seed storage: **stateless (default)**; optional "storage mode" (encrypted with Secure Enclave P-256, then stored in the Keychain, this device only)
- Public key export: per-chain xpub / public key / address, passed to the Watcher via QR code
- Signing: transfers and common contract interactions on the 6 chain categories above; by default, refuse to sign each chain's "dangerous operations" (see the threat model)
- Addresses: full grouped display, allowlist, look-alike address warning
- Watcher: balances, history, transaction building, broadcasting; a self-hosted node is preferred, otherwise multiple RPCs are cross-checked

## Explicitly out of scope (Non-goals)

- No blind-signing toggle
- No embedded browser / DApp, no WalletConnect (v1)
- No cloud backup, no telemetry, no crash reporting
- No dependencies distributed as precompiled binaries
- No Flutter / React Native / CocoaPods / any third-party SPM packages
- No App Store release (v1 supports only "compile from source and install it yourself")

## License

This repository's own code: MIT. Third-party source code keeps its respective licenses (see `third_party/MANIFEST.toml`).
No GPL code is brought in (to keep open the option of shipping on the App Store later).
