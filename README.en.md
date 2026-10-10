> English translation of README.md. The Chinese original is authoritative.

# airgap-wallet

A two-iPhone, QR-code-based offline wallet: one iPhone serves as the **offline Signer** (never goes online), the other as the **watch-only wallet** (online, public keys only); the two devices communicate only via QR codes.

Supported: BTC, DOGE, ETH / BNB Chain / other EVM chains, SOL, NEAR, TRON (v1.0 target).

## Generation and review

All code, design, documentation and security audits in this repository were generated and reviewed by Anthropic's **Claude Fable 5.1**; the human maintainer sets requirements, makes product decisions and gives final approval. See the audit reports under [docs/en/audit/](docs/en/audit/). This does not replace an independent human security review; the two-person review required by `docs/en/02-supply-chain-policy.md` must still be completed before any release.

## Principles

- Every line of code that goes into the App exists in this repository as **source code**, traceable to a pinned commit in upstream git.
- No precompiled libraries of any kind (`.a/.so/.dylib/.dll/xcframework`); nothing is downloaded from any package registry.
- Builds are offline and reproducible; no network code may appear in the Signer binary.
- No blind signing. If parsing is incomplete, refuse to sign.

## Documentation

| Document | Contents |
|---|---|
| [docs/en/00-scope.md](docs/en/00-scope.md) | Scope, chains, non-goals |
| [docs/en/01-threat-model.md](docs/en/01-threat-model.md) | Threat model |
| [docs/en/02-supply-chain-policy.md](docs/en/02-supply-chain-policy.md) | Supply chain rules (mandatory) |
| [docs/en/03-architecture.md](docs/en/03-architecture.md) | Architecture |
| [docs/en/04-device-setup.md](docs/en/04-device-setup.md) | Signer device setup procedure |
| [docs/en/05-decisions.md](docs/en/05-decisions.md) | Architecture Decision Records (ADR) |
| [docs/en/feynman/](docs/en/feynman/) | Per-phase Feynman reports |

## Status

Under development; **do not use with real funds**.
