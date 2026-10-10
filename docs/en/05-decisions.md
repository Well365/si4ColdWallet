> English translation of docs/05-decisions.md. The Chinese original is authoritative.

# 05 · Architecture Decision Records (ADR)

Each decision: Context → Decision → Cost. Overturning any decision requires adding a new record that explains why.

---

## D1 · Two separate apps sharing one Rust core (2026-10-10)

- **Context**: The Signer must not contain networking code, and the Watcher must not contain private-key code. With one app in two modes, isolation would rely on a runtime switch, and the switch itself is attack surface.
- **Decision**: One repository, two Xcode projects, two Rust static libraries; isolation is achieved at compile time.
- **Cost**: Some Swift UI code has to be written twice or extracted into a shared directory (network calls are forbidden in the shared directory; checked in CI).

## D2 · Hand-written C ABI, no UniFFI (2026-10-10)

- **Context**: UniFFI brings in dozens of build-time dependencies (proc macros, a template engine, binary parsers), and that code executes on the build machine.
- **Decision**: The Rust side exports only a small number of `extern "C"` functions whose parameters are integers / pointer + length; the Swift side has a thin hand-written wrapper.
- **Cost**: We must ensure memory ownership is correct ourselves (Rust allocates, Rust frees); the number of interface functions must be kept within a few dozen.

## D3 · Third-party code only from upstream git source (2026-10-10)

- **Context**: A published package in a package registry can differ from the git source; publishing accounts get compromised; SPM packages may be prebuilt binaries (verified to be the case for both bdk-swift and Trust Wallet Core).
- **Decision**: See `02-supply-chain-policy.md`: pinned commits, whole-tree hashes, `[patch.crates-io]` pointing to local paths, Cargo offline.
- **Cost**: Adding and upgrading dependencies is all manual work; version conflicts have to be resolved by hand.

## D4 · The Signer is stateless by default (2026-10-10)

- **Context**: The Secure Enclave does not support secp256k1 / ed25519, so it can only "encrypt and safekeep" the seed; the physical attack surface after the phone is stolen cannot be fully assessed.
- **Decision**: By default, the seed is loaded by scanning a SeedQR each time and cleared after signing; "storage mode" is an option (ECIES encryption with an SE P-256 key, Keychain `ThisDeviceOnly`).
- **Cost**: The SeedQR has to be taken out for every signing; physical custody of the SeedQR becomes critical.

## D5 · Write it ourselves where feasible and official test vectors exist; never write cryptographic primitives ourselves (2026-10-10)

- **Write ourselves**: BIP39 (encoding + PBKDF2 composition), UR (bytewords, CRC32, fountain codes, minimal CBOR), minimal JSON output, hexadecimal.
- **Use upstream source**: libsecp256k1 (via rust-secp256k1), SHA-256/SHA-512/HMAC/RIPEMD-160 (rust-bitcoin's hashes), ed25519 (curve25519-dalek / ed25519-dalek 2.x to be evaluated in P2), Keccak-256 (to be evaluated in P2).
- **Cost**: The self-written parts must cover 100% of the official test vectors and be included in the scope of the external audit.

## D6 · No serde / JSON library (2026-10-10)

- **Context**: serde's derive macros are code executed at build time, and serde once smuggled in a prebuilt binary (serde_derive 1.0.172).
- **Decision**: The Rust side only needs to "output" JSON (the display model), so we hand-write a minimal writer; the Swift side parses it with the system `JSONDecoder`.
- **Cost**: When display model fields change, both sides must be synchronized by hand; tests lock down the format.

## D7 · Chain parsing references Keystone, copying individual files instead of depending on it as a whole (2026-10-10)

- **Context**: The Rust chain modules of the Keystone 3 firmware (MIT) are the most complete ready-made implementation, but their workspace depends on `cryptoxide` and on Keystone's own git forks.
- **Decision**: In P2, evaluate chain by chain and copy only the needed parsing source files into `third_party/keystone-extract/`, preserving provenance and license headers; signing is routed through our own cryptographic backend instead.
- **Cost**: Upstream fixes are not synchronized automatically and require periodic comparison.

## D8 · MIT license, no GPL (2026-10-10)

- **Decision**: Our own code is MIT; third-party code keeps its original license; GPL code (Polkadot Vault, Trezor) is used for read-only reference only and is never copied.

## D9 · Zero third-party packages in the Xcode projects; QR codes use system frameworks (2026-10-10)

- **Decision**: QR code generation uses CoreImage and recognition uses AVFoundation; no third-party Swift library of any kind is introduced.

## D10 · The toolchain is installed in a project-specific directory (2026-10-10)

- **Context**: The current development machine is a daily-use machine; the toolchain should not pollute the system, and this also makes it easy to reproduce exactly on a second machine.
- **Decision**: `RUSTUP_HOME` / `CARGO_HOME` point to `~/.airgap-wallet-toolchain/`, and the shell configuration is not modified; the environment is entered via `tools/env.sh`.
- **Cost**: Every new terminal requires `source tools/env.sh`. Release builds must still be done on a dedicated Mac.

## D11 · Hand-written `hex_lit` shim (2026-10-10, P1)

- **Context**: rust-bitcoin declares `hex_lit` as a regular dependency. The `.cargo_vcs_info.json` of hex_lit 0.1.1 on crates.io records the source commit `a1b61585…`, but the upstream repository Kixunil/hex_lit has only one commit (0.1.0), and that commit does not exist (`git fetch` returns "not our ref"). The published package cannot be traced back to source.
- **Decision**: Per rule R1, it is not used; a shim with the same name and version is hand-written in `core/shims/hex_lit` (compile-time hex literals, about 40 lines, with tests) and substituted via `[patch.crates-io]`. rust-bitcoin uses this macro only in test/benchmark code.
- **Cost**: No substantive cost. This is a real case of the "published package ≠ source" risk, and is written up in the P1 Feynman report.

## D12 · Optional dependencies use "disabled stubs" as placeholders (2026-10-10, P1)

- **Context**: The Cargo lockfile is independent of features, so weak dependency features (such as `encoding?/std`) require the optional dependency to appear in the lockfile even if it is never enabled.
- **Decision**: For such dependencies, an empty crate with the same name and version is placed in `core/stubs/<name>`, whose source is a single line of `compile_error!`. Currently there is only one: `bitcoin-consensus-encoding`. Generated by `tools/vendor/make-stub.sh`.
- **Cost**: If the dependency is ever truly needed, it must be imported from upstream per R1 and the stub deleted.

## D13 · The Signer FFI crate produces only a staticlib (2026-10-10, P1)

- **Context**: When both `["staticlib", "rlib"]` are declared, all `#[no_mangle]` exported functions are missing from the static library built with release + LTO; the "network symbol check" then **passes falsely** because the library contains almost no code.
- **Decision**: Produce only `staticlib`; and add a "link probe" (`tools/probe/`): a C program calls every exported function and is actually linked, so a single missing export makes the link fail; the network symbol check now runs on the linked executable instead.
- **Cost**: None. Lesson: every check needs a "negative control" that proves it can fail.

## D14 · The toolchain switches to the official standalone installers instead of rustup (2026-10-10, P1)

- **Context**: Security review 1 pointed out that rustup runs the newly installed `rustc --version` before verification is complete; subsequent `component add` downloads are checked only against a SHA-256 manifest; and rustup also rewrites its installation records, which makes byte-for-byte verification difficult.
- **Decision**: Use the official Rust standalone installers (`rust-<version>-<platform>.tar.xz` and the individual iOS standard library packages); the SHA-256 hashes of the installers and their signature files are pinned in `toolchain/PINNED.sha256`, with strict GPG signature verification (GOODSIG + VALIDSIG for the specified fingerprint, rejecting anything revoked/expired); the post-install directory tree fingerprint is pinned in `toolchain/INSTALLED_TREE.sha256` and re-verified before every build. `rust-toolchain.toml` is deleted, and the toolchain is entered only via `tools/env.sh`.
- **Cost**: When adding a compilation target or upgrading the version, the pinned hashes must be checked and updated by hand.

## D15 · Check tools rewritten with the Python standard library; Rust compilation moved into a sandbox (2026-10-10, P1)

- **Context**: Security review 1 found multiple bypassable points in the original bash check scripts, such as regex injection, wildcard gaps, and failures swallowed by `|| true`; security review 2 found that build scripts could rewrite the pinned hashes and allowlists in the repository.
- **Decision**: All checks are consolidated into `tools/aw.py` (implemented in `tools/awlib/`, standard library only, run isolated with `python3 -I`, exact string comparison); all Rust compilation goes through `tools/cargo-sb` (`sandbox-exec`: no network, may write only to `target/` and `CARGO_HOME`, restricted ioctl / system services / executables, detached from the terminal).
- **Cost**: `sandbox-exec` is macOS-specific and has been marked deprecated by Apple, but it still works; it is not a complete security boundary (see "Build-time code: trust boundary" in `docs/en/02`), so official releases still require a dedicated build environment and reproduction by multiple people.

## D16 · The Signer FFI uses session handles; secrets live only in Rust memory (2026-10-10, P1)

- **Context**: Security review 1 pointed out that the old interface let the mnemonic and passphrase exist as Swift `String`/arrays, which cannot be reliably zeroized, violating threat T10; the Rust review found that the third-party HMAC and `Xpriv` left residue on the stack from which the mnemonic and root private key could be recovered.
- **Decision**: The Signer C interface is changed to "session handles" (ABI v2): Swift passes only the indices of the words in the wordlist, and the mnemonic, seed, and private keys exist only inside the Rust session; private keys are wrapped in `SecretXpriv` (wiped on drop); every interface that touches secrets scrubs 64 KiB of stack before returning (`scrub_stack`). Retest: all secret patterns had 0 hits on the stack.
- **Cost**: The passphrase still exists briefly as a Swift string in the input field (SecureField) and cannot be zeroized; all we can do is hand it to Rust as soon as possible and zeroize the intermediate byte array.

## D17 · Implement the OS version check ourselves; the Signer no longer imports `dlsym` / `fopen` (2026-10-10, P1; revised after re-review 4)

- **Context**: Swift's `#available` and SwiftUI's inlined code call `__isPlatformVersionAtLeast` in the compiler runtime (compiler-rt). For compatibility with older systems, it uses `dlsym` to look up 10 CoreFoundation functions and `fopen` to read `SystemVersion.plist`. Raising the deployment target to iOS 26 does not get rid of them either (tested, and reverted). The initial approach was to keep these two imports and constrain the arguments at the call sites; security re-review 4 bypassed this constraint using "the callee implicitly overwrites argument registers".
- **Decision**: Implement `__isPlatformVersionAtLeast` in Rust in `aw-ffi-common`, calling dyld's `_availability_version_check` directly (available since iOS 15; compiler-rt also takes this path on newer systems). Our static library precedes compiler-rt in link order, so the linker no longer pulls in the original implementation. `dlsym` and `fopen` are therefore now forbidden outright. `os_log` (SwiftUI's runtime warnings) is still a restricted import, and its format string must be an allowed literal.
- **Cost**: A compiler runtime function is replaced, and its behavior depends on a private dyld interface (the same as compiler-rt); there are unit tests on the macOS host.

## D18 · Signer and Watcher libraries are built separately; dependency graph isolation is added to C3 (2026-10-10, P1)

- **Context**: When the two FFI libraries are built in the same `cargo build`, Cargo unifies features, so the Watcher library pulled in signing code (`aw-chain-btc`'s `signing`), and the hashes of both libraries also differed from those of separate builds.
- **Decision**: Every build script invokes Cargo separately for each package; C3 checks with `cargo tree`: the Watcher dependency graph must not contain `aw-keys`, `aw-bip39`, or the `signing` feature; the Signer dependency graph must not contain the `watch` feature. The Watcher build script additionally checks that the static library contains no signing-related symbols.
- **Cost**: Slightly longer build times.

## D19 · Official builds start from an empty `target/`; artifacts are copied out of the sandbox and compared with the C6 results (2026-10-10, P1; supplemented after re-review 4)

- **Context**: Security re-review 3 demonstrated in practice that build-time code can replace the intermediate artifacts of unchanged crates in `target/` without Cargo noticing, and the next build then carries the tampering into the artifacts.
- **Decision**: `tools/ios/build-*.sh` always runs `cargo clean` first (executed inside the sandbox); the hashes of the built static libraries are compared with the independent build results recorded by `tools/repro/build-twice.sh`, and any mismatch is a failure.
- **Re-review 4 addendum**: A build script can leave a background process behind that modifies the libraries in `target/` after the checks are done. Now, after `cargo-sb` finishes, it cleans up leftover processes in the session, and any leftover is judged a failure; immediately after compilation, the libraries are copied to `build/lib/`, which the sandbox cannot write to; verification and linking use only this copy, and it is verified once more after linking (the Xcode projects' `OTHER_LDFLAGS` point to `build/lib/`).
- **Cost**: Every official build is a full compilation (about 1–2 minutes); after code changes, `build-twice.sh` must be rerun first.

## D20 · Deployment target iOS 17.0; the clipboard is used only on the Watcher (2026-10-10, P1)

- **Decision**: The deployment target of both apps is iOS 17.0 (covering more older devices; raising it to 26 does not reduce the restricted imports, see D17). The Watcher allows pasting account QR code text from the clipboard (convenient for importing in the simulator and where there is no camera); the Signer forbids any clipboard access (C9).
- **Cost**: None.

## D21 · Keccak uses RustCrypto `keccak` v0.1.2; the sponge construction is hand-written (2026-10-10, P2a)

- **Context**: Ethereum and TRON need Keccak-256. Starting with 0.1.3, RustCrypto `keccak` unconditionally depends on `cpufeatures` on aarch64, which on Apple platforms depends on `libc`, a very large crate with a build.rs; `tiny-keccak` depends on `crunchy`, which generates code with a build.rs.
- **Decision**: Import `keccak` v0.1.2 (tag `keccak-v0.1.2`, zero dependencies, no unsafe, no build.rs). 0.1.3–0.1.6 only added an ARMv8 assembly backend and new functions; the pure-Rust permutation function is unchanged (CHANGELOG and diff compared). The Keccak-256 sponge and padding are hand-written (about 60 lines) and verified with Ethereum's public vectors and 310 differential test cases against Python's `hashlib.sha3_256` (the same sponge with SHA3 padding swapped in).
- **Cost**: We use an older version; if upstream later fixes a problem in the permutation function, we must upgrade per R6.

## D22 · Generic display model; unified entry point in Signer interface v3 (2026-10-10, P2a)

- **Context**: With a separate review UI for each chain, the Swift side can easily miss displaying fields, and the audit surface also grows linearly with the number of chains.
- **Decision**: Rust generates a chain-agnostic display model (a title, a number of "label / value / style" rows, and graded warnings), and Swift only renders it row by row; BTC review is also migrated to this model. The Signer C interface is upgraded to v3: the scanned QR code is handed over in its entirety to `aw_session_review_ur` / `aw_session_sign_ur`, and Rust determines whether it is a PSBT or an `eth-sign-request`; Swift no longer parses any request content. When there is a "high risk" warning, the UI requires the user to tick a confirmation checkbox; Rust also requires the caller to pass a "confirmed" flag (`confirm_danger = 1`) and otherwise refuses to sign — the confirmation requirement does not depend on UI code.
- **Cost**: The UI's expressiveness is limited by the "row" format; complex structures (such as nested EIP-712 objects) must be flattened in Rust.

## D23 · EVM request format and signing conventions (2026-10-10, P2a)

- **Decision**:
  - Requests and responses use ERC-4527's `eth-sign-request` (CBOR tag 401) / `eth-signature` (402), with registry fields consistent with Keystone and MetaMask; unknown keys are rejected on read.
  - The signing hash is always = Keccak-256(bytes to be signed) (for messages, in EIP-191 prefixed form), so "strictly parsing the bytes to be signed" is equivalent to "what is displayed is what is signed".
  - v in the signature: for legacy transactions it is the EIP-155 value (chain ID × 2 + 35 + recid, possibly multiple bytes), for typed transactions it is yParity, and for messages it is 27 + recid.
  - Refuse to sign by default: legacy transactions without a chain ID, EIP-7702 (type 4), Safe DELEGATECALL and `approveHash`, and requests whose declared chain/address/path does not match the actual one. EIP-712 structured data is never signed until it is implemented.
  - ERC-20 and ERC-721 share the same `approve` / `transferFrom` selectors: for contracts not in the token table, the value is displayed as "allowance or NFT ID", and approvals are always high risk.
  - A message is displayed as text only if it consists solely of allowlisted characters (printable ASCII, Chinese characters, and common Chinese punctuation); otherwise it is displayed as hexadecimal.
  - Watcher verification: the request ID matches, the signature recovers this account's corresponding address, and s is low (EIP-2).
- **Cost**: EIP-712 is deferred to P2a part 2; until then, DApp operations that depend on EIP-712 (such as Permit signatures) cannot be used — these are themselves high-risk operations.

## D24 · The Watcher displays the same review result as the Signer (2026-10-10, P2a)

- **Decision**: After building a transaction, the Watcher calls **the same** Rust review code as the Signer to generate the display model. The user can compare the contents on the two devices line by line: if the Watcher has been tampered with but the Signer has not, the two displays will differ.
- **Cost**: The Watcher library grows slightly in size (the review code contains no private keys).

## D25 · Unknown contract calls: strong warning + forced confirmation, not blanket refusal to sign (2026-10-10, P2a, user decision)

- **Context**: Threat model T5 says "refuse to sign if parsing is incomplete", while the "per-chain dangerous operations" table says "unknown contract call: strong warning" for EVM; the two are in tension. Always refusing to sign is safer, but a large number of DeFi operations would become unusable.
- **Decision** (confirmed by the user): Keep the strong warning. The Signer displays the contract address, function selector, and call data, marked as high risk; the user must tick the confirmation in the UI, and the Rust side also requires the "confirmed" flag (D22). T5's "refuse to sign" applies to data that **can be parsed but is structurally invalid**; contract calls and EIP-712 structured data whose "semantics cannot be recognized" are handled with a strong warning.
- **Cost**: Users may sign a malicious call out of confirmation fatigue; the mitigation is to gradually expand the recognizable call and structured data types, and to keep the default refuse-to-sign list for dangerous operations.

## D26 · Ed25519 uses `ed25519-compact` v2.4.2, not the latest version (2026-10-10, P2b)

- **Context**: Solana and NEAR need Ed25519. `ed25519-dalek` has a long dependency chain (including the proc macro `curve25519-dalek-derive`); `ed25519-compact` (maintained by the author of libsodium) has zero dependencies and no build.rs once its optional dependencies are disabled, and only one `unsafe`, used to zeroize memory.
- **Decision**: Take tag `2.4.2` (commit `eb269493`, released 2026-08-19). 2.5.0 / 2.6.0 were released two weeks ago; their changes concentrate on stricter "signature verification" and the PEM format, and do not touch key generation or signing; for supply chain reasons, versions that have been published for some time are preferred. `default-features = false`.
- **Constraint**: The library aborts the program when it encounters an all-zero private key, so `aw-keys::slip10` rejects all-zero private keys before calling it. When the Watcher needs to verify Ed25519 signatures in the future, re-evaluate whether to upgrade to a version with strict verification (per R6).
- **Cost**: The latest verification hardening is not used.

## D27 · Strict entropy: health checks + an independently verifiable dice-only mode (2026-10-10, P2b, user requested "a strict random number generation mechanism")

- **Decision**:
  - Mixed mode (default): the system random bytes first go through health checks — ≤ 15 distinct byte values, 5 consecutive identical bytes, an arithmetic progression, or identical to the previous value in this session; if any condition holds, generation is refused (for true random numbers, the false-positive probability of each condition is < 1e-8); they are then mixed with the dice rolls as `SHA-256(tag ‖ system random bytes ‖ count ‖ rolls)`.
  - Dice-only mode: entropy = the first 16 / 32 bytes of `SHA-256(dice roll string)`, with at least 50 rolls for 12 words and at least 100 rolls for 24 words (≥ 129 / 258 bits), and the rolls must pass a "looks like real dice rolling" check (chi-square, consecutive repeats, periodicity; added after review); the device's random numbers are not used at all, and users can recompute the result on an offline computer with `tools/testvectors/verify_dice.py` (Python standard library only), consistent with Coldcard's approach.
  - Health checks can only detect "broken" random numbers and cannot prove randomness (they are ineffective against Milk Sad-style PRNGs with small seeds); the real safeguard is a sufficient number of dice rolls.
  - After a successful unlock, the mnemonic and passphrase in the session are cleared immediately.
  - Signing needs no random numbers: ECDSA uses RFC 6979, and Ed25519 is inherently deterministic; system random numbers are used only to generate the mnemonic and for side-channel protection of the secp256k1 context.
- **Cost**: Dice-only mode requires rolling the dice 50 / 100 times.

## D28 · The Signer directly displays receive addresses for each chain (2026-10-10, P2b)

- **Decision**: At unlock, derive and keep only public information: for BTC (BIP84), EVM (m/44'/60'/0'), DOGE (m/44'/3'/0', testnet m/44'/1'/0'), and TRON (m/44'/195'/0'), the account public key is kept and any index is derived on demand; the SLIP-10 paths for Solana (m/44'/501'/i'/0') and NEAR (m/44'/397'/i') are fully hardened and cannot be derived from a public key, so the public keys of the first 20 accounts are precomputed at unlock, and the private keys used for derivation are zeroized immediately afterward. Address formats match the default paths of Phantom, TronLink, NEAR wallets, and others; every chain is cross-checked against an independent Python implementation (`tools/testvectors/chain_addresses.py`).
- **Cost**: Solana / NEAR can display only the first 20 accounts; for transaction signing on these chains, private keys will be derived on demand when it is implemented in P2c / P2d.

## D29 · EIP-712 structured-data signing: strict parsing, complete display, always high risk (2026-10-10, P2a part 2)

- **Decision**:
  - Parsing is stricter than MetaMask's: JSON must not contain duplicate keys; only four keys are allowed at the top level; each struct must contain exactly the declared fields; numeric values must be within the declared bit width; mixed-case addresses must conform to EIP-55; `EIP712Domain` allows only the five fields in the specification.
  - If the domain has a chain ID that does not match the request: refuse to sign. If the domain has no chain ID: warn that it "can be used on any chain".
  - Recognized types get a summary: EIP-2612 Permit, DAI-style permit, Permit2 (PermitSingle / PermitBatch / the various TransferFrom types), and Seaport listings ("give / receive / pay to others" itemized; flagged as a phishing listing when the user receives nothing at all). The summary is only a reading aid; **all fields** being signed are itemized below it.
  - Per D25, all structured-data signing (recognized or not) is high risk, and signing requires ticking the confirmation.
  - Encoding and hashing are checked byte for byte against an independent pure-Python implementation (`tools/testvectors/eip712_vectors.py`) and the specification's examples.
  - Hardening after review: signed fields are always displayed in full, never truncated; the Signer refuses to sign a single string / bytes value over 1024 bytes or a personal_sign message over 4096 bytes (if it cannot be read in full, it is blind signing); ≤ 64 struct types, ≤ 64 fields each, ≤ 512 fields in total (to prevent crafted data from making the Signer compute for a long time); Seaport summaries are given only for orders at the official deployment addresses (1.1–1.6) with an exactly matching structure, Permit2 summaries only for its six known structures, and everything else is treated as "unrecognized"; strings containing newlines, tabs, or quotes are displayed as hexadecimal (to prevent forging "another row").
  - The Watcher can also initiate: paste the message or JSON provided by the dApp; the Watcher first checks it with the same review code and then generates the QR code; when the signature comes back, it verifies that it was indeed signed by this address.
- **Cost**: Login-type structured-data signing also requires one extra confirmation tick; overly long legitimate requests (rare) cannot be signed with this wallet.

## D30 · Passphrase mode: entered twice + expected fingerprint checked by Rust (2026-10-10, user request)

- **Context**: A mistyped passphrase does not produce an error; it silently yields a different wallet, and the user may receive funds at the wrong address.
- **Decision**:
  - At unlock, the user explicitly chooses "standard wallet / passphrase wallet"; for a passphrase wallet, the passphrase must be entered twice and both entries must match.
  - The user may enter the 8-character wallet fingerprint recorded previously. The check is done on the **Rust side** (`aw_session_expect_fingerprint`): on mismatch, unlocking is refused and the passphrase is cleared, but **the mnemonic is kept**, so the user only needs to re-enter the passphrase rather than all 24 words again.
  - A warning (without blocking) is shown when the passphrase contains non-ASCII characters, has leading or trailing spaces, or is shorter than 8 characters.
  - After unlock, the top of every page shows "wallet type · fingerprint".
  - The Signer interface version is bumped to 4.
- **Cost**: One extra entry.

## D31 · Block explorer URLs: text only on the Signer, clickable on the Watcher (2026-10-10, user decision)

- **Decision**: The Signer's address page shows each chain's block explorer URL below the address (`Text(verbatim:)`: not parsed into a link, not clickable, and no URL-opening API is called — C9 still forbids `openURL`). URLs are built only from a fixed prefix plus an all-alphanumeric address. On the Watcher, clickable links are provided below BTC / EVM addresses. URL table: BTC mempool.space, ETH Etherscan, BNB BscScan, SOL Solana Explorer, DOGE Blockchair (testnet has no commonly used explorer, so none is shown), TRON Tronscan, NEAR NearBlocks.
- **Cost**: URLs shown on the Signer must be typed in manually on another device.

## D32 · BTC fee rules: 5% ratio, absolute cap, self-transfers checked too, zero-value outputs change nothing (2026-10-10, audit P0-3 and re-review)

- **Decision**: `aw-chain-btc` raises fee warnings under three rules; hitting any of them is high risk (`Level::Danger`), and the FFI only signs with `confirm_danger=1`:
  1. **Ratio**: `fee × 20 > ratio base` (i.e. above 5%). The ratio base is the total paid to external addresses; when that total is 0 (everything returns to this wallet, or every external output is 0 sat) it is the total of all outputs; when the base is 0, any `fee > 0` counts as over the ratio (the fee is 100%).
  2. **Absolute**: `fee > HIGH_FEE_ABSOLUTE_SAT = 100 000 sat (0.001 BTC)`, regardless of ratio.
  3. **Fee rate**: the existing `HighFeeRate` rule is unchanged.
- **"Self-transfer"** is now defined as "no External output at all" rather than "external amount is 0": a transaction carrying a 0-sat external output neither counts as a self-transfer nor escapes the ratio check. The "self-transfer" title and the `SelfTransferOnly` warning use the same test.
- **Scope of the thresholds**: these constants are set for BTC mainnet/testnet only. DOGE fees have a completely different unit and magnitude (about 0.01 DOGE/kB ≈ 1 000 000 koinu); when DOGE is wired in, the absolute threshold must be set per coin and must not reuse 100 000.
- **Cost**: a large self-transfer (e.g. UTXO consolidation) needs one extra confirmation whenever the fee exceeds 5% of the outputs; during high-fee periods, fees above 0.001 BTC also require confirmation. This is deliberate: one extra confirmation is cheaper than one missed look.
- Tests: `aw-e2e/tests/btc_roundtrip.rs` (5% warning, self-transfer ratio, absolute cap, zero-value outputs do not bypass).

## D33 · Safe multisig: inner calls reviewed under the same rules; admin calls and blind signing always refused (2026-10-10, audit P0-1/P0-2, re-review and second re-review)

- **Background**: a Safe (formerly Gnosis Safe) signature can travel three roads: on-chain `execTransaction` (selector `0x6a761202`), the module entry points `execTransactionFromModule` / `…ReturnData` (`0x468721a7` / `0x5229073f`), and the EIP-712 `SafeTx` signature (the one that actually authorizes). The first round of fixes only refused `operation=1` and displayed the inner target; the re-review found four remaining bypasses: personal_sign over a safeTxHash, admin calls on the Safe itself, `SafeTx.data` not expanded, and refund parameters ignored. The second-round implementation went through another independent re-review, which closed non-canonical encodings, module entry points with `operation=0`, printable 32-byte messages, the `baseGas` amplifier, inner transferFrom / permit not itemised, and SafeTx fields defaulting to zero.
- **Decision** (all three roads share exactly one rule set; the code is shared through `review::inner_call_rows` / `safe_exec_rows` / `safe_refund_rows`):
  1. `operation ≠ 0` (DELEGATECALL) → refuse with `DelegateCall`. A **non-canonically encoded** entry point (incomplete head, non-zero high bytes in an address word, offset or length out of bounds) → refuse with `Parse`: Safe 1.3/1.4 are compiled with solc 0.7 (ABI coder v1), which masks the high bytes of an address word and executes anyway, so the Signer must not let it through as an "unknown call".
  2. Inner `approveHash(bytes32)` → refuse with `BlindApproval`; a personal_sign message of **exactly 32 bytes is always** refused with `BlindApproval` — not only when it cannot be displayed as text: an attacker can grind free SafeTx fields such as `baseGas` until the safeTxHash consists of printable characters only (about 2^45 attempts, hours on one GPU). Safe accepts eth_sign-style signatures; this is the off-chain equivalent of approveHash.
  3. Inner target is the Safe itself and the selector is one of the 11 admin functions (`enableModule`, `disableModule`, `addOwnerWithThreshold`, `removeOwner`, `swapOwner`, `changeThreshold`, `setGuard`, `setFallbackHandler`, `setModuleGuard`, plus the legacy ≤ 1.1.1 `changeMasterCopy` and `signMessage`) → refuse with `SafeAdmin` (error code `AW_ERR_EVM_REJECT_BASE - 17`); other self-calls keep a high-risk warning. The selectors are checked against keccak in a unit test, and every one has an end-to-end refusal test.
  4. `gasPrice ≠ 0` → show the refund gas price, `safeTxGas`, `baseGas`, the refund token (contract label for ERC-20; the zero address means the native coin), the refund receiver (the zero address is labelled as paying the transaction originator, tx.origin) and "maximum refund = (safeTxGas + baseGas) × gasPrice", with a high-risk warning; when `safeTxGas` is 0, the display states that the gas actually used is unbounded and that figure is not a cap. An ERC-20 refund is not bounded by the on-chain gas price, `baseGas` can be amplified at will, and the token can be drained.
  5. Module entry points with `operation = 0` are expanded under the same rules and labelled "module entry point (bypasses the multisig threshold): if this account is the module, the call executes directly".
  6. Inner calldata is displayed in full (32 bytes per line, like message signing), never truncated; a nested entry point is expanded recursively, the "Safe" of the nested level is that level's target, the depth limit is 3, and beyond it the request is refused with `TooLong`.
  7. Inner calls get the same recognition and warnings as top-level ones: known-token transfer/approve, `transferFrom`, EIP-2612 `permit`, DAI `permit`, Permit2 `approve`, `setApprovalForAll`, `transfer` on an unknown contract (high risk), unknown selectors (high risk); row labels carry an "inner" prefix.
  8. A `SafeTx` must be the complete Safe structure: the domain has `verifyingContract`, and all nine fields `to / value / data / operation / safeTxGas / baseGas / gasPrice / gasToken / refundReceiver` are present with the correct types; any missing or mistyped field → refuse with `Parse`, never default to zero.
  9. The top-level title is "Suspected Safe multisig execution" and shows the entry point name: the Signer can only recognize the selector and cannot verify that the target contract really is a Safe.
- **Not covered** (stated explicitly): Safe's 4337 module `SafeOp`, EIP-1271 contract-signature flows, custom entry points of other modules, and `SafeMessage` typed data. They currently fall under the generic rule "every EIP-712 structured signature is high risk" (D29) without semantic parsing.
- Tests: unit tests in `aw-chain-evm/src/{abi,review,typed_review}.rs` (selectors vs keccak, malformed encodings, module entry points, incomplete structures); `aw-e2e/tests/evm_roundtrip.rs::{safe_bypass_paths_are_closed, safe_second_review_gaps_are_closed}`; each FFI crate pins the error-code numbering in a test.

## D34 · Solana addresses support Ledger Live's two path schemes (2026-10-11, user request)

- **Background**: after restoring a Ledger-generated mnemonic, the user's Solana address did not match the one in Ledger Live. Ledger Live's derivation table (`libs/ledger-wallet-framework/src/derivation.ts`) lists three Solana schemes and scans all of them: `solanaMain` = `44'/501'` (non-iterable, a single account), `solanaBip44Change` = `44'/501'/<account>'/0'`, and `solanaSub` = `44'/501'/<account>'`. This wallet only implemented `m/44'/501'/i'/0'` (the Phantom / Solflare / Trezor / Solana CLI default), so accounts created under the Ledger Live main account or `solanaSub` were invisible.
- **Decision**: `aw-chain-sol` gains `Scheme { Phantom, LedgerLive, LedgerMain }`, all paths fully hardened; at unlock every scheme is pre-derived (20 accounts each for Phantom and Ledger Live, one for the main account) and the private keys are zeroized immediately. The FFI `aw_session_address` gains a `scheme` parameter (0 Phantom, 1 Ledger Live, 2 Ledger Live main account; other chains must pass 0, and the main-account scheme only accepts index 0); the Signer's address page shows an "account type" picker when SOL is selected, the `chain` field carries the scheme name and `note` explains its origin. The default remains the Phantom scheme.
- **Verification**: the independent Python implementation `tools/testvectors/chain_addresses.py` gained vectors for both schemes; `aw-e2e/tests/addresses.rs` and the `aw-ffi-signer` tests compare against them verbatim; out-of-range indices, unknown schemes, and a non-zero scheme on other chains all return `AW_ERR_BAD_ARGUMENT`.
- **Not done**: when Solana transaction signing (P2c) is implemented, the sign request must be able to express all three schemes and the Signer must match on the full path; the Ledger Live Ethereum scheme `m/44'/60'/N'/0/0` (first address identical to ours, different from the second on) and the legacy MEW scheme `m/44'/60'/0'/N` are not supported yet and would get the same "account type" treatment when needed.

## D35 · Watcher sending system: node registry, fee tiers, balance check before building (2026-10-11, user request)

- **Background**: the user asked for the Watcher to "list the sending nodes and gas choices — a complete system that can send". Previously each EVM chain had one built-in node plus a "chainId=URL" text box, fees were fully automatic (2 × base fee + the node's suggested priority fee, gas limit hard-coded to 21 000 / 100 000), and Bitcoin had a single Esplora URL box and a fee-rate box.
- **Decision**:
  1. **Node registry** (`ios/Watcher/Watcher/Nodes.swift`): each network has a set of built-in public nodes (no API key, verified live on 2026-10-11: ETH PublicNode / dRPC / Flashbots Protect (marked "recommended for broadcasting only"); BSC BNB Chain official / Defibit / Ninicoin / PublicNode / dRPC; Sepolia PublicNode / dRPC; BSC testnet PublicNode / BNB Chain official / dRPC; BTC mempool.space / Blockstream; testnet4 mempool.space) plus user-added nodes (https only, no username/password, health-checked before being added). The node page checks each node: EVM nodes are checked for chain ID, block height and latency; Esplora nodes for the genesis block (mainnet / testnet4) and block height; a node more than 5 blocks behind the best one is shown in orange. Old settings are migrated once.
  2. **Broadcast through any node**: once the signature is back, any node can be chosen for broadcasting, and a failed broadcast can be retried on another node; the chain ID / genesis block is re-checked before broadcasting, and for EVM the transaction hash returned by the node is still verified.
  3. **Three EVM fee tiers** (Rust `aw-chain-evm::fees`, FFI `aw_evm_fee_tiers`, checked arithmetic throughout): from `eth_feeHistory` (10 blocks, 10/50/90th-percentile priority fees) and `eth_maxPriorityFeePerGas`; slow = base fee × 5/4 + median p10 (not above standard), standard = base fee × 3/2 + max(median p50, node suggestion), fast = base fee × 2 + max(median p90, standard); for an even count the higher middle value is the median; when both the base fee and the slow priority fee are 0 (BNB Chain), slow uses the standard tier; all zeros is an error. Nodes without `eth_feeHistory` fall back to the latest block's base fee plus the node suggestion; chains without a base fee use `eth_gasPrice` × 1, 5/4, 3/2. A "custom" option takes max fee and priority fee in gwei (parsed by Rust; the priority fee may not exceed the max fee).
  4. **Gas limit**: 21 000 for a native transfer to a plain address; `eth_estimateGas` × 1.2 for tokens or contracts; the default is used (with a note) when estimation fails; it can be entered manually.
  5. **Balance check before building** (Rust `watch::check_funds`, FFI `aw_evm_check_funds`): native balance ≥ amount (for native transfers) + gas limit × max fee; token transfers also need token balance ≥ amount. If short, no sign request is generated and the shortfall is explained (`AW_ERR_TX_REJECT_BASE - 19 / - 21`).
  6. **"Maximum total deducted"** (audit P1-11): the transaction display on both the Signer and the Watcher gains a row "maximum total deducted (amount + max fee)", or "maximum deducted (fee only)" for token transfers — amount and fee stay on separate rows, with a total on top, so gas can never be mistaken for the amount.
  7. **Bitcoin fee-rate tiers**: mempool.space uses `v1/fees/recommended` (fast / standard / slow / economy), other Esplora servers use `fee-estimates` (1 / 3 / 6 / 144 blocks), always rounded up to a whole sat/vB of at least 1; custom rates are allowed. After building, the actual fee, transaction size and "total deducted" are shown.
  8. Manual nonce (to replace or speed up a stuck transaction) lives under "Advanced".
- **Security boundary**: nodes remain untrusted — the balances, nonces and fees they report are only used for building and hints; the transaction content (fees included) is reviewed independently by the Signer, abnormal gas price / priority fee / fee ratio raise warnings, and "maximum total deducted" shows the worst case. Public nodes see the addresses being queried; add your own node for privacy.
- **ABI**: `aw-ffi-watch` gained two functions, ABI version 3 → 4; `aw-ffi-signer`'s `aw_session_address` gained a `scheme` parameter in D34, ABI version 4 → 5 (Swift updated accordingly).
- **Not done**: sending SOL / NEAR / TRON waits for the Signer to implement signing on those chains (P2c / P2d); transaction formats other than EIP-1559 (the Watcher only builds type-2 transactions); cross-checking balances across several nodes (currently one node, with manual switching for comparison).

## D36 · Signer artifact checks accept the new Xcode 27 / Swift 6.3 symbols (2026-10-11, user decision: review, then allowlist)

- **Background**: built with Xcode 27.0, the Signer failed the C4/C5 artifact checks (audit P1-7): 48 imports not on the allowlist, a new `__TEXT` section `__swift_as_cont`, and an autolinked `libswiftCoreLocation.dylib`. The user chose to review each item and allowlist it rather than install Xcode 26.6.
- **Review findings** (source library of each import checked with `xcrun dyld_info -imports`):
  - 30 from libswiftCore: register-specific `swift_retain_xN` / `swift_release_xN` entry points (a compiler optimization, same semantics as retain/release), exclusivity checks `swift_beginAccess/endAccess`, `swift_initStackObject`, `swift_getExistentialTypeMetadata`, the value-witness table for `()`.
  - 15 from SwiftUI: `LazyState` (the new SDK's implementation of `@State`) and metadata/constructors of `Binding / ForEach / Section / EmptyView` (3 are weak imports).
  - `___chkstk_darwin` from libSystem: the stack probe for large frames.
  - `__swift_FORCE_LOAD_$_swiftCoreLocation` and `libswiftCoreLocation.dylib` (weak): in the Xcode 27 SDK SwiftUI transitively imports CoreLocation and Swift autolinks its overlay. The Signer binary uses no CoreLocation API and its Info.plist has no location-permission key, so the system grants it no location capability.
  - `__swift_as_cont`: same structure as the already-allowed `__swift_as_entry` / `__swift_as_ret` (section flags 0, 32-bit relative pointers) — the async continuation table, not code.
  - None of these carries a forbidden capability (network, pasteboard, dynamic loading); the deny lists are unchanged.
- **New check**: `__swift_as_entry / __swift_as_ret / __swift_as_cont` must be relative-pointer tables whose length is a multiple of 4 and whose every entry points inside `__text` (so these allowlisted sections cannot smuggle data or point elsewhere). Verified to fail on a copy with one entry tampered.
- **Result**: the Xcode 27 device build of the Signer passes C4/C5 (799 imports, 27 linked libraries).
- **Cost**: the allowlist grows with the toolchain; `TOOLCHAIN.lock` still says Xcode 26.6 and version enforcement (the other half of audit P1-7) is not done — switching Xcode versions requires reviewing new symbols again.

## D37 · Solana transaction review and signing (2026-10-11, P2c)

- **Scope**: SOL transfers and SPL token (including Token-2022) `TransferChecked`; the Signer supports the three D34 derivation schemes; the Watcher builds, verifies and broadcasts. Off-chain message signing is not supported yet (refused).
- **Message parsing**: legacy and v0; compact lengths only in their shortest encoding; header, duplicate accounts, program indices, account indices and total length (≤ 1232 bytes) are checked the same way as Solana nodes do; an independent Python implementation produced 600 differential vectors that all match.
- **Refused by default**: anything that does not parse strictly; v0 address lookup tables (referenced addresses cannot be verified offline — the threat model had a strong warning, this upgrades it to a refusal); this account not being a signer; System `Assign` / `AssignWithSeed`; SPL `SetAuthority`; a "create associated token account" instruction whose account address does not match the (wallet, token program, mint) derivation; duplicated or unknown ComputeBudget instructions.
- **Strong warnings**: unknown programs; unknown tokens or decimals that do not match a known token; token approvals; closing a token account (when the deposit goes to someone else); durable nonce; `CreateAccount` owned by an unknown program; uncommon system / token instructions; a maximum fee above 0.01 SOL.
- **Recipient verification**: when sending tokens the Watcher always includes "create the recipient's associated token account if missing" (a no-op if it exists); the Signer takes the recipient wallet from it and checks via PDA derivation that it really owns the destination token account before showing "recipient (ownership verified)"; without that instruction only the token account is shown, with a note that ownership cannot be verified. The PDA "not on curve" test uses ed25519-compact's public validation; derivations match 60 vectors from an independent Python implementation.
- **Fees**: 5000 lamports × signatures + ⌈compute-unit price × limit / 10⁶⌉; without a limit, 200 000 units per instruction up to 1.4 million; the display shows "maximum fee" (separate style), "maximum total deducted (amount + maximum fee)" and any possible account deposit. The Watcher's three priority tiers use the 25th / 50th / 75th percentiles of `getRecentPrioritizationFees`, with standard at least 1000, fast at least twice standard, all capped at 10⁷ micro-lamports; custom values are allowed. Balances are checked before building.
- **Signing**: the session keeps only the m/44'/501' node and derives child nodes on demand; Ed25519 deterministic signatures, self-verified after signing; matches the RFC 8032 official vectors. The Signer checks that the address declared in the request is the one derived from the path (a wrong account type or index is refused with `AW_ERR_SOL_REJECT_BASE - 9`).
- **Watcher**: import by scanning the address QR on the Signer's address page and choosing the same account type and index; the node registry checks mainnet / devnet by genesis hash; after broadcasting, the signature returned by the node must be this transaction's signature.
- **Error codes**: `AW_ERR_SOL_REJECT_BASE = -400`, reasons 1–12 pinned by tests in both FFI crates; Watcher ABI 4 → 5.
- **Not done**: off-chain message signing, multi-signer transactions, address lookup tables, staking and dApp transactions; testnets other than devnet; an actual broadcast from the devices (needs devnet test coins).

