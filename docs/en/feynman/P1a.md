> English translation of docs/feynman/P1a.md. The Chinese original is authoritative.

# P1 Feynman report (first half): Toolchain and supply chain foundation

Date: 2026-10-10 · Status: P1 first half complete; see Section 8 for the independent review conclusions; see `P1b.md` for the second half

## 1. In one sentence

We have built a pipeline that "eats only source code, cooks with the network cut off, and inspects every dish", and used it to make the first Signer skeleton that runs in the iPhone simulator and passes its self-test.

## 2. Explained for a layperson

Imagine a kitchen that uses only its own vegetable garden:

- **Where the vegetables come from**: instead of buying pre-packaged vegetables at the supermarket (the package registry), we go straight to the place of origin (the author's git repository) and pick the vegetables from one particular day and one particular row (a pinned commit); every vegetable is weighed and photographed (a directory fingerprint is computed) and entered in a register.
- **Lock the door and cut the network while cooking**: if the kitchen is missing something, the dish simply doesn't get made; we never order takeout at the last minute.
- **Three checks before serving**: ① do the vegetables match the register (fingerprint); ② has anything unrecognized gotten mixed in (binary scan); ③ does the finished dish contain the "networking" seasoning (symbol check).
- **Every check has to stage a "catch the thief" drill**: deliberately put a pebble in the food and confirm the check really sounds the alarm.

This time we really did run into a "pebble": `hex_lit`, a small library that rust-bitcoin depends on. The 0.1.1 version sold at the supermarket claims to come from a certain row, but there is no such row at the place of origin at all. It isn't necessarily poisonous, but since its origin can't be accounted for, we won't eat it — we grew our own (40 lines of code, with tests).

We also ran into a case of a "check just going through the motions": after the signing library was compiled, the optimizer had deleted our interface functions entirely, so the "no networking seasoning" check passed — because the pot was nearly empty. Once we discovered this, we changed how it is compiled and added a "link probe": a small C program that really calls every interface once; if a single one is missing, it won't build.

## 3. What exactly was done

| Deliverable | Location | Notes |
|---|---|---|
| Toolchain installation and verification | `tools/bootstrap/install-toolchain.sh`, `toolchain/TOOLCHAIN.lock` | Rust 1.99.0 installed in `~/.airgap-wallet-toolchain`, leaving the system untouched; signing public key fingerprint cross-checked against two sources; channel manifest GPG signature verified; rustup-init hash checked; the 2464 component URLs/hashes that rustup actually used match the signature-verified manifest entry by entry |
| Source import tools | `tools/vendor/import.sh`, `tree-hash.sh`, `review-scan.sh` | Accept only https + a 40-character commit hash; verify what the tag points to; disable export-ignore so the complete source tree is exported; automatically generate a review checklist |
| Third-party source (8 repositories) | `third_party/`, `MANIFEST.toml` | rust-bitcoin, rust-secp256k1, hex-conservative, arrayvec, rust-bech32, cc-rs, shlex, python-mnemonic (word list and test vectors only) |
| C library verification | `tools/vendor/verify-libsecp256k1.sh` | libsecp256k1's 153 files = upstream + public patches, byte-for-byte identical |
| Hand-written shim / disabled stub | `core/shims/hex_lit`, `core/stubs/bitcoin-consensus-encoding` | Decisions D11, D12 |
| Offline build configuration | `Cargo.toml`, `.cargo/config.toml`, `rust-toolchain.toml` | crates.io replaced with an empty directory; all 18 packages in the lock file are local paths |
| Rust core | `core/crates/aw-common`, `aw-bip39`, `aw-keys`, `aw-ffi-signer` | Zeroize utilities; hand-written BIP39; BIP32/BIP84; hand-written C interface + startup self-test |
| Check scripts C1–C8 | `tools/checks/`, `tools/probe/`, `tools/repro/` | See R3 in the rules document |
| Signer skeleton app | `ios/Signer/` | Hand-written Xcode project, zero third-party packages; runs its self-test at launch; runs successfully in the simulator |

## 4. How we prove it is right

| Evidence | Result |
|---|---|
| `cargo test --workspace --locked --offline` | All 29 tests pass: 24 official BIP39 vectors (entropy→mnemonic, mnemonic→entropy, seed), 24 BIP32 root private keys, 3 official BIP84 addresses, positive and negative cases for the C interface |
| `cargo clippy -- -D warnings` | Zero warnings in our own code (unwrap/expect/panic forbidden; network and process types forbidden) |
| C1 fingerprints / C2 binaries / C3 provenance | All pass |
| C7 libsecp256k1 verification | 153 files byte-for-byte identical |
| C8 link probe | Both the iOS device build and the simulator build link successfully; running in the iPhone 16 Pro simulator: self-test 0, BIP84 address correct, incorrect mnemonic rejected (-3) |
| C4/C5 on the final app binary | Signer.app has no network-related imported symbols and links only Apple system frameworks and the Swift runtime libraries |
| C6 reproducible (one machine, two paths) | Device build `c3b81bc0…8755`, simulator build `eee06756…bc44`; byte-for-byte identical across the two paths |
| Negative controls | Rename an executable to .txt and put it in the repository → C2 fails; add one space to a third-party README → C1 fails; run C4 against `/usr/bin/curl` → fails |
| Simulator screenshot | `build/screens/p1-signer-selftest.png`: self-test passes; address matches the official BIP84 vector |

**Not verified**: running on a real device (no device), reproduction on a second computer, developer certificate behavior with the network cut off (D1–D4), manual line-by-line review of the third-party source code.

## 5. What I can't explain clearly / am not sure about (knowledge gaps)

| Gap | Why I can't explain it clearly | How to fill it | When to fill it |
|---|---|---|---|
| The Rust standard library's "dead code" still contains file operations | The static library imports `open/opendir/getenv` and others (from the standard library's crash backtrace feature); whether they are completely stripped out of the linked app hasn't been confirmed one by one yet | List all imported symbols of the app binary and explain each one; evaluate switching to a `no_std` core | P1 second half |
| Whether the whole iOS app package can be reproduced byte for byte | So far we've only proven that the Rust static library is reproducible; the Xcode output includes signatures and compiled resources | Build on two Macs, strip the signatures, and compare | P1 second half |
| The third-party source has only had "automated scanning + a first-pass review of the build scripts" | The directories that take part in compilation total about 141,000 lines (measured; including inline tests and precomputed data tables, of which rust-bitcoin `bitcoin/src` is 42,000 lines and libsecp256k1 `src` is 55,000 lines), and no one has read them line by line yet | Manual review in order of risk (first the parts of libsecp256k1 that are actually compiled, and rust-bitcoin's bip32/psbt/address), with conclusions written into `third_party/REVIEW/*.md` | From the P1 second half on, ongoing |
| How long a developer certificate holds up after the network is cut off | No public documentation from Apple | Test D1–D4 on a real device | Needs you to provide an iPhone |
| thiserror / anyhow, recommended in the user rules | They are proc macro dependencies, which conflicts with supply chain rule D6 | Keep hand-writing error types | Decided; they will not be introduced |

## 6. Compared with the plan

- Proceeding according to plan; we additionally did C7 (C library verification) and C8 (link probe), both added after actually running into problems.
- New decisions D11 (hand-written hex_lit), D12 (disabled stubs), D13 (produce only a staticlib).
- The results of the independent code review (Rust review + three rounds of security review) are in Section 8 below.

## 7. Next steps (P1 second half)

1. Write our own UR animated QR code encoder/decoder (bytewords, CRC32, fountain codes), validated against the official Blockchain Commons test vectors.
2. Watcher skeleton app + BTC testnet PSBT: the Watcher builds it → QR code → the Signer parses, displays and signs it → QR code → the Watcher broadcasts it.
3. Test D1–D4 on a real device; reproduce C6 on a second computer.

## 8. Independent review conclusions

Four independent reviews were done in total: one round of Rust code review and three rounds of security review of the supply chain and the iOS shell. The last two rounds were both "re-reviews of the previous round's fixes", and each time the reviewer had to actually get hands-on and try to bypass them. All CRITICAL and HIGH findings have been dealt with, and negative controls were run for them.

| Round | Scope | Findings | Resolution |
|---|---|---|---|
| Rust review | Secret handling and the C interface in `core/` | No CRITICAL/HIGH. 1 MEDIUM: third-party HMAC and `Xpriv` leave residue on the stack — "mnemonic XOR 0x5c" in 8 places (with 12 words, the mnemonic can be recovered directly), and the root private key and root chain code in 1 place each. Plus 7 LOW | `SecretXpriv` is wiped when dropped; PBKDF2 builds the keyed HMAC only once; 64 KiB of stack is wiped before the interface returns. Retest: 0 occurrences across the board. All LOW findings also fixed: added 15/21-word vectors, output parameters cleared on error, pointer alignment checks, C++ guards in the header file, etc. |
| Security review 1 | Toolchain installation, import scripts, check scripts, Xcode project, Swift | 1 CRITICAL: C1 could be bypassed (it "passed" even with MANIFEST missing, hidden directories weren't checked, directory names were treated as regular expressions). 7 HIGH: regex and wildcard holes in C2/C3, Cargo configuration in parent directories, C4 was only a denylist, build-output checks could be silently skipped, the toolchain lock file could be overwritten, Xcode linked unverified libraries | All checks rewritten in `aw.py` (D15); toolchain switched to the official standalone installer with pinned hashes (D14); Signer interface switched to session handles, with secrets only in Rust (D16); Xcode links via explicit `.a` paths; added C9, C10 |
| Security review 2 | Re-review | 4 HIGH: build.rs could rewrite the pinned hashes and allowlists in the repository; `.cargo/config` without an extension wasn't checked; C4 could be bypassed by direct syscalls and by "dlsym pointers in the data section"; `env.sh` failed to clear `XCODE_XCCONFIG_FILE` and similar variables (in a test, this could slip an extra library into the link arguments). Plus 5 MEDIUM | Compilation moved into a sandbox that can only write to `target/`; toolchain directory fingerprint pinned in the repository; strict checking of `.cargo/`; check for `svc` instructions; environment variables cleaned, and the actual link arguments verified before building; all MEDIUM fixed (C2 now walks the file system, allowlists restricted to specific directories, the release gate requires review by two people, etc.) |
| Security review 3 | Re-review | 3 HIGH: build scripts could escape the sandbox through the terminal via `TIOCSTI`; intermediate build outputs in `target/` could be replaced without being detected; C4 couldn't see code outside `__text` or function pointers in the data section | See Section 4 of the P1b Feynman report |

**The biggest lesson**: every round found a real way around the "checks themselves". Check scripts are code too, and they need adversarial review and negative controls just the same; for any "pass", you first have to prove it can "fail".
