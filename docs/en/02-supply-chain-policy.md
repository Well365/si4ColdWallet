> English translation of docs/02-supply-chain-policy.md. The Chinese original is authoritative.

# 02 · Supply Chain Rules (Mandatory)

Status: P0 frozen · 2026-10-10; revised after three rounds of P1 security review · 2026-10-10 · any exception must be recorded in `docs/en/05-decisions.md` and approved by two people

## Core principle

> **Every line of code that goes into the App must exist in this repository as source code and be traceable to a specific pinned commit in the upstream git repository. The build process does not access any network.**

What you download for an "open-source library" through a package registry (crates.io, SPM, CocoaPods, npm) is a **published package**, which is not necessarily identical to its git source. We do not use published packages; we use only upstream git source.

## R1 · Bringing in third-party code

1. Source may be taken only from the **official upstream git repository**, pinned to a **commit hash**, with proof that the commit is an ancestor of some upstream tag or branch (to avoid picking up a same-named commit from the fork network).
2. Export with `tools/vendor/import.sh` (which internally calls `aw.py import`): `git archive`, overriding the repository's own `.gitattributes` (so that export-ignore, eol, ident, etc. cannot rewrite bytes), and removing `.git`.
3. Register in `third_party/MANIFEST.toml`: name, upstream URL, ref, commit, license, export path, directory-tree fingerprint (NUL-separated, covering file modes, empty directories, and symlinks), import date, reviewers.
4. Manual review is mandatory before import (`tools/vendor/review-scan.sh` generates the complete list, untruncated):
   - Code executed at build time: `build.rs` (including a custom `build = "..."`), proc macros, build-dependencies
   - Binary embedding: `include_bytes!`, `include!`, `#[path]`
   - Network, file system, processes, `dlsym`, `extern {}`, inline assembly
5. **Do not import by default**; anything that can be written clearly in ≤200 lines and verified against official test vectors (e.g. BIP39, bytewords, fountain codes), we write ourselves.
6. **We do not write low-level cryptographic primitives ourselves** (elliptic curves, hashes, HMAC): use upstream source that has undergone long-term review (libsecp256k1, rust-bitcoin hashes).
7. Before release, every entry must have two reviewers and the verdict "同意" (approve) in `third_party/REVIEW/<name>.md` (enforced by `verify-third-party --release`).

## R2 · Build

1. **Cargo can see only the repository**: `.cargo/config.toml` sets `net.offline = true` and replaces crates.io with the empty directory `core/no-registry`; all dependencies point to `third_party/` or `core/` via `[patch.crates-io]`. The SHA-256 of this file is pinned in `tools/awlib/cargo_checks.py`; there must be no other `.cargo/` directory in the repository, and no Cargo configuration of any kind in parent directories or in `CARGO_HOME`.
2. Every build command uses `--locked`; first `source tools/env.sh`, which clears every environment variable that could change the behavior of Cargo / rustc / the compiler / the linker / Xcode, and pins PATH, timestamps, and path mappings.
3. **All Rust compilation goes through `tools/cargo-sb`** (macOS sandbox): network forbidden; may write only to `target/` and `CARGO_HOME`; ioctl and sending signals to other processes are forbidden; may look up only a few system services; may execute only programs from the toolchain, Xcode, and `target/`; runs in a new session with no controlling terminal; if any processes remain in the session after it ends, they are all force-killed and the build is marked as failed (`tools/sb-session.py`).
4. **Official builds start from an empty `target/`** (`tools/ios/build-*.sh` runs `cargo clean` first). Immediately after compilation, the static libraries are copied to `build/lib/`, which the sandbox cannot write to; the subsequent hash check (comparison against the C6 independent build results) and the Xcode link use only this copy, and the hashes are checked once more after linking.
5. The Signer library and the Watcher library **must be built separately** (Cargo unifies the features of all packages within a single build; see decision D1, C3).
6. Xcode projects: **zero Swift Package dependencies**, zero CocoaPods, zero script phases; Rust static libraries are linked via explicit `.a` paths; `xcodebuild` runs under `env -i`, and the effective `OTHER_LDFLAGS` are verified before and after the build.
7. Release builds are performed on a dedicated Mac (or a dedicated virtual machine, or a dedicated user account): no IDE extensions installed, no wallets kept on it, offline during the build.

### Build-time code: trust boundary

`build.rs` scripts and their build-dependencies run on the build machine as the current user. Currently there are only:

| Build-time code | Purpose |
|---|---|
| `third_party/rust-secp256k1/secp256k1-sys/build.rs` (via cc-rs, shlex) | Compiles the C source of libsecp256k1 |
| `third_party/rust-bitcoin/bitcoin/build.rs`, `.../io/build.rs` | Only runs `$RUSTC --version` |

This set is pinned as `BUILD_TIME_CODE` in `tools/awlib/cargo_checks.py` (C3); any addition or removal causes a failure. **The sandbox only narrows what they can do; it is not a complete security boundary**: within the same build, build-time code can still rewrite the intermediate artifacts of other crates in `target/` (demonstrated in practice in the third security re-review). Therefore build-time code must be manually reviewed, and official releases must be built in a dedicated build environment and reproduced by multiple people on different machines (R5).

## R3 · Automated checks (any single failure blocks)

All are implemented by `tools/aw.py` (implementation in `tools/awlib/`; Python standard library only, `python3 -I` isolated mode) plus a few scripts, and are run together by `tools/checks/run-all.sh`:
`--source-only` checks only the source; `--artifacts <artifact…>` additionally checks build artifacts; `--release` further adds online upstream verification, C7, and full Xcode signature verification.

| Check | Command | What it checks |
|---|---|---|
| C1 Source consistency | `aw.py verify-third-party [--release]` | Every entry in `third_party/` (including hidden directories) is registered in MANIFEST with a matching fingerprint; with `--release`, two-person review with the verdict "同意" (approve) is required |
| C2 Binary scan | `aw.py scan-binaries` | Walks the entire repository (without relying on git); every non-text file must be registered by "path + SHA-256" in `BINARY_ALLOWLIST` and may reside only in third-party test/data/image directories; rejects nested `.git` and gitlinks |
| C3 Dependency sources | `aw.py check-cargo` | Every package and every target source resolved by Cargo lies under `core/` or `third_party/` in the repository; configuration files and environment have not been tampered with; the set of build-time code is unchanged; the Signer/Watcher dependency graphs are isolated |
| C4 No network in Signer | `aw.py check-binary` | See "What C4 does and does not do" below |
| C5 Framework allowlist | Same as above | `otool -L` allows only the system frameworks in `signer-libs.allow` |
| C6 Reproducibility | `tools/repro/build-twice.sh` | Two independent from-scratch builds, in two different paths (single machine) / on different machines; the SHA-256 of the four Rust static libraries must match; the result is recorded in `build/repro/c6.sha256`, and official builds are compared against it |
| C7 C library verification | `tools/vendor/verify-libsecp256k1.sh` | The libsecp256k1 bundled in rust-secp256k1 = pinned upstream commit + public patches with pinned hashes, identical file by file (requires network) |
| C8 Link probe | `tools/probe/link-probe.sh` | A C program calls every exported interface and is actually linked (-dead_strip); C4/C5 are run on the output, and a self-test is run in the iOS Simulator |
| C9 iOS sources | `aw.py check-ios-sources` | Only Swift source and a few project files are allowed in `ios/` (Xcode synchronized folders automatically compile any C/ObjC/C++ file placed in them); Signer Swift source must not use forbidden APIs such as network, clipboard, logging, or file APIs (matched on identifier boundaries); Xcode projects must not have script phases or package references; there must be no world-writable directories under `ios/` |
| C10 Disabled stubs | `aw.py check-stubs` | Every disabled stub in `core/stubs/` is byte-for-byte identical to the standard template (containing only `compile_error!`) |
| C11 Assembly and custom sections | `aw.py check-asm` | Source that is compiled into the App (Rust, C/ObjC/C++ with all extensions, Swift) must not contain inline assembly, assembly files, custom sections, naked functions, `@_silgen_name`, etc.; the scan scope is cross-checked against the actual dependency graphs of both Apps (`cargo tree`), and any newly imported third-party code that is missed by the scan causes a failure; exceptions registered in `asm.allow` are pinned by SHA-256 (currently 4, none of which is compiled for aarch64) |
| Upstream verification | `aw.py verify-upstream` | Re-fetches every commit from upstream and confirms that the local source is byte-for-byte identical to upstream (runs with `--release`; requires network) |

Every check must have a "negative control" record: deliberately introduce a violation to prove that the check fails (see the P1 Feynman report).

### What C4 does and does not do

C4 performs static checks on the linked executable; it is **defense in depth, not proof**:

- All imported symbols must be in the `signer-imports.allow` allowlist; network-related symbols (socket, connect, getaddrinfo, URLSession, Network.framework, etc.) are forbidden without exception.
- `dlsym`, `dlopen`, `fopen` are forbidden without exception. The OS version check required by Swift `#available` is provided by our own Rust implementation (which calls dyld's `_availability_version_check` directly), so the compiler runtime's implementation, which would use dlsym, is not linked in (decision D17).
- `os_log` is the only restricted import (it comes from SwiftUI inlined code): at every call site, the format string must be determined by a single string-literal load instruction and be in the allowed set; between the load and the call there must be no rewrites and no jumps into that range, and no calls or branches of any kind (a callee implicitly overwrites the argument registers); in the dyld binding table it may appear only in a GOT slot, and only once (no function pointers may be hidden in data sections).
- All code sections are scanned as raw bytes: no `svc/hvc/smc` (direct system calls that bypass libSystem); direct branches may land only inside code sections.
- Non-code sections of `__TEXT` are executable too: they are scanned for the system call encodings commonly used on Darwin (`svc #0x80`, `svc #0`), as well as any `svc` immediately following a "set x16" instruction. Ordinary data occasionally happens to match the `svc` encoding mask (11 occurrences measured in the Signer), so this is only a heuristic.
- The `__TEXT` segment may contain only standard sections; segments other than `__TEXT` must not have execute permission.

**What static checks cannot rule out**: indirectly calling read-only data (such as `__TEXT,__const`) as code, or deriving the addresses of other functions from the address of a legitimately imported function. C11 can only block syntax that "produces or places machine code" (inline assembly, custom sections, etc.); it cannot stop a pattern like "an ordinary constant array + one pointer cast", so such cases can be found **only through manual review**; at runtime, iOS's own isolation (Airplane Mode, no SIM card, no Wi-Fi, no Apple ID sign-in; see `docs/en/04`) is the last line of defense.

## R4 · Toolchain

- Rust uses the official **standalone installers** (not rustup), installed in the project-dedicated directory `~/.airgap-wallet-toolchain/v2`, without modifying the system or the shell configuration (decisions D10, D14).
- The SHA-256 of the installers and signature files is pinned in `toolchain/PINNED.sha256`; signatures are strictly verified with the official Rust GPG public key (GOODSIG + VALIDSIG with the specified fingerprint are required; revoked/expired/bad signatures are not accepted).
- The fingerprint of the installed directory tree is pinned in `toolchain/INSTALLED_TREE.sha256` and re-verified before every build (`tools/bootstrap/verify-toolchain.sh`).
- Xcode: the Apple signature chain and Gatekeeper are checked before building; with `--release`, full signature verification is performed.

## R5 · Code hosting and release

- All commits are signed; `main` is protected, and merging requires two-person review; accounts use hardware keys for two-factor authentication.
- CI holds no release keys of any kind.
- Release = at least 3 people independently reproduce the build on their own machines → each signs the build hash → published only once the threshold is reached.

## R6 · Dependency upgrades

- An upgrade = a new import: go through R1 again, review `git diff <old-commit> <new-commit>`, and record the review verdict.
- No upgrading just to follow the crowd; upgrade only for security advisories or required functionality.
