> English translation of docs/feynman/P1b.md. The Chinese original is authoritative.

# P1 Feynman report (second half): The "Watcher ↔ Signer" closed loop on Bitcoin testnet

Date: 2026-10-10 · Status: P1 second half complete; three items — real devices, a second computer, and an actual testnet broadcast — need your help (see Section 7)

> The Feynman method: if you can't explain something in plain language so that a layperson understands it, you haven't truly understood it yourself. Whatever you can't explain clearly is a gap you need to fill.

## 1. In one sentence

Two phones can complete a Bitcoin testnet transfer using nothing but QR code scans between them: the Watcher drafts it, the Signer checks it item by item and then signs, and the Watcher in turn checks the signatures and assembles a transaction ready to broadcast. This path already runs end to end in automated tests, and in the simulator we have run the "Signer exports the account → Watcher imports it" segment.

## 2. Explained for a layperson

**How the two phones divide the work**: the Signer is like a notary locked in a safe — never online, and accepting nothing but QR codes; the Watcher is like a secretary who runs errands — able to go online to check balances and draft payment orders, but holding no seal (private key).

**Animated QR codes (UR fountain codes)**: a transaction can be several thousand bytes, which won't fit in a single QR code. We split it into many "postcards" shown in rotation. Each postcard carries several pages of content "mixed together" (XOR). The receiver doesn't need to receive them in order and doesn't mind missing a few; once it has collected enough of them, it can recover the full text the way you solve a system of equations. These rules are a public standard from Blockchain Commons; we wrote our own implementation following the standard and checked it byte for byte against its official test data.

**The notary doesn't take things on trust**: for any payment order the secretary brings, the notary recomputes every number personally, and refuses to sign if a single one doesn't match:

- The complete previous transactions showing "where the money came from" aren't attached → refuse to sign (prevents misreported amounts from tricking you into losing money to fees)
- It claims "the change goes back to your own address", but the computed address isn't yours → refuse to sign (prevents the change from being swapped for an attacker's address)
- It asks for a special kind of signature that "signs only part of it" → refuse to sign
- Inputs that don't belong to this wallet have been slipped in → refuse to sign

**The secretary doesn't take the notary on trust either**: once the signatures come back, the Watcher checks that the transaction content is exactly the same as what it drafted, and verifies every signature using data it computed itself, before assembling the final transaction.

**This time's unexpected discovery — "flavors bleeding together in one wok"**: the Signer and Watcher programs share part of their code. When both were put into the same compilation, the compiler merged the "ingredients" (feature flags) that each side asked for, and as a result, signing code got mixed into the Watcher program. Now they are cooked separately in two woks, and we added a check: if anything signing-related shows up in the Watcher's ingredient list, it raises an alarm.

**The third security review — "someone in the kitchen can reach the owner's keyboard"**: compiling runs third-party build scripts. We had long since locked them in a sandbox (no network access, no writing files wherever they like), but the reviewer found that a program inside the sandbox could "stuff keystrokes" into the owner's terminal; once the owner's terminal read them, arbitrary commands were executed as the owner. Now compilation happens in a new session with no terminal, and the sandbox also forbids stuffing keystrokes, launching other programs, and calling system services.

## 3. What exactly was done

| Deliverable | Location | Notes |
|---|---|---|
| UR animated QR codes | `core/crates/aw-ur` (about 2100 lines, 40 tests) | CRC32, bytewords, strict CBOR, xoshiro256**, sampler, fountain code encoding/decoding, UR encoding/decoding; account (crypto-hdkey, both the old and new tags) and transaction (crypto-psbt) formats; maximum message size limited to 1 MiB, at most 2048 fragments |
| Bitcoin module | `core/crates/aw-chain-btc` (about 850 lines) | Review (`review.rs`, 20 rejection and error reasons, plus warnings such as high fee), signing (`sign.rs`, compiled only into the Signer), watching (`watch.rs`, coin selection, change, combining signatures, compiled only into the Watcher), two-way conversion between accounts and QR codes |
| End-to-end tests | `core/crates/aw-e2e` (11 tests) | Draft → animated QR code → review and sign → animated QR code → combine and verify; one rejection case for each of 8 kinds of attack; signatures from the two "devices" byte-for-byte identical |
| C interface | `aw-ffi-common`, `aw-ffi-signer` (ABI v2, session handles), `aw-ffi-watch` | Secrets live only in the Rust session; every interface that touches secrets wipes 64 KiB of stack before returning (decision D16) |
| Signer app | `ios/Signer/` (7 Swift files) | Generate (system random numbers + optional dice) / back up / restore the mnemonic (built-in word keyboard, third-party keyboards blocked), export the account QR code, scan to review and sign, masking against screenshots and in the background |
| Watcher app | `ios/Watcher/` (5 Swift files) | Import the account by scanning or pasting, check the balance (Esplora API, mempool.space testnet4 by default), draft a payment, scan the signature back, combine and then broadcast |
| Shared UI | `ios/Shared/UI/` | CoreImage generates QR codes, AVFoundation scans them (zero third-party libraries, decision D9) |
| Check tool | `tools/aw.py` + `tools/awlib/` (about 1100 lines) | C1–C5, C9–C11; new C11 (assembly and custom sections) |
| Sandbox and official builds | `tools/cargo-sb`, `tools/sb-session.py`, `tools/ios/build-*.sh` | Hardening after the third and fourth reviews: new session with no terminal, cleanup of leftover processes, build outputs copied out of the sandbox before being verified and linked (Section 8) |
| OS version check | `__isPlatformVersionAtLeast` in `aw-ffi-common` | Replaces the compiler runtime's implementation, which uses dlsym; as a result the Signer no longer imports `dlsym` / `fopen` (D17) |
| Secret residue regression test | `tools/probe/stack_scan.c`, `stack-scan.sh`, `stack_patterns.py` | Scans the stack after calls, in the simulator, to confirm there is no master private key, chain code, seed, account private key, or HMAC-derived value |
| Independent verification tools | `tools/testvectors/` | 15/21-word BIP39 vector generation, decoding QR codes from screenshots, an independent crypto-hdkey decoder |
| Decisions | `docs/en/05-decisions.md` D14–D20 | Standalone installer toolchain, Python checks and sandbox, session handles, restricted imports, separate builds, clearing target, deployment target and clipboard |

## 4. How we prove it is right

### 4.1 Functionality

| Evidence | Result |
|---|---|
| `tools/cargo-sb test --workspace --all-features --locked` | All 90 tests pass (UR 40, common 12, BIP39 11, end-to-end 11, Signer interface 6, keys 4, hex_lit 3, Watcher interface 2, OS version check 1) |
| `tools/cargo-sb clippy --workspace --all-features --all-targets -- -D warnings` | Zero warnings in our own code (only third-party code has warnings; we don't modify upstream) |
| Official UR vectors | The random numbers, sampling, fragmentation, frame-by-frame encoder output, and CBOR from bc-ur's `test.cpp` all match byte for byte; the crypto-hdkey from the BCR-2020-007 specification example matches |
| Link probe (run inside the simulator) | `PROBE OK`: self-test, bad checksum rejected, master fingerprint 73c5da0a, account QR code round trip, garbage transaction rejected |
| Simulator demo | The Signer generates a wallet (fingerprint 86e21cbf) and displays the account QR code (`build/screens/p1b-signer-account-qr.png`); an independent decoder extracts from the screenshot: crypto-hdkey, CRC correct, fingerprint 86e21cbf, path m/84'/1'/0', testnet; after importing the same account, the Watcher shows the same fingerprint and the address `tb1q22aj2l3hasv2skgy7sgghetmvs3zlk0cwve5u2` (`p1b-watcher-account.png`) |

### 4.2 Security and supply chain

| Evidence | Result |
|---|---|
| `tools/ios/build-signer.sh sim` | Clear target → compile in the sandbox → copy to `build/lib/` → matches the C6 result (`6a6714ae…6d29`) → Xcode build (zero warnings) → re-verify the copy after linking → C1–C5, C9–C11 all pass; all 724 imports in the output are on the allowlist, **no longer including `dlsym` / `fopen`** (21 symbols no longer used were removed from the allowlist at the same time) |
| `tools/ios/build-watcher.sh sim` | Same as above; the Watcher library matches C6 (`4e73de21…0d40`), and there are no signing-related symbols in the library |
| C6 one machine, two paths (re-run after the re-review 4 fixes) | All 4 static libraries match: device Signer `544096d1…b59e`, device Watcher `c002bf69…4312`, simulator Signer `6a6714ae…6d29`, simulator Watcher `4e73de21…0d40` (because of the newly added OS version check function, the hashes differ from those at re-review 3; the sandbox hardening from re-review 3 did not itself change the outputs) |
| Secret residue scan (simulator) | Positive control: 10 hits; all 9 secret patterns: 0 hits |

### 4.3 Negative controls (proving the checks can fail)

| Control | Expected | Actual |
|---|---|---|
| A malicious build.rs run in a terminal tries 13 kinds of escape (TIOCSTI injection ×4, launching open/osascript/launchctl/python3/curl, writing outside the repository, writing to `/private/var/folders`, going online) | All fail | Old sandbox: the injected commands were executed by the user's terminal, and open and osascript succeeded; new sandbox: all 13 fail |
| C4: dlsym pointer placed in the data section | Caught | Caught (binding location `__DATA,__data`) |
| C4: an allowed literal placed before the call as a decoy | Caught | Caught (the argument can't be determined statically) |
| C4: machine code placed in a custom section `__TEXT,__aw` | Caught | Caught (non-standard section + jump out of the code section) |
| C4: `svc #0x80` in `__text` | Caught | Caught (reported in both places: disassembly and raw bytes) |
| C4: a naked function placed in the allowed section `__TEXT,__const`, then reached with bl | Caught | Caught (jump out of the code section) |
| C4: fopen with "w" mode | Caught | Caught |
| C4: a data pointer pointing into `__TEXT,__const`, then called indirectly | Can't be caught (known limitation) | Passes — written into `docs/en/02`, with C11 and manual review as the backstop |
| C11: add one line of `asm!` to one of our own crates / add `@_silgen_name("socket")` in Swift / change one byte of a registered assembly file | Caught | All three caught |
| C3: a Watcher dependency requests the `signing` feature / a Signer dependency requests the `watch` feature | Caught | Both caught |
| Secret residue scan: temporarily remove stack scrubbing and recompile | Residue found | Account chain code found 1 time → `STACK SCAN FAIL` |
| C2: a `.pyc` accidentally left behind when the check tool ran | Caught | Caught (a real accident: since then the check tool has been forbidden from writing bytecode) |
| Re-review 4: build.rs launches a background process detached from the process group, which rewrites `target/` after 7 seconds | Build fails before the rewrite can happen | `[cargo-sb] 构建结束后会话中仍有进程（已强制结束）` ("processes still remained in the session after the build ended (force-terminated)") → build fails; the marker file never appeared |
| Re-review 4: a callee implicitly overwrites dlsym's argument registers via a 128-bit return value | Caught | Argument tracking returns "can't determine"; and dlsym is now forbidden outright (reported as soon as it is bound) |
| Re-review 4: machine code written as an ordinary C constant array and called through a pointer | Caught | Caught (`svc #0x80` encoding appears in a data section + jump out of the code section) |
| C9: put a `.m` file in the Signer source directory | Caught | Caught (file type not allowed in `ios/`) |
| C11: put a `.mm` file with inline assembly in `core/` | Caught | Caught |

## 5. What I can't explain clearly / am not sure about (knowledge gaps)

| Gap | Why I can't explain it clearly | How to fill it | When to fill it |
|---|---|---|---|
| Whether it runs and scans properly on real devices | No devices; the simulator has no camera, so for the scanning screen we only verified that it opens | Hands-on testing with two iPhones: export the account, scan animated QR codes back and forth, sign | Needs you to provide two iPhones and a developer account |
| A real broadcast on testnet | Test coins require a faucet, and faucets require passing a CAPTCHA (which I can't do for you); the Watcher's "refresh balance" reported no errors, but the returned data hasn't been independently verified | After you claim a small amount of testnet4 coins, go through the complete flow and check it in a block explorer | Same as above |
| Static checks are not proof | C4 can't rule out "indirectly calling read-only data as code"; nor can it rule out working out other functions' addresses from a legitimate function's address | Rely on C11 + manual review + runtime isolation (airplane mode, etc.); evaluate switching to a `no_std` core to shrink the import surface | Evaluate during P2 |
| The 734 imported symbols from Swift and the system libraries | Reviewed only by category (SwiftUI, AVFoundation, CoreImage, etc.), not explained one by one | For the Signer, annotate the purpose of each one, written as comments in the allowlist | Before P2 |
| Manual review of the third-party source code | About 141,000 lines are still PENDING; `--release` fails because of this | First review the parts of libsecp256k1 that are actually compiled, rust-bitcoin's bip32/psbt/address, the three build.rs files, and cc-rs | Needs two reviewers (could be you and one other person you trust) |
| Build-time code can still tamper with things within the same build | The sandbox can only narrow the scope; it is not a boundary (tested in practice in review 3) | Dedicated build Mac / virtual machine + several people reproducing on different machines | Before release |
| The secret residue scan only covers the stack, 12 words, an empty passphrase, and the simulator | Copies on the heap are wiped on the Rust side, but this hasn't been verified by scanning; stack frame sizes on a real device may differ | Extend to the heap, 24 words, and passphrases; run on a real device | During P2 |
| The compiler warning that `rust-objcopy` can't find `libLLVM.dylib` | The standalone installer's directory layout doesn't match the path rust-objcopy searches; this only affects symbol stripping of the "build script executables", not the app's static libraries (C6 matches) | Find out whether this is a known issue with the official installer | Low priority |

## 6. Compared with the plan

- Planned: UR, BTC review/signing/watching, the two app skeletons, end-to-end tests — all complete.
- Unplanned but necessary: all the problems exposed by the three rounds of security review fixed; toolchain switched from rustup to the standalone installer (D14); check scripts rewritten in their entirety (D15); Signer interface switched to session handles (D16); found and fixed the "flavors bleeding together in one wok" problem (D18).
- Postponed: real-device testing, reproduction on a second computer, an actual testnet broadcast — all of them need your devices or your actions.

## 7. Next steps

What you need to do (I can't do these):

1. **Two iPhones + a paid Apple developer account**: real-device testing of installing the Signer with the network cut off, how long the developer certificate stays valid offline (D1–D4 in `docs/en/04`), and scanning animated QR codes back and forth.
2. **A second Mac**: run `tools/repro/build-twice.sh` and compare against this machine's 4 hashes (the real C6).
3. **Claim testnet4 test coins** (the faucet requires a CAPTCHA): once they're sent to the address the Watcher displays, we'll go through a complete transfer.
4. **Two reviewers**: review the third-party source code following the checklists in `third_party/REVIEW/`.

What I'll do next (P2):

1. Ethereum / BNB Chain module (EIP-1559 transactions, field-by-field display of EIP-712 structured signatures).
2. Solana, NEAR, TRON, DOGE modules, reusing the same "review → sign → Watcher re-review" framework.
3. Turn each chain's dangerous-operations list (unlimited approvals, program upgrades, delegation, etc.) into refusals to sign or red warnings.

## 8. Independent review conclusions

| Round | Findings | Resolution |
|---|---|---|
| Security review 3 | 3 HIGH: ① a build script injects keystrokes through the terminal via `TIOCSTI` and escapes the sandbox; ② intermediate build outputs of unchanged crates in `target/` can be replaced, and Cargo won't notice; ③ the disassembly check only looks at `__text`, and can't see code in custom sections or dlsym pointers in the data section | ① New session with no terminal + ioctl / system services / executing other programs forbidden (the 13 controls in Section 4.3); ② official builds clear target first, outputs are compared against C6, and `docs/en/02` spells out the trust boundary for build-time code (D19); ③ section allowlist, raw-byte scan, jump-target check, dyld binding check, argument-register tracking, plus C11 at the source level |
| Security review 4 (re-review of the review-3 fixes) | 3 HIGH: ① a build script can leave behind a background process that replaces the static library after the C6 check and before Xcode links it; ② a callee can implicitly overwrite argument registers, bypassing the dlsym call-site check; ③ "an ordinary constant array used as code" is not caught by C11, and the non-code sections of `__TEXT` aren't scanned either; C11 missed the ObjC/C++ extensions | ① Cleanup of leftover processes in the session (any leftover means failure) + outputs copied to `build/lib/`, which the sandbox can't write to; verification and linking use only the copy, which is re-verified after linking; ② eliminated at the root: we implement the OS version check ourselves, and `dlsym` / `fopen` are forbidden outright; the tracking for `os_log` is judged a failure as soon as it hits any call/jump; ③ scan all sections of `__TEXT` for syscall encodings; C11 covers all C-family extensions; C9 forbids non-Swift source code in `ios/`; `docs/en/02` states honestly that "constant arrays used as code" can only be caught by manual review |
| Security review 5 (re-review of the review-4 fixes) | While running experiments, the reviewer was interrupted by a safety classifier and switched to a read-only code review: **no CRITICAL / HIGH**. 4 MEDIUM: a missing C6 baseline only produced a notice, not a failure; C11 skipped build/target directories at any depth; C11's scan list was hard-coded (it missed the newly introduced keccak); `sb-session.py` didn't handle Ctrl-C. Plus several LOW | All 4 MEDIUM fixed: a missing baseline now means failure (let through only when `AW_ALLOW_NO_C6=1` is set explicitly); C11 skips no subdirectories; C11 uses `cargo tree` to check the scan list against the two apps' actual dependencies; the whole child session is ended on receiving an interrupt signal. LOW items fixed: the `asm !` spelling, ret with no operands, getsid ignores only "process doesn't exist / no permission", an nm failure on the Watcher now means failure, Package.swift and symbolic links anywhere in `ios/`, xcode-select must point to Xcode.app |
