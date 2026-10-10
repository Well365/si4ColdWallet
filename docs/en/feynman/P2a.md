> English translation of docs/feynman/P2a.md. The Chinese original is authoritative.

# P2a Feynman report: Ethereum / BNB Smart Chain (EVM chains)

Date: 2026-10-10 · Status: P2a part 1 complete (transfers, tokens, approval recognition, message signing); EIP-712 structured-data signing is left for part 2, and for now the Signer refuses to sign all such requests

> The Feynman method: if you can't explain something in plain words so that a layperson understands it, you haven't truly understood it yourself. Wherever you can't explain clearly is a gap that needs filling.

## 1. In one sentence

The Signer can now also understand and sign the following on EVM chains such as Ethereum and BNB Smart Chain: transfers, token transfers and approvals, and message signing. For content it can't understand or that is high-risk, it either refuses to sign outright, or signs only after the user has confirmed it item by item.

## 2. Explained to a layperson

**One key, many locks**: Ethereum, BNB Smart Chain, Polygon and other EVM chains all use the same set of "address rules", so one account has the same address on all of these chains. What tells them apart is the "chain ID": every transaction states which chain it belongs to (EIP-155), and it is invalid on any other chain. The Signer always puts the chain name and chain ID on the first line.

**"What you see is what you sign"**: on Ethereum, what gets signed is the Keccak hash of a string of bytes. The Signer takes this byte string apart **strictly** (for RLP encoding it accepts only the one canonical form), displays it item by item, and then computes the hash and signature over **that very same byte string**. As long as the parsing is strict, "what is displayed" and "what is signed" cannot possibly diverge.

**The most common scam is an "approval", not a "transfer"**:
- `approve` (approval): once you sign it, the other party can move your tokens away at any time, without needing your signature again. An "unlimited approval" is even more dangerous.
- Another pitfall was found during this phase's review: ERC-20 tokens and ERC-721 NFTs use **the same function number** for `approve`. For the exact same line of data, "0" means "revoke the approval" for a token, but "approve NFT #0" for an NFT. Being offline, the Signer can't tell which kind the contract is, so for any contract it doesn't recognize, it always displays the approval as high-risk and no longer uses the word "revoke".
- Other ways of writing an approval are recognized as well: `increaseAllowance`, Permit2, DAI-style permit.
- A Safe multisig `approveHash` amounts to "approving in advance a transaction whose contents you can't see", so the Signer refuses to sign it outright.

**Message signing can deceive you too**: a web page asks you to "sign a login message". Some characters are invisible to the naked eye, or look exactly like English letters (for example the Cyrillic letter "а"), so the screen shows "example.org" while what you actually sign is a different domain. Now only characters on a whitelist (English letters, digits, common punctuation, Chinese) are displayed as text; everything else is displayed as hexadecimal. In addition, a "message" of exactly 32 bytes is very likely the hash of a transaction; signing it amounts to blind signing, so it is now refused outright (see D33).

**Both phones show the same content**: after the Watcher builds a transaction, it calls **the very same** review code as the Signer, so the content it displays is the same too. The user can compare the two phones line by line. If the Watcher has been tampered with but the Signer has not, the two sides won't match.

## 3. What was actually done

| Deliverable | Location | Notes |
|---|---|---|
| Third-party: Keccak permutation function | `third_party/keccak` (RustCrypto keccak v0.1.2) | Zero dependencies, no unsafe, no build.rs; for why a newer version is not used, see decision D21 |
| EVM module | `core/crates/aw-chain-evm` (about 2300 lines, 18 unit tests) | Keccak-256 sponge, strict RLP, 256-bit integers, transaction parsing (legacy EIP-155 / EIP-2930 / EIP-1559), ABI recognition, EIP-191, `eth-sign-request` / `eth-signature`, review, signing (compiled only into the Signer), watching (compiled only into the Watcher), account QR code |
| Generic display model | `core/crates/aw-common/src/display.rs` | All chains share "title + rows + graded warnings"; BTC has been migrated as well (decision D22) |
| Signer interface v3 | `aw-ffi-signer` | The scanned QR code is handed to Rust as a whole, and Rust decides whether it is BTC or EVM; a high-risk request must carry a "user has confirmed" flag, otherwise Rust refuses to sign |
| Watcher EVM interface | `aw-ffi-watch/src/evm.rs` | Account import, addresses, amount parsing, building transfers, checking signatures, assembling the transaction and re-reviewing it field by field, transaction hash |
| Signer UI | `ios/Signer/Signer/WalletView.swift` | Exports accounts per chain; a unified review screen; when there is a high-risk warning, the user must tick the confirmation box |
| Watcher UI | `ios/Watcher/Watcher/Evm*.swift` | A new "Ethereum / BNB" tab: import, network selection (Sepolia, BSC testnet, Ethereum, BSC), balances (including USDT/USDC), transfers, scanning the signature back, broadcasting and checking the hash; custom nodes are supported, and the node's chain ID is checked |
| Self-test | Signer startup self-test | Adds Keccak public vectors, EVM address derivation, and one real signature with recovery |
| Independent verification tools | `tools/testvectors/ur_hdkey_decode.py`, `keccak_vectors.py` | Pure-Python secp256k1 and Keccak that derive addresses independently; generation of SHA3 differential vectors |
| Checks | C3 / C11 | Dependency isolation now covers EVM (the Watcher must not carry the signing feature); C11's scan scope is now checked against the actual dependency graph |
| Decisions and plan | `docs/en/05` D21–D24, `docs/en/06` | The P2 plan and this phase's four decisions |

## 4. How we prove it is correct

### 4.1 Functionality

| Evidence | Result |
|---|---|
| `tools/cargo-sb test --workspace --all-features --locked` | All 119 tests pass (29 more than at the end of P1: 18 EVM unit, 8 EVM end-to-end, 1 Signer interface, 1 Watcher interface, 1 display model) |
| Public vectors | Keccak (`""`, `"abc"`, the Transfer event signature); the EIP-155 specification's example transaction: signing hash and signed transaction match byte for byte; EIP-55 checksum address examples; EIP-191 `"Hello World"`; the official RLP test cases (including rejection of non-canonical encodings) |
| Differential testing | The same sponge switched to SHA3 padding and compared with Python `hashlib.sha3_256` on 310 inputs (0–300 bytes plus the rate boundaries): all match |
| Known address | Test mnemonic m/44'/60'/0'/0/0 = `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` (the common result in MetaMask and other wallets): Rust tests, the Signer self-test, the simulator UI, and an independent pure-Python derivation — all four agree |
| End-to-end | Watcher builds an EIP-1559 transaction → animated QR code (1 frame dropped out of every 3) → Signer reviews and signs → Watcher checks and assembles → this account's address is independently recovered from the assembled transaction; BSC legacy transaction v = 147/148; message signature v = 27/28; the signatures from the two "devices" are byte-for-byte identical |
| Official build and checks | `build-signer.sh` / `build-watcher.sh`: clear target → compile in the sandbox → copy out of the sandbox → matches C6 → zero Xcode warnings → C1–C5 and C9–C11 all pass; all 731 Signer imports are on the whitelist (the 22 new SwiftUI symbols were added after being reviewed one by one) |
| C6 two-path reproduction | The 4 static libraries match: device Signer `08ec7f05…6ccf`, device Watcher `2b22b643…0d55`, simulator Signer `8ce9c83b…5cdc`, simulator Watcher `ac64b7e5…7a23` |
| Link probe / secret residue | The probe reports `PROBE OK` in the simulator (including exporting an EVM account and rejecting an unknown chain); the stack scan adds two new patterns, EVM account private key and chain code; 0 occurrences for all 11 kinds of secret |
| Simulator demo | Signer restores the test wallet (fingerprint 73c5da0a) → exports the EVM account QR code (`build/screens/p2a-signer-evm-account-qr.png`) → decoded independently from the screenshot: coin type 60, path m/44'/60'/0', address #0 correct → Watcher imports it, shows the same fingerprint and address, and actually queries the balance from a Sepolia node (chain ID check passed, `p2a-watcher-evm-account.png`) |

### 4.2 Refusals to sign and warnings (all covered by tests)

| Scenario | Result |
|---|---|
| Chain ID declared in the request doesn't match the transaction / address mismatch / a path belonging to another wallet / a non-address path | Refuse to sign |
| EIP-7702 (type 4), blob (type 3), legacy transactions without a chain ID | Refuse to sign |
| Safe DELEGATECALL, Safe `approveHash` | Refuse to sign |
| Data type doesn't match the content (a typed transaction posing as a legacy transaction) | Refuse to sign |
| Chain ID so large that EIP-155's v can't hold it | Refuse to sign at the review stage |
| Unlimited / near-unlimited approvals, approvals on unknown contracts (possibly NFTs), Permit2, DAI permit, setApprovalForAll, unknown contract calls, contract deployment | High risk: the UI requires ticking the confirmation box, and Rust checks again as well (messages of exactly 32 bytes are now refused outright, see D33) |
| Watcher: request ID mismatch, tampered signature, a signature from another address, high s value, assembled result differs from the content to be signed, the hash returned by the node doesn't match the transaction | All rejected or reported as errors |

### 4.3 Independent review

| Review | Findings | Resolution |
|---|---|---|
| EVM security review (code reading + running tests) | **No CRITICAL**. The core property "signing hash = hash of the very bytes that were parsed and displayed" holds. 1 conditional HIGH: an ERC-721 `approve` was displayed as ERC-20, so "approve NFT #0" would be shown as "revoke approval". 3 MEDIUM: near-unlimited approvals got only an ordinary notice; the message text filter missed invisible characters and homoglyphs; `increaseAllowance`, Permit2, Safe `approveHash` and others were not recognized. 6 LOW | All fixed, each with a regression test (`review_findings_regressions`): approvals on unknown contracts are always high-risk and never say "revoke"; an "extremely large amount" threshold; messages switched to a character whitelist; 4 more call types recognized, and the Signer refuses to sign `approveHash`; the high-risk confirmation is now enforced in Rust; oversized chain IDs are rejected at review time; a warning for an abnormal priority fee; messages no longer use an unverified chain ID as their title; the Watcher re-reviews field by field after assembling and checks the transaction hash after broadcasting |
| Security review 5 (re-review of P1, read-only) | No CRITICAL / HIGH; 4 MEDIUM fixed | See section 8 of P1b |

## 5. What I can't explain clearly / am not sure about (knowledge gaps)

| Gap | Why I can't explain it clearly | How to fill it | When to fill it |
|---|---|---|---|
| EIP-712 typed data | Not implemented yet; many DApps use it for login, listings, and Permit signatures | P2a part 2: our own strict JSON parsing, computing hashStruct per the specification, recognition of Permit/Permit2/Seaport etc. with high-risk warnings | Next step |
| Unknown contract calls can still be signed (after ticking the confirmation box) | Threat model T5 says "refuse to sign if parsing is incomplete", while the EVM table allows "unknown contract call: strong warning"; the two are in tension | Please decide: should this become "always refuse to sign unknown contract calls" (safer, but many DeFi operations would become unusable) | Needs your decision |
| QR scanning on real devices, real broadcasting | No devices; in the simulator the Chinese input method interferes with automated input, so the transfer UI was only verified as far as "import account, check balance" | Test on real devices; get Sepolia / BSC test coins, then make one real transfer | Needs your help |
| The token list is small | It only includes USDT, USDC and DAI on Ethereum and BSC; other tokens are shown as "unknown contract" with raw values | Assess whether to add more tokens (each one added requires checking its contract address) | During P2 |
| Whether the fee is reasonable | The Signer is offline and can't know the current on-chain fee level; it can only do absolute-threshold checks (gas price > 1000 gwei, priority fee > 100 gwei) | The Watcher could compare the suggested values from several nodes in its UI | During P2 |
| Human review | `third_party/keccak` (about 500 lines) awaits confirmation by two reviewers | Review it together with the other third-party entries | Needs reviewers |
| Apple's nm can't read some object files from the Rust toolchain | In the static library, the `compiler_builtins` member that comes with Rust is newer LLVM bitcode, which the nm bundled with Xcode (an older LLVM) doesn't recognize. The way the Watcher build script was originally written silently swallowed this error (found in this phase and changed to let through only this exact case); C4 checks the linked executable, so it is unaffected | Evaluate bringing in llvm-tools of the same version as Rust (must be verified per R1/R4), or switch to our own Mach-O / ar parser | During P2 |

## 6. Compared with the plan

- Most of P2a was completed according to the plan in `docs/en/06`; EIP-712 was split off into part 2 (until then the Signer refuses to sign all of it, so security is not affected).
- Unplanned but necessary: continued hardening of the build process based on the fourth and fifth rounds of supply chain review (cleaning up background processes, copying artifacts out of the sandbox before linking, removing `dlsym` completely); fixed 1 HIGH and 3 MEDIUM based on the EVM review.
- New decisions D21 (Keccak source), D22 (generic display model and Signer interface v3), D23 (EVM request format and signing conventions), D24 (the Watcher displays the same content as the Signer).

## 7. Next steps

1. **P2a part 2: EIP-712** (our own strict JSON parser, structured hashing, recognition of Permit-type requests).
2. **P2b: DOGE** (reusing the Bitcoin module: legacy P2PKH signing, DOGE addresses, previous transactions must be attached).
3. **P2c: TRON** (reusing Keccak and secp256k1; minimal protobuf decoding; always refuse to sign permission-changing contracts).

What I need you to decide or help with: whether to always refuse to sign unknown contract calls (see section 5); two iPhones, a developer account, a second Mac, test coins, third-party reviewers (same as P1).
