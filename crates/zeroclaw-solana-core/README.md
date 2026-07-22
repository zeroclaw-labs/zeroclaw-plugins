# zeroclaw-solana-core

**Track E entry** (shared core / infrastructure prize): a clean,
MIT/Apache-2.0-licensed, `wasm32-wasip2`-friendly Solana substrate — base58,
Borsh, hand-rolled versioned-transaction construction, durable-nonce
handling, zero-copy Token-2022 parsing, and JSON-RPC shaping over an
injected `HttpTransport` — that both [`token-risk-check`](../../plugins/token-risk-check)
and [`depin-attest`](../../plugins/depin-attest) actually import for their
real logic, not just link against for show.

## Why this exists

> "`solana-client` is not going to give it to you inside a WASM component...
> Expect real friction compiling the standard stack for `wasm32-wasip2`
> inside a WIT component." — this bounty's own "traps" section.

`solana-sdk`/`solana-client`/`solana-program` are not `wasm32-wasip2`
components-friendly. This crate has zero dependency on any of them — only
`borsh`, `serde`/`serde_json`, `bs58`, and `base64` — and carries no
tool-specific orchestration or WIT/`wit-bindgen` code at all. It builds and
tests on a plain host target with `cargo test`; a plugin importing it never
needs a wasm toolchain just to run its own tests.

## What's in here

- **`crypto`** — `Pubkey`/`Signature`/`Blockhash` newtypes over fixed-size
  arrays, base58 in/out, the `SysvarRecentBlockhashes` constant.
- **`transaction`** — the actual Solana wire format, hand-rolled:
  `MessageHeader`, `CompiledInstruction`, `LegacyMessage`, `MessageV0`,
  `VersionedMessage`, `VersionedTransaction`, plus `Instruction`/
  `AccountMeta` builder types, account-ordering/compilation
  (`compile_legacy_message`), and `build_durable_nonce_transaction` — the
  answer to the bounty's blockhash-expiry "trap": a normal blockhash expires
  in ~150 blocks, which a transaction sitting in a human approval queue will
  blow constantly; a durable nonce doesn't expire until explicitly advanced.
- **`rpc`** — an `HttpTransport` trait (each plugin supplies its own `waki`-
  backed implementation, gated to the wasm build only — this crate never
  depends on `waki` at all), JSON-RPC request shaping for `getAccountInfo`/
  `getTokenLargestAccounts`, and a zero-copy Token-2022 mint parser.
- **`guardrails`** — `enforce_limits`/`enforce_destination`/
  `GuardrailContext`: structural spend/destination caps for any future
  transfer-shaped plugin built on this crate. (Neither current plugin needs
  these directly — `token-risk-check` is read-only and `depin-attest` moves
  zero lamports — but they're part of the reusable substrate for Tracks A/B.)

**Byte-compatible transactions without `#[derive]` everywhere.** Solana's
wire format uses "compact-u16" (shortvec) length prefixes, not Borsh's
default u32-LE prefix, and a legacy message carries no version-tag byte at
all. `ShortVec<T>` and `VersionedMessage` therefore have hand-written
`BorshSerialize`/`BorshDeserialize` impls; everything else derives normally.

**Untrusted-byte parsing never indexes or allocates on faith.** Every read
in the Token-2022 parser goes through `.get()`/`checked_add` instead of
direct indexing or unchecked arithmetic, and `ShortVec`'s Borsh decode never
pre-allocates based on an attacker-claimed length. Both were fixed after
being caught by differential/property testing, not designed in from the
start — see "Hardening pass" below.

## Building

```bash
cargo test                          # host tests, no wasm toolchain needed

# Supply-chain / license policy (see deny.toml)
cargo install cargo-audit cargo-deny
cargo audit
cargo deny check

# Fuzzing (Linux/macOS only -- see the fuzz feasibility note below)
cargo install cargo-fuzz
cargo +nightly fuzz run shortvec_differential
cargo +nightly fuzz run token2022_parser_no_panic
```

This crate is a plain library (`crate-type = ["rlib"]`), not a wasm
component itself — there's nothing to `cargo build --target wasm32-wasip2`
here directly; that happens in each consuming plugin.

## ✅ Verified build status

Compiled and tested with `rustc`/`cargo 1.97.1`:

| Command | Result |
|---|---|
| `cargo test` (host) | **40/40 passed**, 0 failed |
| `cargo clippy --all-targets` | clean, 0 lints |
| `cargo deny check` | advisories/bans/licenses/sources all ok |
| `cargo audit` | 0 vulnerabilities (3 informational, all dev-only, see below) |

### Hardening pass

Adversarial-input testing found four real bugs — none reachable through
either plugin's tool flow as originally called, but all real divergences
from correct/safe behavior:

- **`ShortVec` premature allocation.** `Vec::with_capacity(len)` sized a
  buffer directly off an attacker-claimed shortvec length (up to `u16::MAX`)
  before validating a single byte existed. Nested `ShortVec`s (e.g. every
  `CompiledInstruction` inside a `ShortVec` of instructions) could amplify a
  tiny malicious payload into many large upfront allocations. Fixed by
  growing the `Vec` as bytes are actually read.
- **`decode_shortvec_len` diverged from the canonical wire format** in three
  ways, found by differentially fuzzing it against the real `solana-short-vec`
  crate (via `proptest`, and a `cargo-fuzz` target for CI): it accepted
  non-minimal ("aliased") encodings like `[0x80, 0x00]` for the value 0,
  accepted a third byte with the continuation bit still set, and never
  validated the accumulated value actually fit in `u16`. All three are now
  rejected, matching the canonical decoder exactly (see the doc comment on
  `decode_shortvec_len`).
- **An off-by-one in the Token-2022 mint bounds check** required 1 fewer byte
  than the subsequent field read actually used — unreachable in practice
  (the outer `MINT_BASE_LEN` guard already ensures enough bytes), but latent.
  Fixed by rewriting the whole parser to use `.get()`/`checked_add`
  throughout instead of hand-verified index arithmetic.
- **A self-referential guardrail** in an earlier draft of `depin-attest`
  checked a caller-supplied fee against a ceiling built from that *same*
  caller-supplied value, so the check could never fail. Fixed by moving all
  account identities to trusted config-only resolution (see that plugin's
  own README for the current, correct design — the fee-cap concept itself
  was later removed entirely once memo instructions, which move zero
  lamports, replaced the placeholder attestation-program design).

Verification methods used, and why each was chosen:

- **`proptest`** (runs on stable Rust, no special tooling): round-trips and
  differential checks against `solana-short-vec` and `spl-token-2022`, plus
  a "never panics on arbitrary bytes" property for the Token-2022 parser —
  512 randomized cases per run.
- **`spl-token-2022`/`solana-program`/`solana-short-vec` as dev-only
  dependencies**: differentially verifies `MINT_BASE_LEN`/`ACCOUNT_TYPE_OFFSET`/
  the six extension-type constants and parsed field values (including
  `supply`) against the canonical crates' own pack/extension APIs — not
  just self-consistency with hand-built fixtures. Confirmed via
  `cargo tree -e normal` that none of these reach the shipped rlib or
  either plugin's `.wasm` binary; they're dev-dependencies only.
- **`cargo-fuzz`**: the fuzz targets exist and build cleanly (`fuzz/`), and
  run in CI on Linux, but **do not work on this Windows authoring host** —
  verified directly, not assumed: the ASan build links (there is an MSVC
  toolchain present, just not on `PATH`) but the compiled binary fails at
  launch with `STATUS_DLL_NOT_FOUND` (the ASan runtime DLL needs a separate
  LLVM/Clang install); the no-sanitizer build fails to *link* at all
  (`__start___sancov_cntrs` unresolved — SanitizerCoverage's counter-section
  registration is a PE/COFF-vs-ELF incompatibility, not fixable by
  installing one more component). `proptest` is the practical local
  substitute; the fuzz targets are still real and run in CI.
- **`wasm-opt` (Binaryen)**: does not support the Component Model binary
  format at all yet ([binaryen#6728](https://github.com/WebAssembly/binaryen/issues/6728))
  — confirmed locally, it refuses to even parse a `wasm32-wasip2` component.
  Size discipline instead comes from each plugin's own release profile
  (`opt-level = "s"`, LTO, strip, `codegen-units = 1`), which is working
  well: both plugins land under 25% of the 1.5MB budget. See each plugin's
  own build output for current numbers.
- **`cargo-audit`/`cargo-deny`**: both installed and run locally against
  this crate's actual dependency tree (not configured blind); `deny.toml`
  reflects the real license set and dependency shape observed. The 3
  informational `cargo-audit` warnings (`bincode`/`libsecp256k1` unmaintained,
  `rand` 0.7.3 unsound) are all reachable *exclusively* through the
  differential-testing dev-dependencies (`spl-token-2022`/`solana-program`),
  never through the shipped code.

### Still worth independently verifying

Nothing here blocks a build, but this is an assumption that couldn't be
checked against a live network or a canonical crate:

- **The `SysvarRecentB1ockHashes11111111111111111111` constant** is correct
  per the documented Solana format, but (unlike the Token-2022 TLV offsets
  and extension-type constants, which are differentially verified against
  `spl-token-2022`) there's no equivalent canonical-crate check available
  for a bare sysvar address constant.
