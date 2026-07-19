# M4 Results — Durable Nonce Mode (isolated experiment)

**Verdict: M4 PASS.** All 20 promotion-gate conditions met, including the
focused read-only M4 security audit (zero Critical, zero High). Eligible to be
proposed for promotion; PR #54 and the frozen tags were not modified, and
promotion remains a separate maintainer decision.

This is an isolated experiment on disposable branches. The frozen M3.5 submission
and its fallbacks are untouched.

## Starting commits and tags

| Repo | Disposable branch | Base |
|---|---|---|
| zeroclaw-solana (nanosol) | `agent/m4-durable-nonce-experiment` | `989cd0d3bd25ce6a2d796f72c0dc6a4ae56d989f` |
| zeroclaw-plugins | `agent/m4-durable-nonce-experiment` | `95e10dc1b8ec4c796b22d50ffc63136e462eaf0a` |

Frozen (unchanged): `m35-security-freeze-95e10dc` → `95e10dc…`,
`m3-known-good-3f7f8e9` → `3f7f8e9a5db1a7d7c626d1f22ace166cd0d02b17`.
PR #54 head = `95e10dc…` (draft, frozen M3.5) — not modified. Working trees clean
apart from the M4 commits below.

## Official sources and versions (host dev-dependency oracles)

`solana-nonce 3.2.0` (features serde), `solana-system-interface 3.2.0` (features
bincode), `solana-sdk-ids 3.1.0`, plus the existing `solana-message 4.3.0`,
`solana-transaction 4.1.5`, `solana-instruction 3.4.0`, `solana-pubkey 4.2.0`,
`solana-hash 4.5.0`, `bincode 1.3.3`. Primary docs: Agave "Durable Transaction
Nonces" implemented proposal, Solana core `durable-nonces` docs, and the
`simulateTransaction` RPC reference. Toolchain `cargo +1.96.1`. Devnet RPC
`https://api.devnet.solana.com` (solana-core 4.2.0-beta.1), Agave CLI 3.1.13.

## Phase-A spike verdict: PASS

All eight Phase-A conditions passed (full detail in
`../../spikes/durable-nonce/M4_SPIKE_RESULTS.md`):

1. Official nonce-account bytes parsed correctly (oracle + a real devnet account).
2. Official `AdvanceNonceAccount` bytes match exactly.
3. Runtime account order / signer / writable requirements proven.
4. Simulation works without blockhash replacement.
5. Unsigned durable tx survived ≥ 5 min (379 s; the T0 recent blockhash had
   already expired by 256 s).
6. External signing & submission finalized.
7. Nonce before/after preserved (unchanged across the hold; advanced on execution).
8. No production behavior modified during Phase A.

Phase-A devnet signature (SOL transfer viability):
`3fdropMCZm1Yriy1iTupQTQpMcLxrciAC7YtaVGw7AC8k1avFgkjZUX4NK7wDsboCpSRPtNCFPxa5ps2WKoHK1ig`
— nonce `4vMZqWuEMy9gAa5PWaYVWkQhvLKFquKH62fnzfKcvDkN` → `9ExdJdLpwALYq2WqBUdXMo8yB8r6hGVc3CocMV2Gfjud`.

## Nonce-account format (80 bytes, confirmed)

`[Versions disc u32 LE = Current(1)] [State disc u32 LE = Initialized(1)]
[authority 32] [durable_nonce 32] [lamports_per_signature u64 LE]`. The nanosol
parser is a strict fixed-80-byte reader: it rejects Legacy (version 0),
Uninitialized, unknown version/state discriminants, and any other length. bincode
tolerates trailing bytes; the parser does not.

## AdvanceNonceAccount instruction (confirmed byte-for-byte)

program = System (all-zero), data = `04 00 00 00`, accounts:
`[0]` nonce (writable, non-signer), `[1]` `SysvarRecentB1ockHashes…` (readonly,
non-signer), `[2]` authority (signer). Must be instruction index 0; the message
blockhash must equal the stored nonce.

## Simulation requests and results (devnet)

Durable simulation: `sigVerify=false`, `replaceRecentBlockhash=false`,
`encoding=base64`.

| Case | Result |
|---|---|
| Valid unsigned durable | `err: null`, two System invocations succeed |
| Stale/unknown nonce | `BlockhashNotFound` |
| Wrong authority | `BlockhashNotFound` |
| Invalid later instruction | `InstructionError[1, Custom(1)]` (advance succeeds, transfer fails) |

The plugin additionally refuses if the RPC reports an unexpected
`replacementBlockhash`.

## New immutable nanosol revision

`5d9501408346540332e95611219a15dafd9c2d87` — pushed to
`Fianko-codes/zeroclaw-solana` branch `agent/m4-durable-nonce-experiment`, pinned
by the plugin. (Adds nonce parsing, `advance_nonce_account`,
`decode_advance_nonce_account`, `RECENT_BLOCKHASHES_SYSVAR_ID`,
`simulate_durable_transaction_request`, `SimulationResult.replaced_blockhash`,
`Error::Nonce`.)

## Files changed

nanosol (`989cd0d..5d95014`): `src/nonce.rs` (new), `src/inspect.rs`,
`src/instruction.rs`, `src/pubkey.rs`, `src/rpc.rs`, `src/error.rs`, `src/lib.rs`,
`Cargo.toml`, `Cargo.lock`, `tests/nonce_oracle.rs` (new).

spl-transfer-build (`95e10dc..HEAD`): `src/transfer.rs`, `src/lib.rs`,
`Cargo.toml`, `Cargo.lock`, `tests/durable_nonce.rs` (new),
`tests/transaction_and_mutations.rs` (field additions),
`tests/rpc_and_simulation.rs` (Option field), `README.md`,
`tests/host_chat_mock_durable.py` (new acceptance driver), this file.
Manifest, WIT, and tool input schema unchanged.

## Tests and counts

| Crate | Tests | Notes |
|---|---|---|
| nanosol | 43 | 36 pre-existing + 7 new (nonce oracle) |
| solana-pay-request | 29 | unchanged |
| spl-transfer-build | 71 | 37 recent-mode (unchanged) + 34 durable |

All durable final-byte mutations, mode-confusion, and simulation error cases
fail closed. Recent-mode golden transaction/summary tests unchanged.

## Exact command results (Rust 1.96.1 matrix)

For `nanosol`, `solana-pay-request`, and `spl-transfer-build`, all of:
`cargo +1.96.1 fmt --check`, `cargo +1.96.1 test --locked`,
`cargo +1.96.1 clippy --locked --all-targets -- -D warnings`,
`cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings`,
`cargo +1.96.1 build --locked --target wasm32-wasip2 --release` — **PASS**.

## WASM artifact

`spl_transfer_build.wasm` (durable build, nanosol `5d95014`):
- size: 703484 bytes
- SHA-256: `b170e503a09ca544e1ed31862d3550d284025894082473a775c3f8395a42cb25`

(The artifact is rebuilt by CI and not committed; the hash identifies the tested
build environment. The strict CI validator's isolated rebuild produced 706776
bytes — Cargo artifact bytes differ with absolute source paths, as documented for
M3.)

## Additional validation (CI parity)

- M0 oracle: `spikes/pda-oracle` 9 tests pass; `spikes/wasm-build` wasm release
  builds.
- Repository tooling unittests 17 pass; CI tooling unittests 36 pass.
- `plan_matrix.py --event pull_request` selects exactly `spl-transfer-build`
  (strict).
- Strict `tools/ci/validate_components.sh` (fresh `CARGO_HOME`, isolated target):
  `spl-transfer-build` test_rc=0 (71), clippy_rc=0, wasm_clippy_rc=0, build_rc=0,
  source-mutation guard clean; `solana-pay-request` test_rc=0 (29), all rc=0.
- WIT drift: vendored `wit/v0` is byte-identical to upstream
  `zeroclaw-labs/zeroclaw@e112ce6b5ccdac9e1cb166bab217e730dd7e24c2` (`wit/` was not
  modified).
- Clean clone with a fresh `CARGO_HOME`: a `git clone --depth 1` of the fork
  branch built `spl-transfer-build` `--locked` for `wasm32-wasip2`, resolving the
  pinned nanosol git rev `5d95014` from GitHub.
- **Fork GitHub Actions**: `Validate plugin repository` run
  [29670417765](https://github.com/Fianko-codes/zeroclaw-plugins/actions/runs/29670417765)
  on `agent/m4-durable-nonce-experiment` — conclusion **success**, including the
  required **Validate Required Gate** (Format, Registry contract, Plan matrix, WIT
  drift, Components shards 0–3, Package dry run). The only fmt annotations are
  pre-existing debt in other untouched plugins.
- Packaging/registry: `registry.json` was not modified; the plugins are not in the
  registry and packaging remains a separate maintainer decision, kept out of M4.

## Real host and agent invocation (durable)

Disposable ZeroClaw 0.8.3 config; the plugin was discovered with capability
`Tool` and permissions `HttpClient, ConfigRead`. Durable operator config
(`blockhash_mode="durable_nonce"`, `nonce_account_pubkey=8RxDmwBi…`). Driven by
`tests/host_chat_mock_durable.py` (a deterministic OpenAI-compatible oracle) and
`zeroclaw agent -a m4`. Real host result:

```
M4_AGENT_OK nonce_account=8RxDmwBibTWTKvwFUxXsvDfzmwYdhUaNP1VzSZ8He8Ho
            nonce=AN1TfxqdcRnPoXUaD6xY9eb7puVwAUorLJBbVaUFjThS
            transaction_sha256=3ce3f84a1af0c63c53a5c919632f0696970468dabe3f300593f2ec0730b56d52
```

The plugin made real devnet RPC calls (mint `getAccountInfo`, nonce
`getAccountInfo`, durable `simulateTransaction`) and returned a 550-byte unsigned
durable transaction. Independent decode confirmed: one all-zero signature slot,
v0, one required signer (sender fee payer), message blockhash == the nonce, 0
address lookup tables, 0 trailing bytes, and exactly four instructions —
`AdvanceNonceAccount` (System, data `04 00 00 00`) at index 0, ATA
`CreateIdempotent` (data `01`), `TransferChecked` (data disc `12`, five accounts
including the reconciliation reference), and Memo v3. Component logs carried only
bounded phase labels.

## Real M4 devnet acceptance

Disposable fixture (keys only in the session scratchpad, never in the plugin):

```
sender / fee payer / nonce authority: 7Ery7VUPWNmHptzDxWUxP3EXfzwUjLCn7iDp3w94bnbV
mint (legacy, 6 decimals):            3b3dsEedXw9DWWWmuddapivdMF7AfqYgepapXjRTzbZw
sender ATA:                           7ZvbaU8YngGXhZr1X9dZMLa1jSQvDMRGnbFCF7e1R1vD
recipient owner:                      7Cm6Ms2UL53jSd6ir4p615Q6puASpduzz1DuwcaBc8qG
nonce account (authority = sender):   8RxDmwBibTWTKvwFUxXsvDfzmwYdhUaNP1VzSZ8He8Ho
amount:                               1.5 (raw 1_500_000, decimals 6)
```

- **T0** (plugin built the unsigned durable tx): 2026-07-19T02:13:16Z.
- Held **363 s** (≥ 5 min); nonce re-read immediately before signing and was
  **unchanged** (`AN1TfxqdcRnPoXUaD6xY9eb7puVwAUorLJBbVaUFjThS`, authority = sender).
- Signed externally (spike `durable_devnet sign`, key never in the plugin);
  the signed transaction's message bytes were **byte-identical** to the
  plugin-returned message (`sha256 c70e5f4070346c3f53793deb8bfcecf6b55b6c07088e6b5e851fa6ba8136578b`).
- Submitted externally; public finalized signature
  [`2YrwNvTAvM29ZsSXt9EVYmHsHizAYNCvusdkMr7prN9m1kKf21NNGrVBzfrW1mSJ8VLu1ouNyz3CxX26CxTEE8fL`](https://explorer.solana.com/tx/2YrwNvTAvM29ZsSXt9EVYmHsHizAYNCvusdkMr7prN9m1kKf21NNGrVBzfrW1mSJ8VLu1ouNyz3CxX26CxTEE8fL?cluster=devnet)
  reached `confirmationStatus: finalized`, `err: null`.
- **Token balances moved:** recipient **0 → 1.5**, sender **200 → 198.5**.
- **Nonce advanced** after execution:
  `AN1TfxqdcRnPoXUaD6xY9eb7puVwAUorLJBbVaUFjThS` →
  `EWmLUejtik2VUVYKe9UNqxvZ3mrcHTbba1BBewRZzEi`.
- **On-chain message bytes == plugin-returned message bytes**
  (`getTransaction` message `sha256 c70e5f40…` matches).

## Controlled failure (nonce consumed on later-instruction failure)

Performed on a **separate** disposable nonce account
`7rtVuvFRhiUCcVHQeiEsqgQAb7UgCEiHWvRdK1qNugjn` (the Phase-A nonce, not the
acceptance nonce), built outside the plugin (the plugin simulates and refuses a
failing transaction). A durable transaction with `AdvanceNonceAccount` at index 0
and a System transfer of 100 SOL (deliberately insufficient funds) was signed and
submitted with `skipPreflight`:

- signature `62xgHDbVe4yd849njVkxdb84kTXxDbFMe6Xt1bZ1DZvfHQeZJ9Dn6PFzwv4Gp6oH2y8V9xf7hn5MXzPWsfcPoQ9K`;
- status `confirmed`, `err: InstructionError[1, {Custom: 1}]` — the later transfer
  failed;
- the nonce was nevertheless **consumed / advanced**:
  `9ExdJdLpwALYq2WqBUdXMo8yB8r6hGVc3CocMV2Gfjud` →
  `ETRFV7AXtzJ3vMX51Ws8KTaPdnw6rFXcW7YAwoRdetgL`.

This matches the documented semantics — once nonce validation succeeds, a later
instruction failure still advances the nonce and charges the fee — and is the
exact warning carried in the durable approval summary and README.

## Private-key handling

No private key ever entered `nanosol`, the plugin, its config, or committed
evidence. The disposable sender / nonce / mint keypairs lived only in the session
scratchpad (mode 0600) and are destroyed at the end. External signing was done by
the spike `durable_devnet sign` helper, outside the plugin. The plugin received
only public keys through operator config.

## Corrected assumptions

- **Authority == fee payer is a writable signer at message level.** The raw
  `AdvanceNonceAccount` marks the authority readonly-signer, but when the
  authority is also the fee payer (the M4 arrangement), `Message::compile` merges
  it into the writable-signer at index 0. The decoder therefore requires only the
  signer privilege for the authority; the verifier separately enforces
  `authority == sender == fee payer`.
- **bincode tolerates trailing bytes**; the nonce parser is a strict fixed-80-byte
  reader instead of a bincode call.
- **Stale-nonce vs wrong-authority both surface as `BlockhashNotFound`** in
  simulation (the durable path is rejected, then the normal path fails because the
  value is not a recent blockhash).

## Remaining risks

- The RPC endpoint is a trust boundary: a dishonest RPC can misreport nonce or
  mint state. The plugin nevertheless guarantees the returned transaction is
  internally consistent with the exact nonce state it accepted.
- Durable-nonce transactions consume the nonce and charge a fee even when a later
  instruction fails; this is surfaced in the approval summary and README.
- M4 supports only `nonce authority == sender`; a separate nonce-authority signer
  is intentionally unsupported.

## Deprecation assessment

Durable nonces are fully functional today but Solana's docs carry a
forward-looking notice that they "may be deprecated in a future release" (SIMD
discussion #415 — a discussion, not an activated change). The recent-blockhashes
sysvar is deprecated for on-chain reads yet still required as an
`AdvanceNonceAccount` account. Operators adopting durable mode should track this.

## Focused M4 security audit (promotion gate condition 20)

A focused, read-only adversarial audit of the M4 diff (nanosol nonce/instruction/
inspect/rpc changes and the plugin durable path) returned **zero Critical, zero
High** findings. All nine audited properties hold: no signing/submission/private-
key path; the single-signer invariant (exactly one required signature, one
all-zero slot, authority == sender == fee payer, no second signer is structurally
possible); durable `verify_final_bytes` (AdvanceNonce at index 0 for the
configured nonce/authority/sysvar, message blockhash == parsed nonce, byte-
equivalent canonical recompile — every divergence attack rejected); operator-only
mode selection (`deny_unknown_fields` + host `__config` strip); the nonce trust
boundary (internally consistent accepted transaction); a total, non-panicking
strict parser; bounded output/errors; unchanged recent mode; and an honest
approval summary. Three Low/informational notes only: the host `__config`-strip
dependency (identical to the M3.5 T1 boundary), the RPC-controlled nonce value
(impact bounded because nothing is signed and every transfer field is derived from
policy), and two provably-unreachable `.expect()`s guarded by the length check.

## Promotion recommendation

M4 meets **all 20 promotion-gate conditions**, including the read-only security
audit (zero Critical/High). It is therefore **eligible to be proposed for the
bounty PR**. Per the experiment's terms, this branch does **not** update PR #54 or
touch the frozen tags; promotion (opening/updating the PR) is a separate,
explicit maintainer decision.
