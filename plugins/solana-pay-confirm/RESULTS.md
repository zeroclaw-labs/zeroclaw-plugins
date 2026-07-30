# `solana-pay-confirm` — M5 results

Evidence for the third and final component of the ZeroClaw Solana submission,
which closes the payment path: **request → build → confirm**.

Every claim below is a command that was executed. Where something was *not*
achieved, it is stated as not achieved, with the blocker and the exact steps that
would finish it.

## 1. Environment

```text
rustc          1.96.1 (31fca3adb 2026-06-26)   # the pinned CI toolchain
host           x86_64-unknown-linux-gnu, Linux 7.1.5-arch1-1
target         wasm32-wasip2
host runtime   zeroclaw 0.8.3 (release, WASM plugin host)
shared core    nanosol rev 2093879cd1cc28c6182386706d70b8a56b3b07be (immutable)
plugin source  c26da355c1243bc75cf6b99f2353e007b3742651
```

All three plugins in this fork are pinned to the same immutable `nanosol`
revision, so the reference derivation cannot differ between request and confirm.

## 2. Full validation matrix, on the pinned toolchain

Run through the repository's own validator (`tools/ci/validate_components.sh`),
which is the same script the `Validate Required Gate` job runs. It snapshots the
committed plugin, runs the four commands, materialises the artifact, and diffs
the tree afterwards to prove the build mutated no source.

| Plugin | `test --locked` | clippy host | clippy wasm | `build --locked --release` |
|---|---|---|---|---|
| `solana-pay-confirm` | 62 passed / 0 failed / 0 ignored | rc 0 | rc 0 | rc 0, 645 147 bytes |
| `solana-pay-request` | 30 passed / 0 failed / 0 ignored | rc 0 | rc 0 | rc 0, 229 624 bytes |
| `spl-transfer-build` | 71 passed / 0 failed / 0 ignored | rc 0 | rc 0 | rc 0, 704 259 bytes |

Both clippy invocations used `-D warnings`. No source mutation was detected for
any plugin. The re-pinned `solana-pay-request` and `spl-transfer-build` suites
pass unchanged against the new core revision — the new primitives are additive.

Artifact built with the documented command from the plugin directory:

```text
plugins/solana-pay-confirm/manifest.toml  wasm_path = solana_pay_confirm.wasm
sha256  e58a8a393585dc44b07f79b5734250c82830f3b861c640e31f4f9114cfd24f10
bytes   644188
```

(The validator builds from a snapshot directory, so its artifact differs from the
in-tree build by the embedded crate path and is 645 147 bytes; both were produced
from source `c26da35`.)

Repository gates, run separately:

```text
cargo +1.96.1 fmt --manifest-path plugins/<each>/Cargo.toml --all -- --check   # clean, all three
structure guard: manifest.toml + Cargo.toml + Cargo.lock present in every plugin dir
tools/build-registry.py --check-history  → preserves 24 generated release entries, 0 refreshes
tools/build-registry.py --check-metadata → matches 12 indexed canonical entries;
                                           pending unpublished source: solana-pay-confirm@0.1.0
python3 -m unittest discover -s tools/ci/tests → 36 tests, OK
```

`registry.json` was not edited. `solana-pay-confirm@0.1.0` is reported as a
pending unpublished source, exactly like the other two components.

## 3. Real host, real component, real mainnet (read-only)

The authoritative artifact and its manifest were copied into a disposable
ZeroClaw 0.8.3 plugin directory. Host discovery:

```text
$ ZEROCLAW_CONFIG_DIR="$M5_HOST" zeroclaw plugin list
  solana-pay-confirm v0.1.0 — Confirm that a Solana Pay request was actually paid,
  verified from raw transaction bytes and reconciled against the recipient's balance delta

$ ZEROCLAW_CONFIG_DIR="$M5_HOST" zeroclaw plugin info solana-pay-confirm
  Capabilities: [Tool]
  Permissions:  [HttpClient, ConfigRead]
```

A deterministic OpenAI-compatible oracle (`tests/host_chat_mock.py`) drove one
real two-turn agent run against `https://api.mainnet-beta.solana.com`:

```bash
python3 plugins/solana-pay-confirm/tests/host_chat_mock.py \
  --port 38191 --recipient ERajJRamvLoNyDmboTE6JjR4rPp16ZHdTwcnqcMz7kjH \
  --amount 1.5 --mint USDC --invoice m5-mainnet-readonly-2026-07-30 \
  --expect-paid false --capture "$M5_HOST/verdict-mainnet.json"

ZEROCLAW_CONFIG_DIR="$M5_HOST" zeroclaw agent -a m5 \
  -m 'Confirm whether invoice m5-mainnet-readonly-2026-07-30 for 1.5 USDC to
      ERajJRamvLoNyDmboTE6JjR4rPp16ZHdTwcnqcMz7kjH has been paid.'
```

Agent result:

```text
M5_AGENT_OK paid=false reference=2m1xGkYy7wzQahXH8rdCTS47AoGXovRGHwL7wA9iCHQ2
            expected_raw=1500000 match_count=0 bytes=645
```

Full verdict returned to the model (645 bytes, against a 4 000-byte ceiling):

```json
{"paid":false,
 "mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
 "recipient":"ERajJRamvLoNyDmboTE6JjR4rPp16ZHdTwcnqcMz7kjH",
 "reference":"2m1xGkYy7wzQahXH8rdCTS47AoGXovRGHwL7wA9iCHQ2",
 "expected_raw":"1500000","match_count":0,
 "reason":"no transaction referencing this invoice was found in the most recent 10 signatures for its reference",
 "summary":"NOT PAID: no settled transfer of 1.5 USDC (EPjF…Dt1v) to ERaj…7kjH matches invoice
            'm5-mainnet-readonly-2026-07-30' · … · this verdict re-derives from the invoice on every call"}
```

What this run establishes, in the real host with the real component over the real
`wasi:http` transport:

1. **The mint account was actually read and parsed from mainnet.**
   `expected_raw = 1500000` for `amount = "1.5"` is only derivable from
   `decimals = 6`, and that number came from the live USDC mint account — it is
   in neither the config nor the arguments.
2. **The closed schema reaches the model.** The oracle asserted the advertised
   parameter schema and recorded exactly
   `["amount", "invoice_id", "mint", "recipient"]` — no `reference`, no
   `__config`.
3. **The reference is derived correctly.** An independent Python
   implementation of the framed SHA-256 derivation reproduces the component's
   value byte for byte:
   `2m1xGkYy7wzQahXH8rdCTS47AoGXovRGHwL7wA9iCHQ2`.
4. **`getSignaturesForAddress` really ran** against mainnet and returned nothing
   for that reference, so the verdict is a *verified* `paid: false` rather than an
   error, and the reason is bounded and endpoint-free.
5. Host tool-I/O persistence was disabled; component logs contained only bounded
   phase labels — no arguments, invoice text, URL, signature, or response bodies.

## 4. Verification against a real finalized mainnet payment

`tests/fixtures/mainnet_usdc_payment.json` is a verbatim capture of the public
mainnet-beta responses for

```text
signature  3yrMvnqXgMaukWqBi7heAn1ZqsoWmWhmivWwU1AbKhX7cRWCL5PBn3krUPvkpQrKoUL6dpUCbibUvX7CYqBLGuik
slot       436144302
message    v0, one signature
transfer   SPL Token `Transfer` (discriminant 3), 5202 USDC base units
recipient  9TFHAowAEo1Xf2qD9KBBEzNuoaYNGjD2AhV8iYEdrkpc
destination 5RZHGLtc1TLGgX5fuNFKnmhZvBFtN6uFjBTUGP1JRTFM (its canonical USDC ATA)
delta      pre 11491627208 → post 11491632410  (+5202)
```

`tests/real_mainnet_bytes.rs` runs the production verification path over those
bytes, offline. It establishes on real data that:

- the signature-list and transaction parsers keep exactly the fields verification
  needs and drop the endpoint's logs and inner instructions;
- the wire bytes decode as a signed v0 transaction;
- the plain `Transfer` encoding a real wallet used is supported — it names no
  mint and asserts no decimals, which is precisely why the decoder had to accept
  it rather than only `TransferChecked`;
- the **locally derived recipient ATA equals the account the payment actually
  credited**;
- the **balance delta reconciles** against the instruction amount.

The payment carries no Solana Pay reference, because it was not made against a
request from `solana-pay-request`. So it must be refused — and the test asserts it
is refused for **exactly** that reason
(`Rejection::ReferenceNotInTransferInstruction`). The reference gate is evaluated
after the token-program, destination, mint, decimals, and amount checks, so
reaching it proves all of those passed on real mainnet bytes. Three further
assertions show the same real bytes being refused with the right reason when the
invoice's amount, recipient, or token program is changed.

The capture script derived the destination ATA with an **independent Python
implementation** of Solana's PDA derivation, including Ed25519 point
decompression for the off-curve check. Agreement with `nanosol` is therefore a
cross-check against a real on-chain ATA, not self-consistency.

## 5. Cross-plugin reference binding

The frozen vector, asserted from both plugins' suites:

```text
recipient   FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa
mint        EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v  (6 decimals)
amount      "1.5"          invoice_id  "412"
reference   3FrMXf9ucXff2biCaz5ehKYr1yguHjWvwLcy8ALDVEnw
url         solana:FnHy…ZGxa?amount=1.5&spl-token=EPjF…Dt1v&reference=3FrM…VEnw
```

- `solana-pay-request`: `golden_reference_vector_is_shared_with_solana_pay_confirm`
  asserts the produced URL and its `reference=` parameter, and that `"1.50"`,
  `"1.500000"`, and `"01.5"` all canonicalise to the same reference.
- `solana-pay-confirm`: `the_derived_reference_matches_the_frozen_cross_plugin_vector`
  and `the_tool_scans_for_exactly_the_reference_in_the_request_url` assert the
  same constant, end to end through the component entry point.
- The value was also reproduced independently in Python before either test was
  written.

**Independent tie to a real on-chain payment.** The M3 devnet acceptance
transaction — public, finalized, and recorded in
`plugins/spl-transfer-build/RESULTS.md` — embeds the reference
`GtaJ8kXf6UFmNKNkeYNhADCMFkxzShLCrsbvoJDkwK9J` in its `TransferChecked` account
list. Deriving from that invoice's four fields
(`ERajJRamvLoNyDmboTE6JjR4rPp16ZHdTwcnqcMz7kjH`,
`Ha9rCm2gQphTYZpEjTGE2un9Nm85SS6coTSS4jidmzY9`, `"1.25"`,
`"m3-devnet-2026-07-18"`) reproduces that exact reference. The derivation this
plugin performs therefore matches a reference that is already attached to a real
settled payment on chain.

## 6. Not achieved: a first-party live payment confirmed end to end

The plan's first evidence item — request a payment on devnet, pay it from a
disposable wallet, and watch `solana_pay_confirm` return `paid: true` — **was not
completed.** It is blocked by three environment facts, each verified rather than
assumed:

1. **The existing M3 devnet payment is no longer retrievable.** The public devnet
   endpoint has pruned it:
   ```text
   getTransaction 4vmwtcaV5toh… → {"result": null}
   getSignaturesForAddress GtaJ8kXf6UFm… → {"result": []}
   getFirstAvailableBlock → 479066362
   ```
   The transaction remains publicly documented and explorer-linked in
   `spl-transfer-build/RESULTS.md`; an archival endpoint would serve it.
2. **A new devnet payment needs funding, and the faucet refused.** Airdrops of
   0.2, 0.05, and 0.01 SOL to a fresh disposable keypair all returned
   `airdrop request failed. This can happen when the rate limit is reached.`
   One alternative public endpoint required an API key.
3. **A local validator cannot substitute on this machine.**
   `solana-test-validator` aborts with
   `Incompatible CPU detected: missing AVX2 support`. The host CPU predates
   AVX2, so the prebuilt validator cannot run and building Agave from source is
   not viable here. (Note also that the plugin requires HTTPS endpoints, so a
   plain-HTTP local validator would be refused by design.)

What completes this item, unchanged, once a funded devnet key or an archival
endpoint is available:

```bash
# 1. request (already proven): produces the URL and reference for the invoice
# 2. pay it with the reference attached — spl_transfer_build already emits exactly
#    that transaction shape when given invoice_id; sign and submit externally
# 3. confirm, twice, and diff the two verdicts:
python3 plugins/solana-pay-confirm/tests/host_chat_mock.py \
  --port 38191 --recipient <RECIPIENT> --amount <AMOUNT> --mint <ALIAS> \
  --invoice <INVOICE> --expect-paid true --capture "$M5_HOST/verdict-1.json"
ZEROCLAW_CONFIG_DIR="$M5_HOST" zeroclaw agent -a m5 -m '<confirm request>'
# repeat with --capture verdict-2.json and: diff verdict-1.json verdict-2.json
# 4. negative: same invoice, wrong amount → different reference → paid:false
```

Until that runs, the honest statement is: **the read, decode, derivation, and
reconciliation paths are proven against real mainnet data and a real host; a
first-party `paid: true` on a payment this project itself created is not yet
recorded.** No test or document in this repository claims otherwise.

## 7. Security audit

`M5_SECURITY_AUDIT.md` in the workspace root records a read-only audit of this
component and the `nanosol` read delta, with an adversary model per trust
boundary and 24 concrete attacks run against the production entry points. No
critical or high findings. Three findings were raised and all three are fixed in
this tree, each with a regression test:

- **F-1 (Medium, docs)** — the README understated the RPC boundary. A single
  dishonest endpoint can forge a *positive* confirmation, not merely hide a
  payment; the README now says so explicitly and explains why in-plugin Ed25519
  verification would not close it.
- **F-2 (Low, API)** — `verify_record` took the commitment level as an argument,
  leaving the gate in the caller. It now reads the level from the candidate, so
  the gate cannot be bypassed by any caller.
- **F-3 (Low, availability)** — a full scan window against two endpoints could
  multiply the per-read cap into ~12.5 MiB of parsing. A 1 MiB per-call read
  budget now bounds the whole call and refuses cleanly instead of risking a fuel
  trap.

The counts in §2 are post-remediation.

## 8. Failed commands, preserved

Development failures are recorded so they are not misreported as passes:

1. `solana airdrop` 0.2 / 0.05 / 0.01 SOL on devnet — rate-limited (see §6).
2. `solana-test-validator` — aborted, missing AVX2 (see §6).
3. Public devnet `getTransaction` / `getSignaturesForAddress` for the M3
   fixture — pruned history (see §6).
4. A 25-signature and then 40-signature survey of recent mainnet USDC activity
   found no third-party Solana Pay payment carrying a reference; almost all
   current USDC flow is DEX/CPI activity. The captured fixture is therefore an
   ordinary payment, used as a negative-with-a-specific-reason case (§4).
5. `tools/ci/run-packager-python.sh` exited 1: no Docker daemon is available
   locally for the pinned container. The same scripts were run with host
   Python and passed (§2); the containerised job remains CI's responsibility.
6. First `cargo +1.96.1 clippy --all-targets` on this plugin exited 101 on
   `redundant redefinition of a binding` in a test. The rebinding was removed;
   the re-run is the rc 0 recorded above. (Rust 1.97 did not flag it, which is
   why the pinned toolchain is the gate that matters.)
7. Builds under `/tmp` competed with a 2.9 GiB tmpfs on this host. The shared
   `CARGO_TARGET_DIR` was moved to disk and job counts were capped; all recorded
   runs are from the on-disk configuration.
