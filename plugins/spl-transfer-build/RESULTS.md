# M3 results — `spl-transfer-build`

## Verdict

**PASS.** Milestone 3 implements only a recent-blockhash, unsigned, version-0
SPL-token transfer proposal. The clean-clone strict validator, M2 regression,
real ZeroClaw host, independent decoder, simulation, external signer, and
devnet landing checks all passed. Durable nonce and M4 work did not begin.

The landed transaction was built before two follow-up commits that changed only
bounded refusal logging/the host oracle and strengthened the appended-unknown-
instruction test. The final clean-clone artifact was then loaded and invoked
again against the same live devnet fixture; its verified transaction shape and
475-byte output were unchanged apart from the required fresh blockhash.

## Date, environment, and repository record

- Recorded: 2026-07-18, Asia/Kathmandu.
- OS: Arch Linux, Linux `7.1.3-arch1-3`, x86_64.
- Rust: `rustc 1.96.1 (31fca3adb 2026-06-26)`.
- Cargo: `cargo 1.96.1 (356927216 2026-06-26)`.
- Solana CLI: `3.1.13`; SPL Token CLI: `5.5.0`.
- ZeroClaw host: `0.8.3`, commit
  `e592a555d69c6a701c0fa0fa3f94a4bbcffbb2c2`.
- Upstream repository: <https://github.com/zeroclaw-labs/zeroclaw-plugins>.
- Fork: <https://github.com/Fianko-codes/zeroclaw-plugins>.
- Branch: `agent/m25-solana-pay-request`.
- Draft PR: <https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/54>.
- Starting fork commit and clean tracked state:
  `58205b3172a42a2c3797e72f4f7f46014f67f04f`.
- Upstream base before and after M3:
  `23a5dcb953f697cae08d8e2802b39894ac9ddda1`.
- Validated implementation head before this evidence-only update:
  `8d3895cea02c7e4722602a43598b1159cd562c5e`.
- The branch was not rebased. PR #54 remained open and draft, with no
  maintainer review/comment or base change during implementation.
- Vendored WIT pin: `e112ce6b5ccdac9e1cb166bab217e730dd7e24c2`;
  bindings use `../../wit/v0` and the pinned-source drift comparison passed.

## Shared deterministic core

M3 extends M1 commit `961ad7b8a10e1a4df8a2090aa1092b943ed4a35e`
on branch `agent/m3-transfer-support`. The immutable public revision is:

```text
989cd0d3bd25ce6a2d796f72c0dc6a4ae56d989f
```

Source: <https://github.com/Fianko-codes/zeroclaw-solana/commit/989cd0d3bd25ce6a2d796f72c0dc6a4ae56d989f>.
Both plugins pin this exact `rev`; no mutable branch or filesystem dependency
is present.

The core adds deterministic JSON-RPC request/response handling for only
`getAccountInfo`, `getLatestBlockhash`, and `simulateTransaction`; strict Mint
and Token-2022 TLV parsing; semantic decoding of the M3 instruction subset;
unsigned v0 transaction inspection; and the unchanged M2 payment-reference
derivation. It contains no HTTP transport.

## Component boundary and artifact

- Plugin path: `plugins/spl-transfer-build`.
- Tool name: `spl_transfer_build`.
- Custody: T1 Build; reads chain state and returns unsigned proposal bytes.
- Capabilities: `tool`.
- Declared permissions, exactly:

  ```toml
  permissions = ["http_client", "config_read"]
  ```

- No signer, submission, status watcher, private-key input/storage, durable
  nonce, ALT, compute-budget, or generic instruction path exists.
- Handwritten code is under `deny(unsafe_code)`; only generated WIT glue has a
  narrowly scoped allowance. Source checks found no stdout logging.

Authoritative fresh-`CARGO_HOME`, clean-clone, strict-staged artifact:

```text
path: plugins/spl-transfer-build/target/wasm32-wasip2/release/spl_transfer_build.wasm
size: 689157 bytes
sha256: a1c3b8deeb7300e98148e07f47b36878d40a8e023691ecc7a4ea5c7f87521d63
type: WebAssembly component, binary version 0x1000d
```

The validator staged and the host loaded the same bytes. Cargo embeds source
paths, so an otherwise equivalent build under a different `CARGO_HOME` or
snapshot path can have a different byte hash; the value above is the preserved
clean-clone strict artifact identity.

The corresponding M2 strict artifact was 230,812 bytes with SHA-256
`4d0a6469de763b8ebca3ceac35c5cb6c9e67f5bcb2816f05d85ac22467daf8bd`.

## Test counts and categories

All automated plugin tests used only `MockTransport`; no automated test made a
live network request.

| Suite | Passed | Failed | Coverage grouping |
|---|---:|---:|---|
| `nanosol` | 36 | 0 | amount 4; inspection 3; instruction oracle 5; message oracle 5; mint/TLV 4; pubkey/PDA oracle 5; reference 2; RPC 5; shape/errors 3 |
| M3 component/injection | 6 | 0 | manifest/schema/T1 boundary, host config injection, swaps, transcript, determinism, map ordering/output budget |
| M3 config/amount | 6 | 0 | required/duplicate/malformed policy, off-curve policy, decimals 0/2/6/9, exact caps, invalid decimal forms |
| M3 RPC/simulation | 6 | 0 | exact method order/options, phase taxonomy, envelopes/IDs/errors, mint/blockhash shapes, bounded logs/bodies, mock-only transport |
| M3 token policy | 3 | 0 | legacy, extension-free Token-2022 opt-in, all current discriminants 1–28, unknown/duplicate/malformed/wrong-owner/uninitialized fixtures |
| M3 transaction/mutation | 4 | 0 | exact ATA/TransferChecked/v0 bytes, final-byte summary, cross-M2 reference, 19 independent wire mutations |
| M3 total | 25 | 0 | 0 ignored |
| M2 regression | 25 | 0 | component 3; injection 5; budget 3; request/reference 7; validation 7 |
| repository tooling | 17 | 0 | registry/package contract |
| CI tooling | 36 | 0 | matrix/report/validator/summary contract |

The 19 independently applied transaction mutations covered amount, decimals,
mint/destination/source/authority/program indexes, fee payer, reference, memo,
instruction order/count, appended duplicate, appended unknown program,
signature bytes, signer count, account flags, ALT data, and trailing bytes.
Every mutation was rejected; no mutation returned the original approval
summary.

## Oracle and fixture sources

- Official RPC semantics:
  [getAccountInfo](https://solana.com/docs/rpc/http/getaccountinfo),
  [getLatestBlockhash](https://solana.com/docs/rpc/http/getlatestblockhash), and
  [simulateTransaction](https://solana.com/docs/rpc/http/simulatetransaction).
  The request fixture asserts `encoding="base64"`, `sigVerify=false`, and
  `replaceRecentBlockhash=true`.
- Transaction and instruction byte oracles are pinned official Solana/SPL
  interface crates: `solana-message 4.3.0`, `solana-transaction 4.1.5`,
  `spl-associated-token-account-interface 2.0.0`,
  `spl-token-interface 3.0.0`, `spl-token-2022-interface 3.1.1`, and
  `spl-memo-interface 2.1.0`.
- Token-2022 discriminants/layouts were verified against
  `spl-token-2022-interface 3.1.1` source and constructed interface fixtures,
  not remembered plan values.
- The reference oracle remains official `@solana/pay 1.0.22` source at commit
  `9b0f8ec70c509c946c387633ae4f1e3115ea4958`; M2 and M3 both produce
  `ECvLKMSgRzVdJjZsdiGAPcRSjwVjS9f7HxizfC256Kei` for the shared golden tuple.
- Live acceptance uses the public devnet transaction linked below.

## Commands that passed

From `nanosol`, and separately from each of
`plugins/solana-pay-request` and `plugins/spl-transfer-build`:

```bash
cargo +1.96.1 fmt --check
cargo +1.96.1 test --locked
cargo +1.96.1 clippy --locked --all-targets -- -D warnings
cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings
cargo +1.96.1 build --locked --target wasm32-wasip2 --release
```

Repository and clean-clone checks:

```bash
git diff --check 23a5dcb953f697cae08d8e2802b39894ac9ddda1 HEAD
python3 tools/ci/plan_matrix.py --event pull_request \
  --base 23a5dcb953f697cae08d8e2802b39894ac9ddda1
python3 -m unittest discover -s tools/tests -p 'test_*.py'
python3 -m unittest discover -s tools/ci/tests -p 'test_*.py'
```

The matrix selected only `solana-pay-request` and `spl-transfer-build`, both
strict. The exact validator was run with an isolated absolute target and fresh
Cargo home:

```bash
CARGO_HOME="$M3_CLEAN_CARGO_HOME" \
STRICT_PLUGINS_JSON='["solana-pay-request","spl-transfer-build"]' \
REPORT_PATH="$M3_VALIDATE/matrix.tsv" \
STAGED_DIR="$M3_VALIDATE/staged" \
LOG_ROOT="$M3_VALIDATE/logs" \
CARGO_TARGET_DIR="$M3_VALIDATE/target" \
bash tools/ci/validate_components.sh \
  solana-pay-request spl-transfer-build
```

It reported, for each plugin, `test_rc=0`, `clippy_rc=0`,
`wasm_clippy_rc=0`, `build_rc=0`, and an unchanged committed source snapshot.
The fresh clone was created with:

```bash
git clone --branch agent/m25-solana-pay-request --single-branch \
  https://github.com/Fianko-codes/zeroclaw-plugins.git "$M3_CLEAN/repo"
```

All ten plugin commands above passed again there before the strict validator.
The WIT workflow's sparse fetch at the exact `wit/UPSTREAM_REF` and
`diff -ru wit/v0 "$M3_WIT_UPSTREAM/wit/v0"` passed.

The host-Python package dry run passed:

```bash
python3 tools/build-registry.py --staged "$M3_VALIDATE/staged" \
  --release-base https://github.com/Fianko-codes/zeroclaw-plugins/releases/download/plugins-v1 \
  --existing-registry registry.json --matrix-json "$M3_MATRIX" --out "$M3_VALIDATE/dist"
python3 tools/build-registry.py --source-plugins "$M3_VALIDATE/staged" \
  --check-metadata "$M3_VALIDATE/dist/registry.json"
python3 tools/build-registry.py --check-publication \
  registry.json "$M3_VALIDATE/dist/registry.json" "$M3_VALIDATE/dist"
```

It verified exactly two planned archives. No generated registry file was
manually edited.

## Real host and agent invocation

The authoritative artifact was copied with its manifest into a disposable
ZeroClaw 0.8.3 plugin directory. These commands exited 0:

```bash
ZEROCLAW_CONFIG_DIR="$M3_HOST" zeroclaw plugin list
ZEROCLAW_CONFIG_DIR="$M3_HOST" zeroclaw plugin info spl-transfer-build
python3 plugins/spl-transfer-build/tests/host_chat_mock.py \
  --port 38175 --recipient ERajJRamvLoNyDmboTE6JjR4rPp16ZHdTwcnqcMz7kjH \
  --mint Ha9rCm2gQphTYZpEjTGE2un9Nm85SS6coTSS4jidmzY9 \
  --capture "$M3_HOST/unsigned-transaction.b64"
ZEROCLAW_CONFIG_DIR="$M3_HOST" zeroclaw agent -a m3 \
  -m '<bounded M3 devnet build request>'
```

Host discovery reported capability `Tool` and exactly permissions
`HttpClient, ConfigRead`. The real two-turn agent result was:

```text
M3_AGENT_OK
reference=GtaJ8kXf6UFmNKNkeYNhADCMFkxzShLCrsbvoJDkwK9J
last_valid_block_height=464983680
transaction_sha256=5025dc6dde84655d0b0e05102cc8fd79ea3cbf2686d9a095d9d28675523722cb
```

The captured unsigned transaction was 475 bytes. Independent Solana CLI
decoding found version 0, one required signer, the configured payer, one zero
signature, three instructions in ATA/Token/Memo order, no address-table
lookups, the expected source/destination ATAs, and a normal recent blockhash.
Host tool-I/O persistence was disabled; component logs contained only bounded
phase labels and no arguments, memo, URL, transaction, account data, response,
or simulation logs.

ZeroClaw reported that no OS sandbox backend was installed and used its
application-layer security boundary. WIT permission linking still enforced the
two declared component permissions, but operators should enable a supported OS
sandbox independently.

## Real devnet acceptance

Disposable public fixture:

```text
sender:          DY8kZcYtLkPBsRgu9BGfRirKsK3Jnf1eDn8LyYiJkxw9
mint (legacy):   Ha9rCm2gQphTYZpEjTGE2un9Nm85SS6coTSS4jidmzY9
sender ATA:      13dZULs9Ua8B6AbJqqU98nnweqEGqXbBUhffMUoYmaMp
recipient owner: ERajJRamvLoNyDmboTE6JjR4rPp16ZHdTwcnqcMz7kjH
recipient ATA:   qR6KPs1QxxR2YA2H1SFHXAAZvMoBBpX4nzCXyZjc2wx
amount:          1.25 (raw 1250000, decimals 6)
reference:       GtaJ8kXf6UFmNKNkeYNhADCMFkxzShLCrsbvoJDkwK9J
```

Public finalized signature:

<https://explorer.solana.com/tx/4vmwtcaV5tohLi2TGY6SnZVKvuvff1je3wxXYM2p328pfxtzbEf5jj4FSpXNX6794x3y4TfCrJ634UbsLEFExhLn?cluster=devnet>

The on-chain v0 message contains exactly `CreateIdempotent`,
`TransferChecked`, and Memo. It has no ALT or compute-budget instruction. The
transaction consumed 23,853 compute units, disproving any need for an M3
compute-budget instruction. Independent final balance reads returned recipient
`1.25` and sender `98.75`.

The signing key existed only in a mode-0600 disposable file outside ZeroClaw.
The plugin received only its public key through operator config. A disposable
external Python/Solders helper checked the all-zero slot, one signer, payer,
and no ALT; signed the exact versioned message; verified the signature; proved
the message bytes unchanged; and submitted via an external RPC call. The
plugin never signed, submitted, received a key, or claimed success on-chain.

Representative passing commands:

```bash
NO_DNA=1 solana confirm \
  4vmwtcaV5tohLi2TGY6SnZVKvuvff1je3wxXYM2p328pfxtzbEf5jj4FSpXNX6794x3y4TfCrJ634UbsLEFExhLn \
  --url https://api.devnet.solana.com
NO_DNA=1 spl-token balance \
  --address qR6KPs1QxxR2YA2H1SFHXAAZvMoBBpX4nzCXyZjc2wx \
  --url https://api.devnet.solana.com
NO_DNA=1 spl-token balance \
  --address 13dZULs9Ua8B6AbJqqU98nnweqEGqXbBUhffMUoYmaMp \
  --url https://api.devnet.solana.com
```

## Failed commands and fixes

No final acceptance command remains failed. Development failures are preserved
here so they are not misreported as passes:

1. Two early `cargo +1.96.1 check --locked` core runs exited 101 after adding
   dependencies. The lockfile was intentionally regenerated, reviewed, then
   every final command used `--locked`.
2. One core mint-layout test exposed error-ordering on truncated data; the
   parser now validates structural length before the initialization flag.
3. Initial core Clippy rejected a needless lifetime; it was removed.
4. Initial M3 Clippy rejected a boolean assertion and a complex test type; the
   assertion and named type alias were corrected without allowances.
5. An off-curve recipient test accidentally aliased a globally writable source
   account. Its PDA fixture was changed to a distinct seed mint.
6. Initial strict runs under `/tmp` exhausted the 2.9-GiB tmpfs; one relative
   `CARGO_TARGET_DIR` also resolved inside the validator snapshot. Final runs
   used validated absolute workspace targets and passed.
7. `tools/ci/run-packager-python.sh -m unittest discover -s tools/tests -p
   'test_*.py'` exited 1 locally because no Docker daemon/socket was available.
   The underlying suite passed 17/17 with host Python, the host package dry run
   passed, and the exact pinned-container job passed in fork GitHub Actions.
8. Official `solana airdrop` attempts for 2, 1, and 0.01 SOL were rate-limited.
   A public devnet RPC with an independent quota supplied 0.001 SOL, after which
   the official proof-of-work faucet supplied 0.02 SOL.
9. `cargo install --locked devnet-pow` failed because its old locked
   `wasm-bindgen 0.2.86` rejects Rust 1.96.1. An unlocked disposable install
   resolved compatible dependencies and succeeded; it was not added to either
   repository.
10. `devnet-pow` inference through one provider failed because that provider
    refused the large `getProgramAccounts`; explicit official faucet difficulty
    and reward parameters succeeded.
11. The first `spl-token mint` omitted the destination and therefore derived
    the default CLI signer's ATA, not the configured fee payer's ATA. The exact
    disposable sender ATA was supplied and minting succeeded.
12. One combined balance command used both mint and `--address` and exited 2.
    The documented `--address`-only form then exited 0 and returned 1.25/98.75.
13. A development `--verbose` host run showed that the host itself can persist
    tool output even though component structured logs do not. Final host config
    set `observability.log_tool_io="off"`; the final invocation exposed only
    the bounded oracle result.
14. One clean-clone validator process was interrupted when the active turn was
    steered. A complete clean restart and the final cached rerun both exited 0.

## Corrected or disproven assumptions

- Current official simulation semantics permit an unsigned transaction with
  `sigVerify=false`; `replaceRecentBlockhash=true` is valid only when signature
  verification is disabled. The exact request fixture is tested.
- Current `spl-token-2022-interface 3.1.1` assigns `Pausable` discriminant 26
  and defines current extension discriminants through 28. M3 tests the
  authoritative interface values rather than a remembered plan list.
- An extension-free Token-2022 Mint uses the base Mint layout owned by the
  Token-2022 program; explicit opt-in accepts it. Any TLV extension or unknown
  discriminant is refused.
- Devnet execution showed no compute-budget instruction is required.
- Public faucet availability is not deterministic; it is an integration
  dependency, not an automated-test dependency.
- Cargo release hashes can vary with source-path embedding. The preserved hash
  therefore identifies the exact clean-clone strict artifact, not every
  semantically reproducible build path.
- ZeroClaw plugin discovery alone is insufficient for a custom model endpoint;
  `native_tools=true` is required for the tool schema to reach the model.

## Remaining risks and limitations

- The configured RPC remains trusted for binary mint state and blockhash
  freshness. Strict parsing cannot prove an endpoint is honest.
- Signers must independently inspect and approve bytes; final-byte verification
  substantially reduces summary-versus-bytes deception only within the exact
  supported subset.
- Recent blockhashes expire quickly; stale proposals must be rebuilt.
- Token-2022 evolves. Unknown future extensions fail closed, and M3 supports
  only extension-free mints even with operator opt-in.
- The plugin is stateless and enforces no per-day limit.
- Production operators should enable an OS sandbox and control host-level tool
  output retention.
- Maintainers must choose the long-term `nanosol` packaging boundary before the
  draft PR is ready for review.
- Upstream maintainers may still need to approve fork-originated workflow runs;
  the fork's identical workflow is green.

None of these remaining risks authorizes M4 behavior. Durable nonce remains
explicitly deferred to M4.
