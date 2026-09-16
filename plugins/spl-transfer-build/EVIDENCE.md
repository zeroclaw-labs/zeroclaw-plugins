# `spl-transfer-build` — evidence

One validation record for this plugin, in the order the work happened. Every claim below is a command that was run and an output that was observed; failed commands are preserved rather than removed.

1. [Recent-blockhash mode: build, test, and devnet acceptance](#part-1-recent-blockhash-mode-build-test-and-devnet-acceptance)
2. [Durable-nonce mode: validation, devnet acceptance, and a controlled failure](#part-2-durable-nonce-mode-validation-devnet-acceptance-and-a-controlled-failure)
3. [Live `mainnet-beta` read-only validation](#part-3-live-mainnet-beta-read-only-validation)
4. [Packaging and registry-install validation](#part-4-packaging-and-registry-install-validation)

---
## Part 1 — Recent-blockhash mode: build, test, and devnet acceptance

### Verdict

**PASS.** Milestone 3 implements only a recent-blockhash, unsigned, version-0
SPL-token transfer proposal. The clean-clone strict validator, M2 regression,
real ZeroClaw host, independent decoder, simulation, external signer, and
devnet landing checks all passed. Durable nonce and M4 work did not begin.

The landed transaction was built before two follow-up commits that changed only
bounded refusal logging/the host oracle and strengthened the appended-unknown-
instruction test. The final clean-clone artifact was then loaded and invoked
again against the same live devnet fixture; its verified transaction shape and
475-byte output were unchanged apart from the required fresh blockhash.

### Date, environment, and repository record

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

### Shared deterministic core

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

### Component boundary and artifact

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

### Test counts and categories

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

### Oracle and fixture sources

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

### Commands that passed

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

### Real host and agent invocation

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

### Real devnet acceptance

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

### Failed commands and fixes

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

### Corrected or disproven assumptions

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

### Remaining risks and limitations

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

### M3.5 security-audit remediation and release freeze

#### Audit record and immutable baseline

This section records the Milestone 3.5 remediation of the external audit in
the repository-root `M3_SECURITY_AUDIT.md`. The audit verdict was 0 Critical,
0 High, 1 Medium, and 4 Low findings. Its independent 11-case serialized-wire
harness found zero verifier bypasses. The remediation began from a clean
tracked worktree at fork commit
`3f7f8e9a5db1a7d7c626d1f22ace166cd0d02b17`; upstream remained
`23a5dcb953f697cae08d8e2802b39894ac9ddda1`, and PR #54 was open and draft
with no maintainer review, comment, CI result, or packaging decision.

The known-good M3 head is preserved publicly by the annotated, non-rewritten
tag `m3-known-good-3f7f8e9`, which resolves to that exact commit. Remediation
was isolated on `agent/m35-audit-remediation`. The production-and-test
remediation commit is
`d20320556d6b64defe81ca72f5bda7c0c7290bcb`. Both plugins still pin the
unchanged immutable `nanosol` revision
`989cd0d3bd25ce6a2d796f72c0dc6a4ae56d989f`; M3.5 did not change the core or
any transaction-construction, serialization, instruction-order, or verifier
semantics.

#### Remediations and committed regressions

- A Token-2022 approval now includes: `Token-2022: displayed amount is the
  transfer amount; net received may depend on mint extensions as reported by
  the configured RPC.` The branch decision uses the token program decoded
  from the final serialized transaction. The extension-free Token-2022
  end-to-end fixture proves the qualifier is model-visible; the corresponding
  legacy fixture proves it is absent. Existing amount, asset, recipient, ATA,
  sender, memo, reference, and blockhash fields remain present, and the output
  budget remains enforced.
- Five audit harness mutations are now ordinary committed wire-level tests:
  an unreferenced extra static key; a six-account transfer with a second
  reference; both reference-policy direction mismatches; a noncanonical key
  ordering with every instruction index remapped; and a separate readonly
  signer as transfer authority. Every final-byte verifier check refuses; none
  reaches or preserves a misleading approval summary. The previous mutation
  suite remains intact.
- A host oracle uses official dev-only
  `spl-token-2022-interface = 3.1.1` extension machinery, from source commit
  `e18f9c6f9bf6044b934f48e3090e8e59e4820f02`, to pack a Mint with
  `TransferFeeConfig`. Its exact bytes have SHA-256
  `3cbb482fdcae9086d23a0d76309e4865dc0ece0222d1972bbf4f3275466d0ba1`.
  The test checks official account type and TLV offsets, core parsing, and the
  plugin's semantics-changing-extension refusal. Official Solana crates remain
  test-only dependencies.
- Both components test execution after caller-controlled `__config` is
  stripped and no trusted host configuration is injected. Payment-request
  attacker aliases do not become policy, and transfer-build refuses before
  transport use. The component value itself cannot authenticate field
  provenance; current ZeroClaw `inject_config` stripping remains a documented
  hard security dependency.
- The smallest transport-agnostic response collector is shared by host tests
  and the Waki path. HTTP 200 succeeds; redirects and 4xx/5xx refuse; the
  documented size limit is inclusive; one byte over or aggregate chunk
  overflow refuses; diagnostics reveal neither URL nor body.
- Three additional Solana Pay vectors cover minimal native SOL, SPL token
  without display text, and reserved/Unicode text. They were executed from
  official `@solana/pay` source declaring version 1.0.22 at commit
  `9b0f8ec70c509c946c387633ae4f1e3115ea4958`. The registry does not publish
  1.0.22, so the exact source commit—not a nonexistent npm artifact—is the
  reproducible oracle. Existing golden output is unchanged.
- Both README openings now lead with operator utility. They also document the
  Token-2022 RPC trust boundary, host config dependency, noncommitted CI-built
  artifacts, path-dependent Cargo hashes, and the priority of semantic and
  byte-level reproducibility.

The new totals are 36 `nanosol` tests, 29 `solana-pay-request` tests, and 37
`spl-transfer-build` tests. Payment-request categories are component 3,
injection 6, output 3, request/golden 10, and validation 7. Transfer-build
categories are component/injection 7, config/amount 6, RPC/simulation 6,
Token policy 5, transaction/mutation 9, and transport 4. Repository tooling
remains 17/17 and CI tooling 36/36. All tests are host-run with deterministic
fixtures or mock transport; the real network is used only for separately
recorded acceptance.

#### Validation and artifacts

For `nanosol` and, separately, each plugin, these commands passed under Rust
1.96.1:

```bash
cargo +1.96.1 fmt --check
cargo +1.96.1 test --locked
cargo +1.96.1 clippy --locked --all-targets -- -D warnings
cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings
cargo +1.96.1 build --locked --target wasm32-wasip2 --release
```

The M0 PDA oracle (`9` tests) and WASM spike passed. PR-mode change planning
selected exactly both changed plugins. Host repository tooling (`17/17`), CI
tooling (`36/36`), strict component validation for both plugins, WIT drift,
source-mutation guards, metadata checks, package dry run, and exact
publication-set verification all passed. A public fresh clone at the
remediation commit, with a new empty `CARGO_HOME`, repeated both strict
component pipelines and packaging successfully.

Authoritative fresh-clone strict artifacts for the tested implementation:

```text
solana-pay-request: 230764 bytes
SHA-256: d437ddd26e6badb8d8382b1f496915eddd06070c31dba18897aa58aa076526da

spl-transfer-build: 689146 bytes
SHA-256: 93208cf7edf1e3e7276902d2ac85771946bd14f235fe7349070e62a456bb26e4
```

The exact pinned-container wrapper could not run locally because this machine
has no Docker socket. That command exited 1 without running tests; its
underlying host Python suite passed 17/17, and the repository's pinned wrapper
is exercised by the fork workflow. Development-only failures were an
intentional placeholder fixture hash, one exact policy-message assertion,
one Clippy `drop_non_drop` lint, strict validation seeing ignored local
`target/` directories, an incorrectly shaped package-plan input, an
unpublished npm version lookup, and public devnet faucet rate limiting. Each
was corrected or bounded without weakening a security check; all corresponding
final commands pass except the explicitly environment-blocked Docker wrapper.

#### Host, devnet, packaging, and residual risk

ZeroClaw 0.8.3 discovered and executed both final clean-clone components. It
reported `ConfigRead` for `solana-pay-request` and exactly `HttpClient,
ConfigRead` for `spl-transfer-build`. A real payment-request call returned the
expected official-vector URL and reference. A real transfer-build call used
the configured devnet RPC, parsed live mint state, obtained a recent
blockhash, simulated successfully, and returned a 475-byte unsigned v0
transaction; the component received only the sender public key.

Because M3.5 routes the Waki success path through the newly tested status/body
collector, the externally signed devnet acceptance is repeated conservatively.
The repeat used sender `Em1XUGLSa9ZEHY27ji81TsePMaXyAcxrQJfoZ36rH36a`,
legacy mint `2QWDRwof3A56ZE3R4CC6iokK2gY4PsNik7HSyHQP8WxA`, recipient
`Av3jRATKDH2CFWfbYZWLRmmn1k8mN6RUYk3ZC8Le6uoD`, source ATA
`DmYtgmRL4tYjnHzi42ctt8xb5PT8FtY4G5ppEQTjo5Mk`, destination ATA
`Ew2GeCMSzEkuDhWPq5NsBAPcRcZw329crBhutkBXHETC`, and reference
`BEPTACJj2wvHWry39tGxFh9ryAVWsRMRkeEnmKLcigUd`. The real agent returned a
475-byte unsigned transaction with SHA-256
`0934375f5400e4d991efa6fd4afbae050235c45b2b94014f7269600157a436a7`.
An isolated external Solders 0.27.1 helper independently required v0, one zero
signature, one payer/signer, no ALT, the exact three programs/account orders,
derived ATAs, raw amount 1,250,000, six decimals, one readonly reference, and
the exact memo. It signed without changing the versioned message (SHA-256
`6720090f84a0f08cbd1c3ea8dd0d72ebdde1dba3b4c9eae40226d2a77f838d1b`)
and submitted outside ZeroClaw. The plugin never received either disposable
key file.

The repeat finalized with public signature
[`PGbL4d1s39LsXMt3SKEKKP7BMh3RP1QeqnZbp8p2udyaPemPSXdGL97ho3jV8gspqBLCEmMd2iBFLJAHPTCmtRM`](https://explorer.solana.com/tx/PGbL4d1s39LsXMt3SKEKKP7BMh3RP1QeqnZbp8p2udyaPemPSXdGL97ho3jV8gspqBLCEmMd2iBFLJAHPTCmtRM?cluster=devnet).
Independent CLI inspection reported message version 0, the exact
CreateIdempotent/TransferChecked/Memo order, no ALT or extra instruction,
23,853 compute units, and status `Ok`. Final balances were recipient 1.25 and
sender 98.75 disposable tokens.

No maintainer packaging response existed when remediation began. `nanosol`
has not been published or relocated, and both plugins retain the exact pinned
Git revision pending an explicit maintainer choice or acceptance. This remains
an M3.5 gate and draft-review blocker, not a reason to invent a packaging
policy.

The Medium finding is corrected in the model-visible summary, but its root RPC
trust-boundary condition is residual: one configured endpoint can still lie
about Token-2022 mint bytes. The qualifier discloses that uncertainty without
claiming a fee exists or that the RPC is honest. The audit's four Low risks
remain bounded/documented: dependence on host-side `__config` provenance,
limited independent official fixtures despite the new packed oracle,
previously thin transport coverage now materially strengthened, and
judge-facing utility/reproducibility communication now improved. Additional
residual risks are recent-blockhash expiry, future Token-2022 evolution,
stateless lack of per-day caps, signer-side approval responsibility, and the
operator's OS-sandbox/RPC choices.

#### Security freeze

The M3 implementation is security-frozen after this remediation: no feature
addition, durable nonce, new transaction type, instruction-order change,
verifier weakening, runtime dependency, or guardrail-semantic change is
included. Future runtime dependencies or security-semantic changes require
renewed targeted review and regression coverage. M4 and `payment-watch` are
explicitly not included and have not begun.

## Part 2 — Durable-nonce mode: validation, devnet acceptance, and a controlled failure

**Verdict: M4 PASS.** All 20 promotion-gate conditions met, including the
focused read-only M4 security audit (zero Critical, zero High). Eligible to be
proposed for promotion; PR #54 and the frozen tags were not modified, and
promotion remains a separate maintainer decision.

This is an isolated experiment on disposable branches. The frozen M3.5 submission
and its fallbacks are untouched.

### Starting commits and tags

| Repo | Disposable branch | Base |
|---|---|---|
| zeroclaw-solana (nanosol) | `agent/m4-durable-nonce-experiment` | `989cd0d3bd25ce6a2d796f72c0dc6a4ae56d989f` |
| zeroclaw-plugins | `agent/m4-durable-nonce-experiment` | `95e10dc1b8ec4c796b22d50ffc63136e462eaf0a` |

Frozen (unchanged): `m35-security-freeze-95e10dc` → `95e10dc…`,
`m3-known-good-3f7f8e9` → `3f7f8e9a5db1a7d7c626d1f22ace166cd0d02b17`.
PR #54 head = `95e10dc…` (draft, frozen M3.5) — not modified. Working trees clean
apart from the M4 commits below.

### Official sources and versions (host dev-dependency oracles)

`solana-nonce 3.2.0` (features serde), `solana-system-interface 3.2.0` (features
bincode), `solana-sdk-ids 3.1.0`, plus the existing `solana-message 4.3.0`,
`solana-transaction 4.1.5`, `solana-instruction 3.4.0`, `solana-pubkey 4.2.0`,
`solana-hash 4.5.0`, `bincode 1.3.3`. Primary docs: Agave "Durable Transaction
Nonces" implemented proposal, Solana core `durable-nonces` docs, and the
`simulateTransaction` RPC reference. Toolchain `cargo +1.96.1`. Devnet RPC
`https://api.devnet.solana.com` (solana-core 4.2.0-beta.1), Agave CLI 3.1.13.

### Phase-A spike verdict: PASS

All eight Phase-A conditions passed (full detail in
[`spikes/durable-nonce/M4_SPIKE_RESULTS.md`](https://github.com/Fianko-codes/zeroclaw-solana/blob/main/spikes/durable-nonce/M4_SPIKE_RESULTS.md)):

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

### Nonce-account format (80 bytes, confirmed)

`[Versions disc u32 LE = Current(1)] [State disc u32 LE = Initialized(1)]
[authority 32] [durable_nonce 32] [lamports_per_signature u64 LE]`. The nanosol
parser is a strict fixed-80-byte reader: it rejects Legacy (version 0),
Uninitialized, unknown version/state discriminants, and any other length. bincode
tolerates trailing bytes; the parser does not.

### AdvanceNonceAccount instruction (confirmed byte-for-byte)

program = System (all-zero), data = `04 00 00 00`, accounts:
`[0]` nonce (writable, non-signer), `[1]` `SysvarRecentB1ockHashes…` (readonly,
non-signer), `[2]` authority (signer). Must be instruction index 0; the message
blockhash must equal the stored nonce.

### Simulation requests and results (devnet)

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

### New immutable nanosol revision

`5d9501408346540332e95611219a15dafd9c2d87` — pushed to
`Fianko-codes/zeroclaw-solana` branch `agent/m4-durable-nonce-experiment`, pinned
by the plugin. (Adds nonce parsing, `advance_nonce_account`,
`decode_advance_nonce_account`, `RECENT_BLOCKHASHES_SYSVAR_ID`,
`simulate_durable_transaction_request`, `SimulationResult.replaced_blockhash`,
`Error::Nonce`.)

### Files changed

nanosol (`989cd0d..5d95014`): `src/nonce.rs` (new), `src/inspect.rs`,
`src/instruction.rs`, `src/pubkey.rs`, `src/rpc.rs`, `src/error.rs`, `src/lib.rs`,
`Cargo.toml`, `Cargo.lock`, `tests/nonce_oracle.rs` (new).

spl-transfer-build (`95e10dc..HEAD`): `src/transfer.rs`, `src/lib.rs`,
`Cargo.toml`, `Cargo.lock`, `tests/durable_nonce.rs` (new),
`tests/transaction_and_mutations.rs` (field additions),
`tests/rpc_and_simulation.rs` (Option field), `README.md`,
`tests/host_chat_mock_durable.py` (new acceptance driver), this file.
Manifest, WIT, and tool input schema unchanged.

### Tests and counts

| Crate | Tests | Notes |
|---|---|---|
| nanosol | 43 | 36 pre-existing + 7 new (nonce oracle) |
| solana-pay-request | 29 | unchanged |
| spl-transfer-build | 71 | 37 recent-mode (unchanged) + 34 durable |

All durable final-byte mutations, mode-confusion, and simulation error cases
fail closed. Recent-mode golden transaction/summary tests unchanged.

### Exact command results (Rust 1.96.1 matrix)

For `nanosol`, `solana-pay-request`, and `spl-transfer-build`, all of:
`cargo +1.96.1 fmt --check`, `cargo +1.96.1 test --locked`,
`cargo +1.96.1 clippy --locked --all-targets -- -D warnings`,
`cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings`,
`cargo +1.96.1 build --locked --target wasm32-wasip2 --release` — **PASS**.

### WASM artifact

`spl_transfer_build.wasm` (durable build, nanosol `5d95014`):
- size: 703484 bytes
- SHA-256: `b170e503a09ca544e1ed31862d3550d284025894082473a775c3f8395a42cb25`

(The artifact is rebuilt by CI and not committed; the hash identifies the tested
build environment. The strict CI validator's isolated rebuild produced 706776
bytes — Cargo artifact bytes differ with absolute source paths, as documented for
M3.)

### Additional validation (CI parity)

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

### Real host and agent invocation (durable)

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

### Real M4 devnet acceptance

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

### Controlled failure (nonce consumed on later-instruction failure)

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

### Private-key handling

No private key ever entered `nanosol`, the plugin, its config, or committed
evidence. The disposable sender / nonce / mint keypairs lived only in the session
scratchpad (mode 0600) and are destroyed at the end. External signing was done by
the spike `durable_devnet sign` helper, outside the plugin. The plugin received
only public keys through operator config.

### Corrected assumptions

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

### Remaining risks

- The RPC endpoint is a trust boundary: a dishonest RPC can misreport nonce or
  mint state. The plugin nevertheless guarantees the returned transaction is
  internally consistent with the exact nonce state it accepted.
- Durable-nonce transactions consume the nonce and charge a fee even when a later
  instruction fails; this is surfaced in the approval summary and README.
- M4 supports only `nonce authority == sender`; a separate nonce-authority signer
  is intentionally unsupported.

### Deprecation assessment

Durable nonces are fully functional today but Solana's docs carry a
forward-looking notice that they "may be deprecated in a future release" (SIMD
discussion #415 — a discussion, not an activated change). The recent-blockhashes
sysvar is deprecated for on-chain reads yet still required as an
`AdvanceNonceAccount` account. Operators adopting durable mode should track this.

### Focused M4 security audit (promotion gate condition 20)

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

### Promotion recommendation

M4 meets **all 20 promotion-gate conditions**, including the read-only security
audit (zero Critical/High). It is therefore **eligible to be proposed for the
bounty PR**. Per the experiment's terms, this branch does **not** update PR #54 or
touch the frozen tags; promotion (opening/updating the PR) is a separate,
explicit maintainer decision.

## Part 3 — Live `mainnet-beta` read-only validation

**Verdict: PASS.** The plugin's read-only paths were exercised live against
`https://api.mainnet-beta.solana.com` through the real ZeroClaw 0.8.3 WASM host.
A real mainnet USDC transfer was constructed, verified, and **simulated on
mainnet with `err: null`**, and independently decoded by a separate library. A
real mainnet Token-2022 mint was refused, twice, for two different reasons.

**Nothing was signed. Nothing was submitted. No private key for any address in
this document exists in this project, in any config, or in any committed file.**
The plugin is T1: it has no signing path and no submission path at all, which is
exactly why pointing it at mainnet is safe.

Recorded: 2026-07-30. Cluster `mainnet-beta`, `solana-core 4.1.0`,
feature set `3345198602`. Host `zeroclaw 0.8.3` (Cranelift/Wasmtime plugin host).
Component built with `cargo +1.96.1 build --locked --target wasm32-wasip2
--release` from `nanosol` rev `5d9501408346540332e95611219a15dafd9c2d87`.

### Why mainnet, and what it does and does not prove

Devnet proves the whole lifecycle including execution (see Part 2:
a finalized devnet transfer after a 363-second hold). Devnet cannot prove the
read paths behave against **real** mint state — real Token-2022 extension TLV
layouts, real canonical ATAs, real compute costs. Mainnet proves that, and it
can be done with zero risk precisely because the custody tier forbids signing.

This document therefore claims: **the read, construct, verify, and simulate
paths are correct against live mainnet state.** It does not claim any mainnet
transfer was executed, because executing one would require a key the project
refuses to hold.

### Addresses used

All are public mainnet addresses. They were selected by reading recent public
USDC activity — no relationship to this project, and no key for any of them
exists here. They are read-only construction inputs supplied through **operator
config**, never by the model.

| Role | Address | Note |
|---|---|---|
| `sender_pubkey` (operator config) | `F7p3dFrjRTbtRp8FRF6qHLomXbKRBzpvBLjtQcfcgmNe` | on-curve wallet holding USDC; needed so mainnet simulation is meaningful |
| recipient (allowlisted) | `4kYMh3RoXaiwdwXw6NkJTaowMkgq3oNoSGNZh9Y3RG4K` | on-curve wallet with an existing USDC ATA |
| mint — legacy SPL | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` | USDC; owner `Tokenkeg…`, 82 bytes, 6 decimals, no extensions |
| mint — Token-2022 | `2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo` | PYUSD; owner `TokenzQd…`, 866 bytes, 6 decimals |

The Token-2022 mint carries eight real extensions — `mintCloseAuthority`,
`permanentDelegate`, `transferFeeConfig`, `confidentialTransferMint`,
`confidentialTransferFeeConfig`, `transferHook`, `metadataPointer`,
`tokenMetadata`. This is the live TLV data the policy has to decide against, not
a fixture.

### Case 1 — legacy SPL mint, full success path (live mainnet)

Driven through `zeroclaw agent -a m5` by the deterministic oracle
`tests/host_chat_mock_mainnet.py --expect ok`. The component was discovered with
capability `Tool` and permissions `HttpClient, ConfigRead`.

Host result:

```
MAINNET_AGENT_OK reference=HJq1JwBQkEBTh9s32QskfMHu1WYYSYjNa81m1GJXbhap
                 last_valid_block_height=414167454
                 transaction_bytes=485
                 transaction_sha256=252ad70f25d78fdab491117fa4fcb3faf26e30ff191de0afaa2515b7406cffa4
```

The component made real mainnet JSON-RPC calls (mint `getAccountInfo`,
`getLatestBlockhash`, `simulateTransaction`) and returned a 485-byte unsigned
transaction. Because the plugin refuses to return a transaction whose simulation
fails, `MAINNET_AGENT_OK` already implies the plugin's own mainnet simulation
succeeded — but that was not taken on trust; see Case 2.

### Case 2 — independent decode and independent mainnet simulation

`tests/mainnet_inspect.py` re-checks the exact returned bytes using `solders`
(an independent implementation, not the plugin's verifier) and re-simulates them
against mainnet itself. The script has **no keypair argument and no signing
path**.

| Check | Result |
|---|---|
| `transaction_bytes` | `485` |
| `transaction_sha256` | `252ad70f25d78fdab491117fa4fcb3faf26e30ff191de0afaa2515b7406cffa4` |
| re-serialize is byte-identical | ✅ |
| signature slots / all zero | `1` / ✅ — nothing is signed |
| message is v0 | ✅ |
| required signers | `1` |
| address table lookups | `0` |
| fee payer == configured sender | ✅ |
| derived sender ATA | `Q4UmPB9hKMw3ERqksavS9oEpNo2eWG4ffkWg7wHa9j6` |
| derived recipient ATA | `4qsJJZgr2Rv8FgUR37uXPJvRcP3RUEB1a4mLbHsWLwr2` |
| instruction programs | `ATokenGPv…`, `Tokenkeg…`, `MemoSq4g…` |
| ATA instruction is `CreateIdempotent` (`01`), targets recipient ATA | ✅ / ✅ |
| token instruction discriminant | `12` (`TransferChecked`) |
| amount raw / decimals | `1500000` / `6` — both match `1.50` at 6 decimals |
| source == sender ATA, mint == configured mint, destination == recipient ATA, authority == sender | ✅ ✅ ✅ ✅ |
| memo text matches | ✅ |
| `message_sha256` | `f5cd2ae1a99a2dae7b3db09e1b27d42596d27c44a12d95d802c667ca097d860d` |
| **independent mainnet `simulateTransaction`** (`sigVerify=false`) | **`err: null`**, `unitsConsumed: 22853`, 11 log lines |

```
INDEPENDENT_MAINNET_INSPECTION_OK
```

#### A free mainnet oracle for ATA derivation

`nanosol` derives associated token accounts with hand-rolled sha256 + off-curve
detection, because `solana-sdk` does not build for `wasm32-wasip2`. Mainnet
supplies an independent check on that: the derived sender ATA
`Q4UmPB9hKMw3ERqksavS9oEpNo2eWG4ffkWg7wHa9j6` **is** the token account that
actually holds this wallet's USDC on chain, and the derived recipient ATA
`4qsJJZgr2Rv8FgUR37uXPJvRcP3RUEB1a4mLbHsWLwr2` likewise. Four out of four
candidate wallets sampled from live USDC activity had their real on-chain token
account equal to the independently derived canonical ATA.

### Case 3 — real mainnet Token-2022 mint, refused twice

Same host, same live mainnet endpoint, `--expect refusal`. Both runs returned
**no transaction at all**; the oracle asserts the absence, not just an error
string.

| Config | Host result | Refusal reason (bounded, model-visible) |
|---|---|---|
| `allow_token_2022 = "false"` (default) | `MAINNET_REFUSAL_OK no_transaction_returned` | `Token-2022 mint refused; operator must explicitly enable extension-free Token-2022` |
| `allow_token_2022 = "true"` (operator opt-in) | `MAINNET_REFUSAL_OK no_transaction_returned` | `Token-2022 mint extensions are outside the supported safe subset` |

The second row is the one that matters. With Token-2022 explicitly enabled by
the operator, the plugin still refused — because it walked the **real** mainnet
TLV extension list and found extensions (`transferFeeConfig`,
`permanentDelegate`, `transferHook`, confidential-transfer) outside the
supported safe subset. A transfer fee or a permanent delegate can make the
amount a human approves differ from the amount a recipient receives, which is
precisely the deception the whole design exists to prevent. Fail-closed against
live data, not against a fixture.

### Reproducing this

Read-only; costs nothing; moves nothing.

```bash
cd plugins/spl-transfer-build
cargo +1.96.1 build --locked --target wasm32-wasip2 --release
# install manifest + wasm into a disposable ZeroClaw config dir, set
# rpc_url = "https://api.mainnet-beta.solana.com" and the addresses above,
# then:
python3 tests/host_chat_mock_mainnet.py --port 38191 \
  --recipient 4kYMh3RoXaiwdwXw6NkJTaowMkgq3oNoSGNZh9Y3RG4K \
  --mint USDC --amount 1.50 --memo "mainnet read-only construction" \
  --invoice-id mainnet-readonly-2026-07-30 --expect ok &
zeroclaw --config-dir <disposable> agent -a m5 \
  -m "Build a guarded USDC transfer of 1.50 to the allowlisted recipient."

# then verify the bytes with an independent library and re-simulate:
python3 tests/mainnet_inspect.py --transaction <captured.b64> \
  --rpc-url https://api.mainnet-beta.solana.com \
  --sender F7p3dFrjRTbtRp8FRF6qHLomXbKRBzpvBLjtQcfcgmNe \
  --mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
  --recipient 4kYMh3RoXaiwdwXw6NkJTaowMkgq3oNoSGNZh9Y3RG4K \
  --amount-raw 1500000 --decimals 6 --memo "mainnet read-only construction"
```

`mainnet_inspect.py` needs `solders` and `httpx`. The transaction's recent
blockhash expires in ~60–90 s, so a captured fixture can be decoded and
structurally re-checked indefinitely but can only be *simulated* while fresh —
rebuild to re-simulate.

### `solana-pay-request` on mainnet

Not applicable, and deliberately so: `solana-pay-request` declares
`config_read` only, imports no `wasi:http`, and makes no network call on any
cluster. It composes a mainnet-usable Solana Pay URL for a mainnet mint without
ever contacting a mainnet endpoint — the cluster is the wallet's concern, not
the plugin's.

### Residual notes

- The configured RPC endpoint remains a trust boundary on mainnet exactly as on
  devnet: a dishonest endpoint can misreport mint state. What the plugin
  guarantees is that the returned bytes are internally consistent with the state
  it accepted, and that the approval summary is derived from those bytes.
- Case 1's success depends on the sampled sender still holding USDC and its ATA
  still existing. If a future reproduction picks a wallet that has since moved
  its balance, mainnet simulation fails and the plugin refuses — which is the
  correct behavior, not a regression.
- Mainnet compute usage (`22853` CU) is recorded as an observation. No
  compute-budget instruction is set; devnet execution showed none is required.

## Part 4 — Packaging and registry-install validation

**Verdict: PASS.** Both plugins package reproducibly, produce the exact registry
entries the maintainers' publish workflow will emit, and **install end to end
through the real `zeroclaw plugin install <name> --registry <url>` path** —
including sha256 verification, which was proven to fail closed against a
deliberately corrupted index.

`registry.json` in this PR is **unchanged**, and that is the correct answer
rather than an omission. See "Why a contributor cannot add registry entries"
below: CI structurally rejects it.

Recorded: 2026-07-30. Host `zeroclaw 0.8.3`. Components built with
`cargo +1.96.1 build --locked --target wasm32-wasip2 --release`.

### Why a contributor cannot add registry entries

`registry.json` is a generated index, and `tools/build-registry.py --check-history`
is a **required-gate** check that compares the PR's committed `registry.json`
against the merge base. It rejects any entry that appears in the candidate but
not the base, unconditionally:

```
$ python3 tools/build-registry.py --check-history registry.json dist/registry.json
error: registry entry was added outside the publication builder: solana-pay-request@0.1.0
error: registry entry was added outside the publication builder: spl-transfer-build@0.1.0
```

That is the check as CI invokes it (`.github/workflows/validate.yml` diffs
`<base>:registry.json` against the committed file). The only path that legitimately
adds entries is `.github/workflows/publish.yml`, which runs on push to `main`,
uploads the zips to the `plugins` release, verifies every URL and digest, and
commits the refreshed index itself.

So a submission that hand-adds entries does not become "installable" — it fails
the required gate. The useful thing a contributor can do is prove the packaging
contract holds and that the install path works, which is what follows.

### Reproducible packaging

The CI package dry run was reproduced locally, byte for byte:

```
verified 2 planned staged plugin(s)
  packaged solana-pay-request v0.1.0  sha256=f111d91904d8…
  packaged spl-transfer-build v0.1.0  sha256=d577ad1c6ed3…
wrote registry.json with 26 entries
```

| Archive | Bytes | SHA-256 |
|---|---|---|
| `solana-pay-request-0.1.0.zip` | 84 KiB | `f111d91904d8ed5ef82f217ca0178dedda07a22a3a2d6493bd20305404acf509` |
| `spl-transfer-build-0.1.0.zip` | 243 KiB | `d577ad1c6ed3c3c814e0944e7b69a9c49b462e4bf021933a85f810f81eb6dd40` |

Zip contents are exactly the install contract — no source, no docs, no tests:

```
spl-transfer-build/manifest.toml                305 bytes   1980-01-01 00:00
spl-transfer-build/spl_transfer_build.wasm   703484 bytes   1980-01-01 00:00
solana-pay-request/manifest.toml                282 bytes   1980-01-01 00:00
solana-pay-request/solana_pay_request.wasm   229624 bytes   1980-01-01 00:00
```

Fixed timestamps and permissions mean identical content always yields an
identical digest. Verified concretely: packaging the same staged bytes twice
with **different** `--release-base` values produced **identical** zip digests —
only the `url` field differs. The index therefore only churns when plugin
content actually changes.

Contract checks, all passing:

| Command | Result |
|---|---|
| `--staged … --release-base … --existing-registry registry.json --matrix-json … --out dist` | 2 planned plugins verified, 26-entry index written |
| `--source-plugins staged --check-metadata dist/registry.json` | `registry metadata matches 2 indexed canonical manifest entries` |
| `--check-publication registry.json dist/registry.json dist` | `verified exact publication set with 2 new archives` |
| `tools/ci/plan_matrix.py --event pull_request` | selects exactly the two plugins, `mode: changed` |

### The exact entries the publish workflow will emit

No maintainer action beyond merge is required — these are generated, not
proposed:

```json
{
  "name": "solana-pay-request",
  "version": "0.1.0",
  "description": "Create deterministic Solana Pay transfer-request URLs without network access or custody",
  "author": "ZeroClaw Solana contributors",
  "capabilities": ["tool"],
  "url": "https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/plugins/solana-pay-request-0.1.0.zip",
  "sha256": "f111d91904d8ed5ef82f217ca0178dedda07a22a3a2d6493bd20305404acf509"
}
{
  "name": "spl-transfer-build",
  "version": "0.1.0",
  "description": "Build and verify an unsigned Solana SPL token transfer with a recent blockhash or durable nonce",
  "author": "ZeroClaw Solana contributors",
  "capabilities": ["tool"],
  "url": "https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/plugins/spl-transfer-build-0.1.0.zip",
  "sha256": "d577ad1c6ed3c3c814e0944e7b69a9c49b462e4bf021933a85f810f81eb6dd40"
}
```

### Real registry install, end to end

The artifacts above were published to a **fork** release
[`registry-install-demo-d577ad1`](https://github.com/Fianko-codes/zeroclaw-plugins/releases/tag/registry-install-demo-d577ad1)
so the host's actual install path could be exercised over HTTPS against real
release assets. Served digests were confirmed equal to the local ones before
testing.

```
$ zeroclaw plugin search solana --registry <fork-release>/registry.json
Plugins matching 'solana' (2):
solana-pay-request v0.1.0 — Create deterministic Solana Pay transfer-request URLs without network access or custody
spl-transfer-build v0.1.0 — Build and verify an unsigned Solana SPL token transfer with a recent blockhash or durable nonce

$ zeroclaw plugin install spl-transfer-build --registry <fork-release>/registry.json
Resolving 'spl-transfer-build' from plugin registry...
Installed plugin spl-transfer-build v0.1.0
Seeded [[plugins.entries]] for 'spl-transfer-build'. …

$ zeroclaw plugin install solana-pay-request --registry <fork-release>/registry.json
Installed plugin solana-pay-request v0.1.0

$ zeroclaw plugin list
Installed plugins:
  spl-transfer-build v0.1.0 — …
  solana-pay-request v0.1.0 — …
```

A pinned install (`spl-transfer-build@0.1.0`) also resolves and installs, into a
separate fresh config directory.

#### Digest verification fails closed

The same release carries `registry-tampered.json`, identical except that
`spl-transfer-build`'s `sha256` is 64 zeros:

```
$ zeroclaw plugin install spl-transfer-build --registry <fork-release>/registry-tampered.json
Resolving 'spl-transfer-build' from plugin registry...
Error: plugin archive sha256 mismatch
$ echo $?
1
$ zeroclaw plugin list
No plugins installed.
```

Transport integrity is enforced, the exit status is non-zero, and nothing is left
half-installed.

### A packaging hazard worth recording

The first attempt reused one tag and deleted/recreated the release. GitHub's
asset CDN then served the **deleted release's bytes** for the same
tag + filename: the install succeeded but delivered the previous manifest, and a
`curl | sha256sum` of the URL returned the old digest while the local file had a
new one. The tag is therefore content-addressed here.

This is exactly the failure the upstream publish workflow already defends
against — it downloads any pre-existing asset of the same name and refuses with
`already exists with different bytes` rather than overwriting. Worth knowing that
the defense is load-bearing, not theoretical.

### One discoverability fix made here

`zeroclaw plugin search solana` matches name and description only. The transfer
plugin's description did not contain the word "Solana", so a user searching the
obvious term found the Solana Pay plugin and missed the Solana transfer builder.
The manifest description is now
`Build and verify an unsigned Solana SPL token transfer with a recent blockhash or durable nonce`
— which also stops understating the plugin, since durable-nonce mode now exists.
`plugin search solana` returns both plugins, as shown above.

Description is manifest-owned metadata, refreshable by the publication builder
(`--check-metadata` passes); the immutable `name@version` identity and the
release fields are untouched.

### Reproducing this

```bash
# build both components, then stage manifest + wasm per plugin
mkdir -p staged/spl-transfer-build staged/solana-pay-request
cp plugins/<name>/manifest.toml staged/<name>/
cp plugins/<name>/target/wasm32-wasip2/release/<name>.wasm staged/<name>/

matrix=$(python3 tools/ci/plan_matrix.py --event pull_request | jq -c .matrix)
python3 tools/build-registry.py --staged staged \
  --release-base "https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/plugins" \
  --existing-registry registry.json --matrix-json "$matrix" --out dist
python3 tools/build-registry.py --source-plugins staged --check-metadata dist/registry.json
python3 tools/build-registry.py --check-publication registry.json dist/registry.json dist
```
