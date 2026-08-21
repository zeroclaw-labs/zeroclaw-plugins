# `solana-pay-request` — evidence

One validation record for this plugin, in the order the work happened. Every claim below is a command that was run and an output that was observed; failed commands are preserved rather than removed.

1. [Build, test, and acceptance](#part-1-build-test-and-acceptance)
2. [Upstream integration and real-host rerun](#part-2-upstream-integration-and-real-host-rerun)

---
## Part 1 — Build, test, and acceptance

> This is the preserved standalone M2 report from commit
> `1701e4ed4f18d0bc0939e87d5ceca6ad0e65a9e9`. Its dependency table records the
> original repository-local M1 linkage. Upstream-layout M2.5 evidence is kept
> separately in Part 2 below.

### Verdict

M2 passes. The final source passes the locked host and `wasm32-wasip2` command
matrix, ZeroClaw 0.8.3 discovers and registers the real component, and a real
two-turn `zeroclaw agent` chat call executes the tool under the default
1,000,000,000-unit fuel budget. The localhost oracle accepted the returned
reference, URL, and identical QR payload.

M3 was not started.

### Date and environment

- Recorded: `2026-07-18T14:17:22+05:45` (`Asia/Kathmandu`).
- OS: Arch Linux rolling, Linux `7.1.3-arch1-3`, x86_64.
- M2 branch: `agent/m2-solana-pay-request`.
- M2 base commit: `961ad7b8a10e1a4df8a2090aa1092b943ed4a35e`.
- The working tree was clean when the branch was created; this report and the
  M2 files were uncommitted while acceptance was run.
- Plugin-reference submodule commit:
  `23a5dcb953f697cae08d8e2802b39894ac9ddda1`.
- `wit/UPSTREAM_REF`:
  `e112ce6b5ccdac9e1cb166bab217e730dd7e24c2`.
- ZeroClaw host commit used for the manual test:
  `e592a555d69c6a701c0fa0fa3f94a4bbcffbb2c2` (`zeroclaw 0.8.3`).
- `rustc +1.96.1 -V`: `rustc 1.96.1 (31fca3adb 2026-06-26)`.
- `cargo +1.96.1 -V`: `cargo 1.96.1 (356927216 2026-06-26)`.
- Installed Rust targets: `x86_64-unknown-linux-gnu`,
  `wasm32-unknown-unknown`, and `wasm32-wasip2`.

### Resolved production dependencies

`Cargo.lock` is committed and was used by every final test, Clippy, and build
command. The direct resolved set is:

| Package | Version/source |
|---|---|
| `nanosol` | `0.1.0`, path `../../nanosol` |
| `serde` | `1.0.228` |
| `serde_json` | `1.0.150` |
| `sha2` | `0.10.9` |
| `wit-bindgen` | `0.46.0`, `wasm32` target only |

The relevant transitive cryptographic/encoding versions inherited from
`nanosol` are `base64 0.22.1`, `bs58 0.5.1`, and
`curve25519-dalek 4.1.3`. There is no HTTP dependency and the manifest grants
only `config_read`.

### Final acceptance commands

Run from `plugins/solana-pay-request` unless otherwise noted.

| Command | Exit | Observed result |
|---|---:|---|
| `cargo +1.96.1 fmt --check` | 0 | No diff after rustfmt. |
| `cargo +1.96.1 test --locked` | 0 | 25 integration tests passed; 0 failed. |
| `cargo +1.96.1 clippy --locked --all-targets -- -D warnings` | 0 | Finished with no warning. |
| `cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings` | 0 | Finished with no warning. |
| `cargo +1.96.1 build --locked --target wasm32-wasip2 --release` | 0 | Produced the component below. |
| `cargo +1.96.1 build --release --features plugins-wasm,plugins-wasm-cranelift` | 0 | Run from the checked-out ZeroClaw host; release build completed in 11m 28s. |
| `ZEROCLAW_CONFIG_DIR=$M2_CONFIG_DIR $ZEROCLAW_BIN plugin list --verbose` | 0 | Listed `solana-pay-request v0.1.0`. |
| `ZEROCLAW_CONFIG_DIR=$M2_CONFIG_DIR $ZEROCLAW_BIN plugin info solana-pay-request --verbose` | 0 | Reported capability `Tool`, permission `ConfigRead`, and the installed component path. |
| `python3 plugins/solana-pay-request/tests/host_chat_mock.py --port 38173` | 0 | Accepted both chat requests and shut down after its assertions passed. |
| `ZEROCLAW_CONFIG_DIR=$M2_CONFIG_DIR $ZEROCLAW_BIN agent -a m2 -m 'Create the configured 25.01 USDC Solana Pay request for invoice 412 to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU, labeled Café & Co, message Table 4 / lunch?, memo Order #412.' --verbose` | 0 | Loaded one WASM tool, retained only that tool by policy, executed it successfully, and completed on iteration 2 with `M2_SMOKE_OK`. |

The host smoke test used only `127.0.0.1`; the component and automated tests
made no live network calls.

### Artifact

- Path:
  `plugins/solana-pay-request/target/wasm32-wasip2/release/solana_pay_request.wasm`.
- Format observed by `file`: WebAssembly component, binary version `0x1000d`.
- Size: **230,774 bytes**.
- SHA-256:
  `1462d6e1cae71282620ce183c5f60806fac95bb38eb4f19a65c88c2b824783d5`.
- The generated `target/` directory is ignored and is not part of the source
  commit.

### Oracle and behavior results

The transfer-request encoding oracle is the official Solana Pay repository at
commit `9b0f8ec70c509c946c387633ae4f1e3115ea4958`, package `@solana/pay 1.0.22`.
The tests reproduce its WHATWG query encoding and transfer-request field
ordering without depending on JavaScript at runtime.

For recipient
`7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU`, USDC mint
`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, canonical amount `25.01`,
and invoice `412`:

- independent digest bytes:
  `c4359f702580c970db693f7aba0da6ceae3aaca35334e4bb4464241c519d747b`;
- base58 reference:
  `ECvLKMSgRzVdJjZsdiGAPcRSjwVjS9f7HxizfC256Kei`;
- the host-returned `url` and `qr_payload` were byte-for-byte equal;
- the localhost chat oracle found the exact URL/reference in the real tool
  result before returning the final assistant response.

The 25 passing tests cover native SOL, configured aliases, direct mint input,
official URL encoding, deterministic repeated runs, reference framing,
closed JSON schema, strict/empty/unknown config, allowlisted recipients,
precision and overflow, caller `__config` spoofing, poisoned display strings,
recipient swaps, unknown aliases, percent-expansion limits, the 4,000-byte
output ceiling, and the absence of QR art, HTTP, and stdout logging.

### Failed development commands and corrections

These are preserved so no intermediate command is misreported as passing:

| Command/attempt | Exit | Cause and correction |
|---|---:|---|
| Initial `cargo +1.96.1 check --locked --lib` | nonzero | Used `.cloned()` on `Option<&str>`; changed to `map(str::to_owned)`, then the same command exited 0. |
| Initial `cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings` | nonzero | Crate-wide `forbid(unsafe_code)` also rejected canonical-ABI unsafe emitted by `wit-bindgen`. The allowance is now scoped only to the generated component module; all handwritten code remains under `deny(unsafe_code)`. The same Clippy command then exited 0. |
| First final `cargo +1.96.1 fmt --check` | 1 | One newly added error-format expression needed rustfmt. `cargo +1.96.1 fmt` exited 0 and the exact check rerun exited 0. |
| First manual chat attempt | 1 | The initial mock required SSE, while this CLI path used non-streaming chat completions. The fixture now validates both host-supported modes. |
| Second manual chat attempt | 1 | ZeroClaw custom providers disable native tool schemas by default, so the loaded tool was not advertised. The disposable provider was corrected with `native_tools = true`; the exact agent command then exited 0. |
| First two reruns of `cargo +1.96.1 test --locked --test request golden_reference_has_independent_sha256_fixture -- --exact --nocapture` | 101 | After adding the asset discriminator, the intentional old string assertion exposed the new base58 vector, then the intentional old byte assertion exposed the new digest bytes. Both fixtures were updated and the final full locked test command passed. |

An earlier host release-build process was interrupted before an exit code was
observed and is not counted as either passing or failing. The complete rerun is
the passing 11m 28s command above.

### Deviations, disproven assumptions, and warnings

1. PLAN's unframed reference preimage concatenates two variable-length strings
   and therefore collides for tuples such as `(amount="1", invoice="23")` and
   `(amount="12", invoice="3")`. It also leaves native-SOL representation
   unspecified; a bare zero sentinel would collide with the syntactically valid
   all-zero direct-mint key. M2 length-prefixes both strings with u32 big-endian
   lengths and includes an explicit SOL/token discriminator before the fixed
   32-byte mint field.
2. PLAN requires enforcing alias precision but lists no way to configure mint
   decimals in a zero-network component. M2 adds `mint_decimals`; every alias
   must have an entry or config loading fails closed.
3. The actual WIT plus `wit-bindgen 0.46.0` emits unsafe canonical-ABI glue.
   A crate-wide `forbid(unsafe_code)` is incompatible with that generated code;
   the narrow generated-module allowance is the smallest working scope. No
   handwritten unsafe exists.
4. In this ZeroClaw checkout, a custom OpenAI-compatible provider requires
   `native_tools = true` for tool schemas to reach the model. Plugin discovery
   alone does not prove chat registration.
5. The disposable host warned that no OS sandbox backend was installed and used
   application-layer security. The risk profile exposed only
   `solana_pay_request`, the component had no network permission, and the test
   used localhost only.
6. The disposable default SQLite memory profile warned that hybrid search had
   no embedder and fell back to keyword search. This did not affect plugin
   discovery or execution.

Unresolved for a later gate: `nanosol` distribution packaging must be resolved
before the pull request leaves draft, and the Telegram presentation path is an
M6 integration concern. Neither is an M2 acceptance condition.

## Part 2 — Upstream integration and real-host rerun

### Verdict

**PASS.** The completed M2 plugin is represented by a real fork branch based
on the current upstream default branch, reproduces from a clean clone, passes
the upstream validation workflow, and executes through the real ZeroClaw agent
runtime. M3 was not started.

The upstream pull request is intentionally a draft. GitHub marked its first
upstream workflow run `action_required`, pending the upstream maintainers'
approval to run fork-originated workflows. The identical workflow completed
successfully in the fork at
<https://github.com/Fianko-codes/zeroclaw-plugins/actions/runs/29639166262>.

### Repository record

- Date: 2026-07-18 (Asia/Kathmandu).
- Environment: Arch Linux, Linux 7.1.3-arch1-3, x86_64.
- Rust: `rustc 1.96.1 (31fca3adb 2026-06-26)`.
- Cargo: `cargo 1.96.1 (356927216 2026-06-26)`.
- Installed targets used here: `x86_64-unknown-linux-gnu` and
  `wasm32-wasip2`.
- Upstream repository: <https://github.com/zeroclaw-labs/zeroclaw-plugins>.
- Upstream default branch and exact base: `main` at
  `23a5dcb953f697cae08d8e2802b39894ac9ddda1`.
- Fork: <https://github.com/Fianko-codes/zeroclaw-plugins>.
- Fork branch: `agent/m25-solana-pay-request`.
- Starting integration worktree state: clean.
- Plugin integration commit:
  `b86e48b12fdc8d19dd582c7b49e5a344f03e570f`.
- Draft upstream pull request:
  <https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/54>.
- Vendored WIT upstream pin:
  `e112ce6b5ccdac9e1cb166bab217e730dd7e24c2`.
- Binding path: `../../wit/v0`, matching upstream `plugins/redact-text`.

The branch was created from the exact upstream commit above; it was not built
by rearranging the standalone repository. The standalone engineering history
remains intact:

- M1 shared-core commit:
  `961ad7b8a10e1a4df8a2090aa1092b943ed4a35e`;
- M2 plugin commit:
  `1701e4ed4f18d0bc0939e87d5ceca6ad0e65a9e9`;
- upstream-layout integration commit:
  `b86e48b12fdc8d19dd582c7b49e5a344f03e570f`.

### Provisional `nanosol` packaging

The standalone filesystem dependency was replaced with this immutable Git
dependency:

```toml
nanosol = { git = "https://github.com/Fianko-codes/zeroclaw-solana.git", rev = "961ad7b8a10e1a4df8a2090aa1092b943ed4a35e" }
```

`Cargo.lock` resolves the full commit and remains committed. There is no
unpinned branch or mutable tag, no local path into the standalone checkout, no
runtime `solana-sdk` dependency, and no crates.io publication. This is the
smallest reversible strategy that passes the current upstream checks while
maintainers decide where the shared core belongs.

Resolved direct versions relevant to this integration are `nanosol 0.1.0` at
the exact Git revision above, `serde 1.0.228`, `serde_json 1.0.150`,
`sha2 0.10.9`, and `wit-bindgen 0.46.0`. `nanosol` resolves `base64 0.22.1`,
`bs58 0.5.1`, and `curve25519-dalek 4.1.3` transitively.

The maintainer question recorded in the draft PR is: should `nanosol` live in
an accepted shared-crate location in this repository, remain an immutable Git
dependency while the PR is draft, or move to a deliberately named and
versioned published crate before review? A minimal documented vendor boundary
remains the fallback if external shared dependencies are not acceptable.

### Layout and contract checks

- The plugin is at `plugins/solana-pay-request`.
- `manifest.toml` name and directory match.
- `wasm_path = "solana_pay_request.wasm"` exists after validation and is
  non-empty.
- The manifest grants `tool` plus only the `config_read` permission.
- The component has no network permission, signer, private key, RPC client, or
  transaction-sending path.
- The host-testable core and thin WASM shim remain separate.
- The scoped generated-WIT unsafe allowance is unchanged.
- The original 25 behavior tests remain present and green.
- `Cargo.lock`, `README.md`, `LICENSE`, manifest, tests, and historical M2
  Part 1 are preserved.
- `registry.json` was not edited.
- No tracked source contains a local absolute checkout path.
- No dependency refers to the standalone repository by filesystem path.
- Validation did not mutate tracked source files.

### Commands and results

All commands in this subsection exited 0 unless explicitly listed under
"Observed non-source limitation."

From `plugins/solana-pay-request` in the integration checkout:

```bash
cargo +1.96.1 fmt --check
cargo +1.96.1 test --locked
cargo +1.96.1 clippy --locked --all-targets -- -D warnings
cargo +1.96.1 clippy --locked --target wasm32-wasip2 -- -D warnings
cargo +1.96.1 build --locked --target wasm32-wasip2 --release
```

Results: formatting passed; 25 tests passed, 0 failed; both host and WASM
Clippy passed with warnings denied; the release component build passed.

From the repository root:

```bash
git diff --check upstream/main HEAD
cargo +1.96.1 fmt --manifest-path plugins/solana-pay-request/Cargo.toml --all -- --check
python3 tools/ci/plan_matrix.py --event pull_request --base upstream/main
python3 -m unittest discover -s tools/tests -p 'test_*.py'
python3 -m unittest discover -s tools/ci/tests -p 'test_*.py'
```

Results: the changed-plugin plan selected only `solana-pay-request` in strict
release mode; registry-tool tests passed 17/17; CI-support tests passed 36/36.
The repository structure guard, registry history check, registry metadata
check, WIT drift check, package dry run, and validation summary also passed.

The component validator was run with an isolated target, reports, logs, and
staging directory using the same strict-plugin setting as CI:

```bash
STRICT_PLUGINS_JSON='["solana-pay-request"]' \
  bash tools/ci/validate_components.sh solana-pay-request
```

It passed host tests, both Clippy modes, the locked release build, artifact
staging, package-tree validation, and the tracked-source mutation guard.

The exact checked-in upstream workflow was then dispatched against integration
commit `b86e48b12fdc8d19dd582c7b49e5a344f03e570f`:

```bash
gh workflow run validate.yml \
  --repo Fianko-codes/zeroclaw-plugins \
  --ref agent/m25-solana-pay-request
gh run watch 29639166262 \
  --repo Fianko-codes/zeroclaw-plugins \
  --exit-status
```

Exit: 0. Format, matrix planning, registry contract (including the pinned
packager container), WIT drift, all four full-sweep component shards, package
dry run, summary, and the required gate passed. Warnings were confined to
pre-existing formatting and Clippy debt in untouched upstream plugins.

#### Clean clone

A fresh clone of the pushed fork branch was made with a new temporary
`CARGO_HOME`, so `nanosol` had to be fetched from its pinned Git source rather
than a pre-existing checkout:

```bash
git clone --branch agent/m25-solana-pay-request --single-branch \
  https://github.com/Fianko-codes/zeroclaw-plugins.git "$CLEAN_DIR/repo"
```

In that clone, all five required plugin commands shown above passed again. The
strict `validate_components.sh` run, registry checks, WIT drift check, package
dry run, summary, source-mutation guard, and repository cleanliness checks also
passed. The test result remained 25 passed, 0 failed. The staged validator
artifact was byte-for-byte identical to the directly built clean-clone
artifact.

#### Observed non-source limitation

This local command exited 1:

```bash
tools/ci/run-packager-python.sh -m unittest discover -s tools/tests -p 'test_*.py'
```

Cause: the installed Docker daemon was inactive and its socket was not
available to the unprivileged session. The underlying suite passed 17/17 with
the host Python interpreter, and the exact pinned-container command later
passed in the successful GitHub Actions workflow above. No source change or
warning suppression was used to bypass it.

The upstream PR workflow is not a failed command: GitHub records it as
`action_required` until an upstream maintainer approves the first fork workflow
run. The fork's exact workflow run is green.

### Component artifact

Clean-clone artifact:

```text
plugins/solana-pay-request/target/wasm32-wasip2/release/solana_pay_request.wasm
```

- Size: 230,753 bytes.
- SHA-256:
  `3ce0f39c07902a67dccb21bd528a8b05d03dced3d6bb9572eeb201a82eb5c8b9`.
- Type: WebAssembly component.

Rust embeds Cargo registry/Git source paths in these release bytes, so the
artifact hash can differ when `CARGO_HOME` has a different path. The values
above are the authoritative fresh-`CARGO_HOME` clean-clone result used for the
final host reload; source, lockfile, tests, and validation remain reproducible.
Generated build artifacts are not tracked.

### Real-host rerun

The clean-clone artifact above was installed with its manifest into a
disposable ZeroClaw 0.8.3 configuration. These checks exited 0:

```bash
ZEROCLAW_CONFIG_DIR="$M25_CONFIG_DIR" "$ZEROCLAW_BIN" plugin list
ZEROCLAW_CONFIG_DIR="$M25_CONFIG_DIR" "$ZEROCLAW_BIN" plugin info solana-pay-request
python3 tests/host_chat_mock.py --port 38173
ZEROCLAW_CONFIG_DIR="$M25_CONFIG_DIR" \
  "$ZEROCLAW_BIN" agent -a m25 -m '<worked-example request>' --verbose
```

The host discovered the component as a tool with `ConfigRead`, advertised
`solana_pay_request` to the model, executed it through the real WASM agent
runtime, emitted structured success logging, and returned `M2_SMOKE_OK` with
the exact golden URL and reference. The mock bound only to localhost and made
no live network request. The installed bytes matched the clean-clone SHA-256.

The host warned that no OS sandbox backend was active. This does not expand the
component's WIT permissions: the plugin remains zero-network and config-read
only, but production operators should enable the platform sandbox independently
of this plugin.

### Remaining items

- Maintainers must choose the final shared-core packaging boundary before the
  pull request leaves draft.
- An upstream maintainer must approve the first fork-originated Actions run on
  draft PR 54. The same exact workflow is already green in the fork.
- `spl-transfer-build` and every M3 concern remain unstarted.

### M3 shared-core regression addendum

Recorded 2026-07-18 after the focused M3 core evolution. This addendum
supersedes only the dependency/artifact facts above; it does not rewrite the
preserved M2.5 execution record.

- Both plugin manifests now pin immutable `nanosol` revision
  `989cd0d3bd25ce6a2d796f72c0dc6a4ae56d989f` from
  <https://github.com/Fianko-codes/zeroclaw-solana>. No branch dependency or
  local path is used.
- M2 now calls the shared `nanosol::reference::derive_payment_reference`
  implementation. The framing, asset discriminator, digest bytes, base58
  reference, URL, QR payload, and all other M2 golden behavior are unchanged.
- At validated implementation head
  `8d3895cea02c7e4722602a43598b1159cd562c5e`, all five required Rust 1.96.1
  commands passed again from `plugins/solana-pay-request`: `fmt --check`,
  locked host tests, host Clippy with warnings denied, WASM Clippy with warnings
  denied, and locked release WASM build.
- Result: 25 tests passed, 0 failed, 0 ignored. The final clean-clone strict
  validator also reported test/clippy/WASM-build exit codes `0/0/0/0` and a
  clean source-mutation guard.
- Fresh-`CARGO_HOME` strict staged artifact: 230,812 bytes; SHA-256
  `4d0a6469de763b8ebca3ceac35c5cb6c9e67f5bcb2816f05d85ac22467daf8bd`.
  Cargo embeds source paths, so this supersedes the earlier artifact identity
  only for the M3 branch and validation environment.
- The cross-component M3 golden test reproduces M2 reference
  `ECvLKMSgRzVdJjZsdiGAPcRSjwVjS9f7HxizfC256Kei` for the same framed invoice
  tuple. No M2 schema, permissions, custody boundary, or output shape changed.
