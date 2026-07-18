# M2.5 upstream-integration results

## Verdict

**PASS.** The completed M2 plugin is represented by a real fork branch based
on the current upstream default branch, reproduces from a clean clone, passes
the upstream validation workflow, and executes through the real ZeroClaw agent
runtime. M3 was not started.

The upstream pull request is intentionally a draft. GitHub marked its first
upstream workflow run `action_required`, pending the upstream maintainers'
approval to run fork-originated workflows. The identical workflow completed
successfully in the fork at
<https://github.com/Fianko-codes/zeroclaw-plugins/actions/runs/29639166262>.

## Repository record

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

## Provisional `nanosol` packaging

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

## Layout and contract checks

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
  `RESULTS.md` are preserved.
- `registry.json` was not edited.
- No tracked source contains a local absolute checkout path.
- No dependency refers to the standalone repository by filesystem path.
- Validation did not mutate tracked source files.

## Commands and results

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

### Clean clone

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

### Observed non-source limitation

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

## Component artifact

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

## Real-host rerun

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

## Remaining items

- Maintainers must choose the final shared-core packaging boundary before the
  pull request leaves draft.
- An upstream maintainer must approve the first fork-originated Actions run on
  draft PR 54. The same exact workflow is already green in the fork.
- `spl-transfer-build` and every M3 concern remain unstarted.

## M3 shared-core regression addendum

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
