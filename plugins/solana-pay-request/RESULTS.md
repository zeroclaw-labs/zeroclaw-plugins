# M2 Results — `solana-pay-request`

> This is the preserved standalone M2 report from commit
> `1701e4ed4f18d0bc0939e87d5ceca6ad0e65a9e9`. Its dependency table records the
> original repository-local M1 linkage. Upstream-layout M2.5 evidence is kept
> separately in `INTEGRATION_RESULTS.md`.

## Verdict

M2 passes. The final source passes the locked host and `wasm32-wasip2` command
matrix, ZeroClaw 0.8.3 discovers and registers the real component, and a real
two-turn `zeroclaw agent` chat call executes the tool under the default
1,000,000,000-unit fuel budget. The localhost oracle accepted the returned
reference, URL, and identical QR payload.

M3 was not started.

## Date and environment

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

## Resolved production dependencies

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

## Final acceptance commands

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

## Artifact

- Path:
  `plugins/solana-pay-request/target/wasm32-wasip2/release/solana_pay_request.wasm`.
- Format observed by `file`: WebAssembly component, binary version `0x1000d`.
- Size: **230,774 bytes**.
- SHA-256:
  `1462d6e1cae71282620ce183c5f60806fac95bb38eb4f19a65c88c2b824783d5`.
- The generated `target/` directory is ignored and is not part of the source
  commit.

## Oracle and behavior results

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

## Failed development commands and corrections

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

## Deviations, disproven assumptions, and warnings

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
