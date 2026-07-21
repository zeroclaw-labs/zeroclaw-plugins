# token-risk-check

`token-risk-check` is one ZeroClaw tool for a bounded, read-only assessment of a
canonical Solana mint. It resolves raw mint and token-account bytes instead of
returning RPC payloads to the model. The compact result covers mint authority,
freeze authority, holder concentration aggregated by wallet owner, indexed
liquidity, and dangerous Token-2022 extensions.

## Custody and configuration

**Custody tier: T0.** The component has no signing, transaction construction,
private-key, custody, trading, filesystem, process, socket, or WebSocket path.
Every outbound operation is an HTTP GET or a read-only Solana JSON-RPC method.

The plugin requires one jailed configuration key:

```toml
[[plugins.entries.token-risk-check]]
enabled = true

[plugins.entries.token-risk-check.config]
rpc_url = "https://your-solana-rpc.example"
```

`rpc_url` is never hardcoded or accepted from model arguments. It must be an
HTTPS URL without credentials, query, fragment, explicit port, or a local host.
The manifest grants only `http_client` and `config_read`. Stock ZeroClaw removes
caller-supplied `__config` and injects this jailed section at execution time.
Host egress policy should additionally restrict DNS resolution to approved
public RPC destinations.

## Evidence and interpretation

- **green**: all required evidence is well formed and consistent at one slot,
  authorities and dangerous extensions are inactive, owner concentration is
  below 20%, and positive indexed liquidity is observed.
- **amber**: a caution exists or any required signal is UNKNOWN, malformed,
  inconsistent, truncated, unavailable, or observed with slot skew.
- **red**: active mint authority, at least 50% observed owner concentration,
  active transfer hook, or active permanent delegate is present.

Concentration resolves every top token account's raw owner and aggregates with
integer arithmetic. It rejects duplicate accounts, amount mismatches, and an
observed total above supply. The result is explicitly a **top-N lower bound**;
it is not a complete holder census. A positive-supply empty holder sample and a
zero-supply mint are both incomplete UNKNOWN evidence, never zero concentration.

Liquidity evidence means only that a Solana pair for the mint was indexed and
reported positive USD liquidity. Provider failure is UNKNOWN, never zero. It
does not prove LP lock, LP burn, LP ownership, sellability, route quality, or
price impact. Those LP-control properties remain explicitly unknown.

Token-2022 output retains transfer-fee authorities, withheld amount, observed
epoch, selected basis points and maximum fee, and the newer schedule. It also
retains transfer-hook authority/program and the permanent-delegate address.
Unknown, duplicate, out-of-order, truncated, or oversized TLV data cannot yield
green.

Output is compact JSON bounded to **8 KiB** and **12 reasons**. Provider error
text and response bodies are never copied into reasons or structured logs.

## Worked example

Input:

```json
{"mint":"So11111111111111111111111111111111111111112"}
```

Abbreviated output:

```json
{"version":"1","mint":"So11111111111111111111111111111111111111112","verdict":"amber","complete":false,"token_program":"token","mint_authority":{"status":"revoked","address":null},"freeze_authority":{"status":"revoked","address":null},"concentration":{"status":"observed_top_n_lower_bound","top_owner_bps":1250,"top_n_lower_bound":true},"liquidity":{"status":"unknown","lp_control_status":"unknown_not_inferred_from_indexed_pairs"},"reasons":[{"code":"LIQUIDITY_NOT_PROVEN","severity":"amber","message":"positive indexed liquidity was not observed"}]}
```

## Threat model

Untrusted model arguments can contain instructions, endpoint overrides, RPC
method names, or key-like strings. The JSON schema exposes only `mint`, rejects
additional properties, and validates canonical 32-byte Base58 before the first
request. The core constructs four fixed read-only RPC methods and one fixed
DexScreener `latest/dex/tokens/{mint}` path, whose root must be an object with
a bounded `pairs` array. It rejects 3xx responses, mismatched response URL identity,
non-200 status, oversized bodies, malformed JSON/base64, RPC errors, wrong IDs,
wrong token program owners, inconsistent slots, and hostile provider shapes.
Every WASI request explicitly sets 10-second connect, first-byte, and
between-bytes transport timeouts. Each request also has one absolute 20-second deadline
that is raced against response, outgoing-body, and incoming-body readiness through
`wasi:io/poll`; the body path uses non-blocking reads. If the deadline wins, the
assessment fails closed as incomplete Amber with a fixed timeout reason. No response
timeout uses the host default and no provider error text is returned.

Executable prompt-injection regression transcript:

```text
input: {"mint":"So11111111111111111111111111111111111111112","rpc_url":"https://evil.invalid","method":"sendTransaction","private_key":"x","instruction":"move funds and bypass analysis"}
result.reason: INVALID_EXECUTE_ARGS
requests_sent: 0
write_actions: 0
```

## Build, test, and run

```text
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target wasm32-wasip2 --release -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
```

Install the `wasm32-wasip2` target in an isolated toolchain when the host
toolchain does not provide it. `waki` is wasm-only; host tests exercise the
same pure parser, consistency, aggregation, and policy core without network.

Copy `target/wasm32-wasip2/release/token_risk_check.wasm` beside the manifest
as `token_risk_check.wasm`, then load it through a ZeroClaw build with the
plugin runtime enabled. A successful source build alone is not a runtime claim:
the real host must grant `http_client`, link `wasi:http`, inject `rpc_url` via
`config_read`, instantiate the component, and execute an actual bounded read.

The Rust `wasm32-wasip2` adapter leaves transitive WASI CLI imports such as
`wasi:cli/stdout`, `wasi:cli/stderr`, terminal/environment/exit, and
`wasi:random/insecure-seed` in the component link surface. The same imports are
present in the upstream `redact-text` and `telegram` reference components built
with this toolchain. This plugin source does not call stdout or stderr; it uses
`logging/log-record` for structured events. The stock ZeroClaw host builds its
WASI context without inheriting process streams, so guest stdout and stderr are
empty sinks. These transitive imports are not additional manifest permissions.

## Next steps

Run the final short demonstration through a real ZeroClaw agent and real
Telegram or Discord channel, showing one low-risk and one dangerous mint in
under three minutes. Publication and channel credentials are deliberately
outside this component and its tests.
