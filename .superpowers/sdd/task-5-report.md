# Task 5 Report: WASM HTTP Shim And Structured Logging

## Scope And Base

- Branch: `codex/token-risk-check`
- Base commit: `0f609de8f81781acf0da1dd417602aaa3156406b`
- Scope: Task 5 only. Added the target-gated component shim, manifest, WASM-only HTTP dependency, host-testable shim helpers, tests, and this report. No README, demo, or submission work was started.

## RED Evidence

Added host tests for strict execution arguments, fixed RPC request bodies and IDs, JSON Schema surface, and response status/size/UTF-8 handling before component production code.

The focused RED run was:

```text
cargo test rpc_request_bodies_use_only_validated_mint_and_fixed_methods
error[E0432]: unresolved imports `bounded_response_body`, `parameters_schema`,
`rpc_request_bodies`, `ShimError`
```

This was the expected failure: the new shim helper APIs did not exist.

## GREEN And Verification Evidence

After the minimal helpers and target-gated component were added:

```text
cargo test                                      # 31 integration tests passed
cargo clippy --all-targets -- -D warnings       # passed
cargo fmt --check                               # passed
git diff --check                                # passed
cargo build --target wasm32-wasip2 --release    # passed
```

The release component exists and is non-empty:

```text
target/wasm32-wasip2/release/token_risk_check.wasm
575678 bytes
```

## Decisions

- `parse_execute_args` remains the first action in `execute`; its strict Task 4 parser validates the mint and only permits host-injected `__config.rpc_url` before any HTTP work.
- The pure helpers generate exactly `getAccountInfo` ID 1 with `jsonParsed` encoding and `getTokenLargestAccounts` ID 2, each using only the validated mint. The component sends one POST for each helper result, with no retry or alternate endpoint.
- `bounded_response_body` requires a 2xx status, reads bytes, rejects bodies larger than 1 MiB, then performs UTF-8 conversion. JSON parsing occurs later in the pure core.
- Every argument, transport, status, body-read, encoding, and assessment failure returns a bounded serialized `unknown` report and a stable error code. No failure path can return `green` or panic.
- WIT generation and `waki` are gated to `target_family = "wasm"`; host tests exercise only pure Rust helpers.
- The manifest requests only `tool`, `http_client`, and `config_read`, using repository-established permission vocabulary.

## Self-Review And Concerns

- `log-record` emits only fixed verdict and stable outcome/error codes in its message and attributes. It does not include the mint, endpoint, arguments, request/response bodies, or transport/parser text. The mandatory fixed WIT function name and enum fields contain no user or operator data.
- The JSON Schema exposes only required `mint` with `additionalProperties: false`; the host-only `__config` section and all policy/network controls are absent.
- `waki` 0.5.1 exposes whole response bodies as bytes. The shim checks status and byte length before any JSON parsing; the host client necessarily materializes the received bytes before that length check.
- No live RPC call was made. The host test suite covers the deterministic request/argument/boundary helpers, while the WASM release build verifies the actual WIT and `waki` path compiles.
