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
576017 bytes
```

## Decisions

- `parse_execute_args` remains the first action in `execute`; its strict Task 4 parser validates the mint and only permits host-injected `__config.rpc_url` before any HTTP work.
- The pure helpers generate exactly `getAccountInfo` ID 1 with `jsonParsed` encoding and `getTokenLargestAccounts` ID 2, each using only the validated mint. The component sends one POST for each helper result, with no retry or alternate endpoint.
- The component requires a 2xx status before streaming. `ResponseBodyAccumulator` bounds each read, rejects cumulative bodies larger than 1 MiB before appending the crossing chunk, then performs UTF-8 conversion. JSON parsing occurs later in the pure core.
- Every argument, transport, status, body-read, encoding, and assessment failure returns a bounded serialized `unknown` report and a stable error code. No failure path can return `green` or panic.
- WIT generation and `waki` are gated to `target_family = "wasm"`; host tests exercise only pure Rust helpers.
- The manifest requests only `tool`, `http_client`, and `config_read`, using repository-established permission vocabulary.

## Self-Review And Concerns

- `log-record` emits only fixed verdict and stable outcome/error codes in its message and attributes. It does not include the mint, endpoint, arguments, request/response bodies, or transport/parser text. The mandatory fixed WIT function name and enum fields contain no user or operator data.
- The JSON Schema exposes only required `mint` with `additionalProperties: false`; the host-only `__config` section and all policy/network controls are absent.
- `waki` 0.5.1 exposes `Response::chunk(&self, len)` for bounded incoming-body reads. The shim uses this API and does not call the unbounded `Response::body()` collector.
- No live RPC call was made. The host test suite covers the deterministic request/argument/boundary helpers, while the WASM release build verifies the actual WIT and `waki` path compiles.

## Review Fix From `7b09dc4`

### Finding And API Verification

Review identified that `Response::body()` buffered the complete incoming body before the 1 MiB helper could reject it. Inspection of `waki` 0.5.1 confirmed that `Response::body(self)` delegates to `Body::bytes()`, whose stream path repeatedly appends chunks without a total limit. The same API exposes `Response::chunk(&self, len)`, which performs one bounded blocking read and returns `None` when the stream closes.

### RED Evidence

Host tests for an exact 1 MiB multi-chunk body, a later chunk crossing the boundary, and stable stream error codes were added before production changes:

```text
cargo test stream_accumulator
error[E0432]: unresolved import `token_risk_check::ResponseBodyAccumulator`
error[E0599]: no variant or associated item named `HttpTransport`, `BodyRead`,
or `ResponseBufferFailure` found for enum `ShimError`
```

The failure was expected because the bounded stream state and typed stream errors did not exist.

### GREEN And Final Verification

The focused tests passed after implementing the accumulator and switching the component to `Response::chunk()`:

```text
cargo test stream_accumulator                         # 2 passed
cargo test stream_errors_have_stable_bounded_unknown_codes  # 1 passed
```

Final verification after the review fix:

```text
cargo test                                      # 34 integration tests passed
cargo clippy --all-targets -- -D warnings       # passed
cargo clippy --target wasm32-wasip2 --all-targets -- -D warnings  # passed
cargo fmt --check                               # passed
git diff --check                                # passed
cargo build --target wasm32-wasip2 --release    # passed
target/wasm32-wasip2/release/token_risk_check.wasm  # 576017 bytes, non-empty
```

### Review-Fix Decisions

- Streaming uses one accumulator `Vec` with amortized linear growth. Each append performs `checked_add`, rejects totals above 1 MiB before mutation, and uses `try_reserve` so capacity failures return `RESPONSE_BUFFER_ERROR` rather than an explicit panic path.
- Reads are capped at 64 KiB while space remains. At the exact 1 MiB boundary, the next read requests only one probe byte; receiving it immediately returns `RESPONSE_TOO_LARGE`, while end-of-stream accepts the exact-boundary body.
- Transport, chunk-read, empty-chunk, buffer, size, and UTF-8 failures map to stable codes and bounded `unknown` tool results. No raw Waki error text is returned or logged.
- The release WASM build is compile validation of the real target-gated `Response::chunk()` integration. No component-level runtime test was claimed because the repository does not provide a host harness for synthetic WASI HTTP streams.
