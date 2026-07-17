# Task 4 Report: Fail-Closed And Injection Resistance

## Scope And Base

- Branch: `codex/token-risk-check`
- Base commit: `c979cad2bd49ae7a6587bf76423abaac56cc64d3`
- Scope: Task 4 only. No WASM HTTP shim, manifest, README, or Task 5 work was started.

## RED Evidence

Added Task 4 tests and fixtures before core changes. The first focused run was:

```text
cargo test never_reports_green_when_required_evidence_is_invalid_or_missing
error[E0432]: unresolved imports `parse_execute_args`, `serialize_report`, `unknown_report`
error[E0599]: no method named `code` found for enum `RiskError`
```

The failure was expected: the fail-closed mapping, strict argument parser, bounded serializer, and typed error-code API did not exist.

## GREEN Evidence

Focused tests passed after the minimal implementation:

```text
cargo test never_reports_green_when_required_evidence_is_invalid_or_missing
cargo test unknown_reports_use_typed_codes_and_bound_error_messages
cargo test execute_args_allow_only_mint_and_host_config
cargo test unknown_extension_names_are_capped_at_32_characters
cargo test serialization_is_valid_json_below_the_cap_or_minimal_unknown
```

Final verification passed:

```text
cargo test                         # 22 integration tests passed
cargo clippy -- -D warnings        # passed
cargo fmt -- --check               # passed
git diff --check                   # passed
```

## Decisions

- Added stable `RiskError::code()` values and `unknown_report`; malformed, missing, null, JSON-RPC-error, unsupported-owner, and supply-mismatch evidence map to `unknown` at the caller boundary.
- Added strict `ExecuteArgs` and nested `ExecuteConfig`, both with `deny_unknown_fields`. Only `mint` and host-injected `__config.rpc_url` are accepted; root `rpc_url`, `threshold`, `method`, and nested unknown fields are rejected. Mint and configured HTTPS URL are validated while parsing.
- The plan schedules the host-testable parser under Task 5, but the Task 4 brief and acceptance request explicitly require it. It remains pure-core code in `risk.rs`; no Task 5 transport work was added.
- Error messages and unknown Token-2022 extension names are bounded by Unicode character count (160 and 32 respectively). Rule production remains capped at 12 reasons.
- `serialize_report` never byte-truncates JSON. Reports with too many reasons or over 8 KiB are replaced by a compact valid `unknown` report with `OUTPUT_TOO_LARGE`.

## Self-Review And Concerns

- The existing report schema represents authority status as booleans. For unknown evidence the fallback keeps schema compatibility and adds `EVIDENCE_UNAVAILABLE`; consumers must honor the `unknown` verdict rather than infer meaning from placeholder evidence fields.
- Task 5 must route every tool response through `serialize_report` and map all `RiskError` values through `unknown_report`; the pure core now exposes both interfaces for that purpose.
- No network, WASM, manifest, documentation, or Task 5 verification was run because it is outside this task's scope.

## Review Fix From `6a01a13`

### Schema Confirmation

Agave's current `UiMint` source defines `is_initialized: bool` under `#[serde(rename_all = "camelCase")]`, so the exact JSON field is `isInitialized` and its type is boolean. The same source defines `extensions` as `Vec<UiExtension>` with `skip_serializing_if = "Vec::is_empty"`, so legacy mints and Token-2022 mints with no parsed extensions may omit the field:

- <https://github.com/anza-xyz/agave/blob/master/account-decoder-client-types/src/token.rs#L1454-L1473>
- <https://github.com/anza-xyz/agave/blob/master/account-decoder/src/parse_token.rs#L1754-L1791>

Task 4 now intentionally requires explicit `extensions` presence for Token-2022 despite that omission behavior. This may return `unknown` for a no-extension Token-2022 mint, but it prevents missing extension evidence from becoming `green`. Legacy mints continue to accept omitted `extensions`.

### RED Evidence

After adding four regressions and before changing production code:

```text
cargo test rejects_
test result: FAILED. 7 passed; 4 failed
```

The failing tests were `rejects_token_2022_without_extensions_evidence`, `rejects_uninitialized_mint`, `rejects_mint_without_initialization_evidence`, and `rejects_malformed_initialization_evidence`. Each failed because `assess` returned a report instead of `MalformedRpcResponse`.

A second presence-model RED verified that JSON null is not treated like an omitted legacy field:

```text
cargo test rejects_null_legacy_extensions_evidence
test result: FAILED. 0 passed; 1 failed
```

The first `Option<Vec<_>>` implementation collapsed missing and null. It was replaced with an explicit `Missing | Present(Vec<_>)` evidence type, so only an omitted key receives the legacy-compatible `Missing` state; null and non-array values fail deserialization.

### GREEN And Verification Evidence

The focused suite passed after modeling extension presence and requiring a true boolean `isInitialized`:

```text
cargo test rejects_                  # 12 passed
```

Final verification:

```text
cargo test                           # 27 integration tests passed
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
git diff --check
```

All commands exited successfully. The prior malformed-account fixture now includes truthful `isInitialized: true`, leaving its missing owner as the intended malformed evidence.
