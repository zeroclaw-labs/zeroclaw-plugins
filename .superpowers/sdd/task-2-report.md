# Task 2 Report: Aggregate Observed Token Owners

## Scope And Base

- Branch: `codex/token-risk-check`
- Base: `3425363` (Task 1 interfaces at `63e35e7`)
- Commit: `3d11629 feat(token-risk-check): aggregate observed token owners`
- Scope: Task 2 owner-evidence parsing and aggregation only. No transport execution or liquidity behavior was changed.

## RED Evidence

Tests and fixtures were added before production changes. The required focused command was run:

```text
cargo test --manifest-path plugins/token-risk-check/Cargo.toml owner -- --nocapture
```

It failed at compilation as expected: `assess` accepted three arguments rather than four, and `Evidence`/`Slots` lacked `top_observed_owner_bps` and `owner_accounts`.

Self-review added a second regression before its production fix:

```text
cargo test --manifest-path plugins/token-risk-check/Cargo.toml \
  bounded_owner_slot_skew_never_reports_green -- --nocapture
```

It failed as expected because valid owner evidence at `largest slot + 2` returned `Green` instead of `Amber` with `EVIDENCE_SLOT_SKEW`.

## GREEN And Verification Evidence

- Focused owner tests: 11 passed.
- Owner slot-skew regression: 1 passed after the minimal rule update.
- Final `cargo test --manifest-path plugins/token-risk-check/Cargo.toml`: 51 integration tests passed, 0 failed; doc-tests passed.
- `cargo clippy --manifest-path plugins/token-risk-check/Cargo.toml --all-targets -- -D warnings`: passed.
- `cargo fmt --manifest-path plugins/token-risk-check/Cargo.toml --check`: passed.
- `git diff --check`: passed before staging and for the staged commit.

## Changes

- `plugins/token-risk-check/src/risk.rs`
  - `assess` now consumes owner RPC evidence as its fourth argument and requires JSON-RPC ID 3.
  - Strictly binds nullable ordered account values to the largest account count, token program, mint, initialized state, parsed amount, valid owner key, and bounded non-reversed slots.
  - Rejects duplicate or invalid largest-account addresses during owner binding.
  - Aggregates validated balances with `BTreeMap<String, u128>` and checked addition.
  - Adds `top_observed_owner_bps`, `owner_accounts`, `TOP_OWNER_CONCENTRATED`, and `OWNER_CONCENTRATION_TOP_ACCOUNTS_ONLY`.
- `plugins/token-risk-check/tests/risk.rs`
  - Covers shared owners at exactly 5,000 bps, distinct owners, null/count/order/mint/program/amount/owner/state violations, invalid slots and response ID, duplicate addresses, and positive owner slot skew.
- `plugins/token-risk-check/tests/fixtures/owners-shared.json`
- `plugins/token-risk-check/tests/fixtures/owners-dispersed.json`

## Self-Review And Concerns

- Owner concentration is intentionally a lower bound over the bounded largest-account set and is labeled with `OWNER_CONCENTRATION_TOP_ACCOUNTS_ONLY`.
- Any malformed, contradictory, duplicate, missing, or out-of-slot owner evidence fails closed through the existing typed error path rather than returning Green.
- WASM transport was intentionally not built or changed: Task 4 must fetch and pass the third RPC response after owner-request construction. Liquidity remains deferred to Task 3.

## Fix Review Findings

### RED Evidence

The new no-liquidity behavior was specified first in `plugins/token-risk-check/tests/risk.rs` and failed before the production change:

```text
cargo test --manifest-path plugins/token-risk-check/Cargo.toml reports_amber_when_liquidity_is_not_observed -- --nocapture
```

Result: 0 passed, 1 failed. The assertion showed the valid four-input assessment returned `Green` instead of required `Amber`.

### Changes

- `plugins/token-risk-check/src/lib.rs`
  - WASM `execute` now derives `owner_accounts_request_body` from the largest-account response, sends the bounded third JSON-RPC POST through the existing `post_json`, and passes the resulting body to four-argument `assess`.
  - No DEX GET was added.
- `plugins/token-risk-check/src/risk.rs`
  - Four-input assessments add Amber reason `LIQUIDITY_NOT_OBSERVED` with message `No liquidity evidence is collected in this assessment` and limitation `LIQUIDITY_NOT_OBSERVED`.
- `plugins/token-risk-check/tests/risk.rs`
  - Replaces owner-only Green expectations with Amber liquidity-not-observed assertions and updates complete reason-order/truncation expectations.

### Verification

```text
cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture
```

Result: 3 passed, 0 failed.

```text
cargo test --manifest-path plugins/token-risk-check/Cargo.toml
```

Result: 51 integration tests passed, 0 failed; 0 doc-tests failed.

```text
cargo check --manifest-path plugins/token-risk-check/Cargo.toml --target wasm32-wasip2
cargo build --manifest-path plugins/token-risk-check/Cargo.toml --target wasm32-wasip2
cargo fmt --manifest-path plugins/token-risk-check/Cargo.toml --check
git diff --check
! rg -n 'assert_eq!\\([^\\n]*Verdict::Green' plugins/token-risk-check/tests/risk.rs
```

Result: all commands exited 0. The WASM check/build compile the third POST and four-argument `assess` call; the final scan found no owner-only Green assertion.

### Commit

`fix(token-risk-check): fetch owner evidence and block unobserved liquidity Green`

### Concerns

- `LIQUIDITY_NOT_OBSERVED` does not claim that liquidity is absent. It records that this Task 2 four-input assessment has no liquidity evidence.
- Until Task 3 supplies the fifth liquidity body, valid low-risk owner evidence remains Amber by design.
