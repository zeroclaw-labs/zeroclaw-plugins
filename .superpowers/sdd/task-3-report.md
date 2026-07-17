# Task 3 Report: Bounded DEX Liquidity Evidence

Base: `d40a193`

Commit: `de68884 feat(token-risk-check): add bounded liquidity evidence`

## Scope

- Added pure `liquidity` parser and fixed DEX Screener token-pairs URL.
- Added bounded, fail-closed pair parsing and stable
  `MALFORMED_LIQUIDITY_RESPONSE` errors.
- Extended `assess` with the fifth liquidity body argument and report evidence.
- Replaced the unconditional liquidity Amber rule with observed/not-observed
  evidence behavior.

Files:

- `plugins/token-risk-check/src/liquidity.rs`
- `plugins/token-risk-check/src/lib.rs`
- `plugins/token-risk-check/src/risk.rs`
- `plugins/token-risk-check/tests/risk.rs`
- `plugins/token-risk-check/tests/fixtures/liquidity-observed.json`
- `plugins/token-risk-check/tests/fixtures/liquidity-empty.json`

## RED Evidence

Before implementation:

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture
```

Result: exit `101`. Compilation failed as expected because the `liquidity`
module, `LiquidityStatus`, `MalformedLiquidityResponse`, fifth `assess` body
argument, and liquidity report fields did not exist.

## GREEN Evidence

Focused liquidity verification:

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture
```

Result: exit `0`; 9 matching integration tests passed.

Final host quality gate:

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml
cargo fmt --manifest-path plugins/token-risk-check/Cargo.toml --check
cargo clippy --manifest-path plugins/token-risk-check/Cargo.toml --all-targets -- -D warnings
git diff --check
```

Result: all commands exited `0`; 57 integration tests passed, with no format,
Clippy, or diff errors.

## Concerns

- Task 4 owns the runtime DEX GET transport. Until then, the WASM execution
  path deliberately passes `[]` to `assess`, so runtime results remain Amber
  with `LIQUIDITY_NOT_OBSERVED`.
- The report always includes `DEXSCREENER_COVERAGE_ONLY`; LP ownership/status
  remains outside this evidence source.

## P1 Fix: Exact Raw Liquidity Decimals

The parser now preserves `liquidity.usd` as `serde_json::value::RawValue` and
enforces the 32-character limit before numeric interpretation. It accepts only
non-negative, plain JSON decimal tokens matching
`0|[1-9][0-9]*(\.[0-9]+)?`; exponent notation, signs, strings, and leading-zero
integers are rejected. Accepted values are canonicalized by trimming fractional
trailing zeroes and compared exactly with a bounded internal decimal
representation. This uses serde_json's built-in `raw_value` feature, not a new
dependency.

### RED Evidence

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture
```

Result: exit `101`; 3 regression tests failed as intended. A 33-character raw
token was normalized to `1e+32`, two distinct precise decimals both became
`1000000000000000.0`, and exponent notation was accepted.

### GREEN Evidence

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture
```

Result: exit `0`; 13 matching tests passed, including raw-token length,
precision-ordering, zero-integer-boundary comparison, canonicalization, and
exponent-rejection coverage.

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml
cargo fmt --manifest-path plugins/token-risk-check/Cargo.toml -- --check
cargo clippy --manifest-path plugins/token-risk-check/Cargo.toml --all-targets -- -D warnings
git diff --check
```

Result: all commands exited `0`; 61 integration tests passed.

## P1 Fix: Fractional Leading-Zero Ordering

The decimal comparison representation now retains the accepted integer string
and original fractional string separately. Integer magnitude is compared first;
fractional digits are then compared at their preserved scales with right-zero
padding. Canonical output still removes insignificant fractional trailing
zeroes, so `0.10` and `0.1` both report as `0.1`.

### RED Evidence

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture
```

Result: exit `101`; 16 matching integration tests ran, with 14 passed and 2
failed as intended. `0.01` preceding `0.1` incorrectly selected `0.01`, and
`0.001` preceding `0.0009` incorrectly selected `0.0009`. The canonical equal
case `0.10` and `0.1` passed.

### GREEN Evidence

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml liquidity -- --nocapture
```

Result: exit `0`; all 16 matching integration tests passed, including the
leading-zero ordering, adjacent-scale, and canonical-equality regressions.

### Final Quality Gate

```bash
cargo test --manifest-path plugins/token-risk-check/Cargo.toml
cargo fmt --manifest-path plugins/token-risk-check/Cargo.toml --check
cargo clippy --manifest-path plugins/token-risk-check/Cargo.toml --all-targets -- -D warnings
git diff --check
```

Result: all commands exited `0`; 64 integration tests passed, with 0 unit and
0 doc tests. Formatting, Clippy, and whitespace checks reported no errors.
