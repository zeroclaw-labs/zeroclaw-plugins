# Task 3 Report: Authorities, Concentration, And Token-2022 Rules

Base commit: `6db089b`

## Scope

Implemented the Task 3 deterministic rule table in
`plugins/token-risk-check`:

- Active mint and freeze authorities produce amber reasons.
- Largest token-account concentration is amber at and above 5,000 basis
  points.
- Token-2022 `transferHook`, `permanentDelegate`,
  `confidentialTransferMint`, and `nonTransferable` produce red reasons.
- Token-2022 `transferFeeConfig` and frozen `defaultAccountState` produce
  amber reasons.
- Unrecognized Token-2022 extension names produce amber reasons.
- Reasons sort by severity (`red`, then `amber`) and stable reason code, cap
  at 12, and add `REASONS_TRUNCATED` when capped.

## TDD RED Evidence

After adding the rule tests and fixtures, before production-rule changes:

```bash
cd plugins/token-risk-check && cargo test marks_
```

Result: exit `101`; 5 tests failed, 0 passed, 9 filtered out.

Every failure was the expected unimplemented-rule assertion: the core returned
`Green` where the test required `Amber` or `Red`.

- `marks_active_authorities_amber`: `Green` instead of `Amber`.
- `marks_concentration_boundary_amber`: `Green` instead of `Amber`.
- `marks_high_risk_token_2022_extensions_red`: `Green` instead of `Red`.
- `marks_fee_and_default_frozen_extensions_amber`: `Green` instead of
  `Amber`.
- `marks_unknown_extensions_amber_and_truncates_reasons`: `Green` instead of
  `Amber`.

No RED failure was caused by a fixture, decoding, or compilation error.

## GREEN Evidence

After implementing the rule table:

```bash
cd plugins/token-risk-check && cargo test marks_
```

Result: exit `0`; 5 passed, 0 failed.

Final verification:

```bash
cd plugins/token-risk-check && cargo clippy --all-targets -- -D warnings
cd plugins/token-risk-check && cargo fmt --check
cd plugins/token-risk-check && cargo test
git diff --check
```

Results:

- Clippy: exit `0`, no warnings.
- Formatting: exit `0`.
- Full test suite: exit `0`; 14 integration tests passed, 0 failed; unit and
  doc tests also had 0 failures.
- Diff check: exit `0`.

The full suite includes the prior fixed-RPC-ID, JSON-RPC-error,
public-key-authority, and legacy green-path tests.

## Decisions

- The concentration threshold is the non-configurable constant `5_000`; the
  comparison is inclusive.
- Extension names are matched only as documented Solana `jsonParsed` camelCase
  variants: `transferFeeConfig`, `transferHook`, `permanentDelegate`,
  `defaultAccountState`, `confidentialTransferMint`, and `nonTransferable`.
  No case folding or aliases are accepted.
- `defaultAccountState` is amber only when its documented
  `state.accountState` is exactly `frozen`.
- Existing legacy mints ignore Token-2022 extension rules and remain green
  when their required Task 2 evidence is low risk.
- Rule severity uses an ordered internal enum so red reasons precede amber;
  `sort_by` then orders by the stable public reason code. Equal-code entries
  retain their evidence order.
- The separate unknown-extension fixture has 13 entries, proving the 12-reason
  cap and `REASONS_TRUNCATED` limitation.

## Self-Review

Reviewed the final diff and line-level control flow for the following:

- Task 1-2 request IDs remain fixed at `1` and `2` and are still validated.
- Active authorities still pass the 32-byte base58 public-key validation before
  any amber rule is emitted.
- Legacy complete evidence remains green with no reasons.
- The supplied concentration boundary is exactly 5,000 bps.
- Exact Token-2022 extension spelling, red-over-amber aggregation, stable code
  ordering, and reason truncation are each test-covered.

No Task 3 defects were found.

## Concern

Task 4 owns the additional caps for unknown extension-name length and total
serialized report size. This task limits reason count as required, but does not
preemptively change Task 4's remaining bounded-serialization scope.
