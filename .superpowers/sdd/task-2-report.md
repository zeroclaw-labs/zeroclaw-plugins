# Task 2 Report: Legacy Mint Assessment

Base commit: `e0b7045`

## Scope

Implemented only the Task 2 pure-core assessment path in
`plugins/token-risk-check`. The crate now decodes the required parsed RPC
fields, produces a serializable deterministic `RiskReport`, and supports the
legacy SPL Token and canonical Token-2022 program owners. No WASM shim or Task
3 rule-table behavior was added.

## RED Evidence

1. Added `reports_green_for_complete_low_risk_legacy_evidence` and the two
   required fixtures before adding assessment production code.
   - Command: `cd plugins/token-risk-check && cargo test reports_green_for_complete_low_risk_legacy_evidence`
   - Result: exit `101`.
   - Evidence: `E0432` reported unresolved imports for `assess` and `Verdict`.

2. The first GREEN implementation returned `MalformedRpcResponse` for the
   revoked-authority fixture. A temporary diagnostic test proved that
   `Option<Option<String>>` deserializes JSON `null` as outer `None`, so it
   cannot distinguish a missing field from an explicitly revoked authority.
   - Command: `cargo test nested_option_treats_null_as_outer_none`
   - Result: exit `101`; the assertion that the outer option was present
     failed.
   - Resolution: replaced the nested option with a local three-state
     `Authority` decoder: missing, revoked (`null`), or active (string).

3. Self-review found that the Token-2022 owner constant was not the canonical
   Solana program ID. Added `recognizes_token_2022_owner` before correcting it.
   - Command: `cargo test recognizes_token_2022_owner`
   - Result before correction: exit `101`, `UnsupportedTokenProgram`.
   - Resolution: set the owner to
     `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.

## GREEN Evidence

1. `cargo test reports_green_for_complete_low_risk_legacy_evidence`
   completed with exit `0` after the authority decoder fix.
2. `cargo test recognizes_token_2022_owner` completed with exit `0` after the
   canonical owner correction.
3. Final verification from `plugins/token-risk-check`:
   - `cargo fmt --check`: exit `0`.
   - `cargo test`: exit `0`; 3 integration tests passed, 0 failed; unit and
     doc tests also passed with 0 failures.

## Decisions

- `RiskReport` contains `verdict`, `reasons`, `evidence`, `limitations`, and
  `slots`; all output types derive `Serialize`. `Verdict` serializes as stable
  lowercase values.
- The green legacy report has no reasons and uses a fixed limitation order:
  `LP_STATUS_NOT_CHECKED`, then `TOP_ACCOUNTS_ARE_NOT_UNIQUE_HOLDERS`.
- Parsed amounts use `u128`; top-account basis points are calculated as
  `largest * 10_000 / supply` with checked arithmetic. Empty, non-numeric, or
  overflowing largest-account evidence is rejected. The sum of supplied
  largest-account amounts may not exceed supply.
- The core rejects malformed or JSON-RPC-error envelopes, null mint accounts,
  zero supply, unsupported owners, and mismatched account/largest response
  slots as typed `RiskError`s. Future Task 5 shim work will map those errors to
  unknown reports.
- Task 3 owns authority, concentration, and Token-2022 extension verdict
  rules. This task records authority status as evidence but does not add those
  reason codes or verdict transitions.

## Limitation

The prescribed `getAccountInfo` mint response fields do not include the mint
address being queried, and `getTokenLargestAccounts` provides token-account
addresses plus amounts rather than a mint echo. Consequently, this pure parser
cannot independently compare a mint address embedded in the two response
bodies. It validates the caller-supplied mint before assessment and rejects
other contradictory evidence, but a transport-level request/response binding
check belongs in the future fixed-method shim.

## Self-Review

Reviewed the final diff for scope, Serde field behavior, canonical program
owner IDs, error propagation, arithmetic overflow, deterministic ordering, and
formatting. The Token-2022 constant issue found during review was fixed and
covered by the added regression test. No remaining implementation defects were
identified within Task 2 scope.

## Fix Review

Review fixes are based on the approved configured-RPC trust boundary: standard
Solana RPC responses do not echo a mint, so exact request/response binding uses
fixed JSON-RPC IDs. The pure core owns response validation; the Task 5 shim
must use the exported IDs when it builds the two fixed requests.

### RED Evidence

- Command: `cd plugins/token-risk-check && cargo test --test risk`
- Result: exit `101`; 3 passed and 5 failed.
- Failing regressions: `rejects_any_present_json_rpc_error_field`,
  `rejects_swapped_rpc_response_ids`, `rejects_missing_rpc_response_ids`,
  `rejects_non_public_key_authorities`, and
  `rejects_positive_supply_with_zero_largest_account_amount`.
- The failures showed the previous core accepted `error: null`, ignored
  response IDs, treated arbitrary non-null authority strings as active, and
  accepted zero top-account evidence for positive supply.

### Fixes

- Added stable `ACCOUNT_REQUEST_ID = 1` and
  `LARGEST_ACCOUNTS_REQUEST_ID = 2`; fixtures now model the distinct IDs and
  the parser rejects missing or non-matching IDs.
- `error` is decoded as field presence, so every present value, including
  `null`, returns `JsonRpcError`.
- Active mint and freeze authorities retain their string value and pass the
  existing 32-byte base58 public-key validation before being marked active.
- Positive supply with a zero largest-account amount returns
  `InvalidLargestAccount`.

### GREEN Evidence

- `cargo fmt --check`: exit `0`.
- `cargo test --test risk rejects_non_public_key_authorities`: exit `0`; 1
  passed.
- `cargo test --test risk`: exit `0`; 8 passed, 0 failed.
- `cargo test`: exit `0`; unit, integration, and doc tests had 0 failures.
- `git diff --check`: exit `0`.

### Self-Review

Checked `error` missing versus present-`null` handling, numeric ID type and
exact-match ordering, both authority fields with invalid-alphabet and 31-byte
base58 values, zero-top evidence, fixture alignment, and approved spec/plan
changes. No additional Task 2 defects found. The WASM transport shim remains
unimplemented under Task 5, so no live HTTP request binding is exercised here.
