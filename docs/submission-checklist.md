# Submission readiness checklist

## Code and packaging

- [x] Standalone Cargo package for each plugin.
- [x] Pure Rust core plus thin WIT WASM shim.
- [x] Host fixture tests under `tests/`.
- [x] `wasm32-wasip2` release builds pass.
- [x] Bounded input and redacted output paths.
- [x] Structured lifecycle logging in WASM shims.
- [x] No signing, transfers, swaps, or private-key handling.
- [x] `token-risk-check` marked `registry = false` while stock host HTTP is unavailable.

## Validation

- [x] Standalone host tests pass on Windows.
- [x] Registry metadata check passes.
- [ ] Linux CI validation passes (required for symlink/named-pipe fixture tests).
- [ ] Upstream maintainer review completed.
- [ ] Upstream CI checks reported green.

## Evidence package

- [x] Portfolio live Telegram result captured.
- [x] Token-risk approval and result captured.
- [x] Wallet narration result captured.
- [x] Stake-monitor result captured.
- [x] Injection refusal captured.
- [ ] Degraded-provider result captured after removing an optional provider.
- [ ] Under-three-minute demo transcript finalized.
- [ ] Screenshots redacted for keys, tokens, and private data.

## Release hygiene

- [ ] Revoke all credentials exposed during development.
- [ ] Confirm no secrets appear in git history, logs, screenshots, or PR text.
- [ ] Resolve or explicitly document the stock-host HTTP capability limitation.
- [ ] Submit the final bounty evidence package after PR review.
