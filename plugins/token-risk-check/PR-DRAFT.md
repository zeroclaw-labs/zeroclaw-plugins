# PR: Add `token-risk-check` read-only Solana tool plugin

## Summary

Adds one T0, read-only `tool-plugin` for concise Solana mint risk checks. It reports a red/amber/green verdict and reasons covering mint/freeze authorities, holder concentration, LP/locker status, and Token-2022 transfer hooks, transfer fees, and permanent delegates.

It naturally complements the `sns-resolve` PR (#55): `.sol domain → resolved address → risk check`.

## Safety and custody

This is custody tier T0. The manifest requests only `http_client` and `config_read`; it contains no signer, wallet, transaction, filesystem-write, socket, or transfer code. API keys are read only from injected config. Missing or ambiguous data is fail-closed.

Well-known tokens with live mint or freeze authority, including USDC when reported that way by the provider, intentionally produce RED. This is fail-closed behavior, not a bug: the plugin does not trust off-chain reputation or maintain a token allowlist.

See `README.md` for the full threat model and a prompt-injection test transcript.

## Structure and tests

- `src/risk.rs`: pure Rust scoring/formatting core.
- `src/lib.rs`: thin wasm-only WIT/waki/logging shim.
- `tests/risk.rs`: host fixtures, including output bound and malformed provider-shape regressions.
- `cargo test --locked` (8/8 passing)
- `cargo build --locked --target wasm32-wasip2 --release`

The plugin follows the repository's documented `plugins/redact-text` layout. Before merge, run the repository validation described in the root README:

```bash
python3 -m unittest discover -s tools/tests -p 'test_*.py'
python3 tools/build-registry.py --source-plugins plugins --check-metadata registry.json
```
