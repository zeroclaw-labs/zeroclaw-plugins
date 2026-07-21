# PR: Add `sns-resolve` read-only Solana Name Service tool plugin

## Summary

Adds one T0, read-only `tool-plugin` for resolving a top-level Solana Name Service `.sol` domain into a wallet address. It uses the official SNS SDK proxy over host-mediated HTTPS and returns a short domain/address response or a clear fail-closed error.

This component is intentionally complementary to `token-risk-check`: the agent workflow is `.sol domain → resolved wallet address → risk check`. Resolution prevents the agent from hallucinating an address; any later token/risk action remains a separate tool call.

## Safety and custody

This is custody tier T0. The manifest requests only `http_client` and `config_read`; it has no signer, wallet, transaction, transfer, filesystem-write, or socket code. It does not send funds and never treats a returned address as authorization for a payment.

See `README.md` for the full threat model and a prompt-injection test transcript.

Malformed names, unsupported subdomains, missing names, and unknown provider response shapes fail closed. API base URL override is config-only; no key or endpoint is hardcoded as a secret.

## Structure and tests

- `src/resolve.rs`: pure Rust domain normalization, provider-response parsing, and compact formatting core.
- `src/lib.rs`: thin wasm-only WIT/waki/logging shim.
- `tests/resolve.rs`: host-run mock fixtures for success, not found, malformed input, subdomain rejection, malformed provider data, and output length.
- `cargo test --locked` (6/6 passing)
- `cargo build --locked --target wasm32-wasip2 --release`
- `test-results-live.md`: read-only live SNS proxy results for `bonfida.sol`, `jupiter.sol`, and a non-existent domain.

The plugin follows the repository's documented `plugins/redact-text` layout. Before merge, run the root README validation commands:

```bash
python3 -m unittest discover -s tools/tests -p 'test_*.py'
python3 tools/build-registry.py --source-plugins plugins --check-metadata registry.json
```
