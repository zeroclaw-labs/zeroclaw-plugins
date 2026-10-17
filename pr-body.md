## Summary

Adds three read-only Solana analysis plugins:

- `wallet-narrate`: bounded, redacted activity summaries with success/failure handling.
- `stake-monitor`: delegation and activation health reporting.
- `token-risk-check`: deterministic mint-authority, freeze-authority, holder-concentration, liquidity, and metadata risk flags.

All plugins use the vendored ZeroClaw WIT contract, standalone Cargo workspaces, pure Rust cores, thin WASM shims, bounded inputs, and no custody/signing/transfer capability.

## Validation

- Standalone host tests pass for all three plugins.
- `wasm32-wasip2` release builds pass for all three plugins.
- Registry metadata check passes; `token-risk-check` is marked `registry = false` because live HTTP imports are host-gated.

## Safety

No private keys, signing, transfers, swaps, or arbitrary RPC methods are accepted. Signatures are redacted and provider data is bounded.

## Notes

Telegram live results and injection-refusal evidence were captured locally. The two registry-ready plugins are pending the generated registry/publish workflow.
