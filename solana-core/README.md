# solana-core

Pure Rust Solana helpers for ZeroClaw wasm tool plugins. No WIT, no `waki`, no `solana-sdk`.

Shared by the DePIN plugins so each component stays small enough for `wasm32-wasip2`.

## Modules

| Module | Responsibility |
| --- | --- |
| `error` | `CoreError` / `CoreResult` |
| `keys` | 32-byte pubkeys, base58 |
| `ix` | System Program nonce advance + SPL Memo |
| `nonce` | Durable nonce account parse |
| `rpc` | JSON-RPC over an injectable `HttpClient` |
| `shape` | Chat-safe truncation / length budgets |
| `tx` | Legacy message encode, unsigned durable-memo tx assembly |

Legacy messages only for now (keeps the wasip2 build simple). A golden `unsigned_tx_base64` fixture locks the encoder output in tests; still verify a signed tx on a local validator or explorer before you rely on it in production.

## HttpClient Trait

`solana-core` does not own networking. Runtime-specific code implements the small `HttpClient` trait:

```rust
pub trait HttpClient {
    fn post_json(&self, url: &str, body: &serde_json::Value) -> CoreResult<serde_json::Value>;
}
```

This keeps host tests deterministic with mock clients and lets wasm plugin shims use `waki` only behind `cfg(target_family = "wasm")`.

Current RPC helpers:

- `get_account_data`
- `get_nonce`
- `get_signatures_for_address`
- `get_transaction_memo`

The DePIN attestation plugin uses `get_nonce`; the uptime watcher uses `get_signatures_for_address` and `get_transaction_memo`.

## Vendor and Sync

Canonical source lives at repo-root `solana-core/`. Plugin directories vendor a copy at:

- `plugins/depin-attest/src/vendor/solana_core/`
- `plugins/depin-uptime-watch/src/vendor/solana_core/`

Sync vendor trees after editing the canonical crate:

```bash
./tools/sync-solana-core.sh
```

The script copies `solana-core/src/` into each plugin vendor directory with `rsync --delete`. This lets each plugin build in isolation while still documenting one canonical source of truth.

## wasm32-wasip2 Notes

The substrate intentionally uses small crates that compile cleanly in the plugin builds:

- `bs58` for public keys
- `base64` for transaction and RPC account data encoding
- `sha2` for attestation hashes
- `serde` and `serde_json` for JSON-RPC payloads

`solana-sdk` and `solana-client` are deliberately avoided. WIT bindings and `waki` stay in plugin shims, not in `solana-core`.

## License

MIT. See the repository `LICENSE`.
