# solana-core

Pure Rust Solana substrate for ZeroClaw wasm tool plugins. It has no WIT bindings, no `waki`, and no `solana-sdk` dependency.

The crate exists so Track C plugins can share Solana message, memo, nonce, key, RPC, and shaping code while keeping each plugin component small enough for `wasm32-wasip2`.

## Module Map

| Module | Responsibility |
| --- | --- |
| `error` | Shared `CoreError` and `CoreResult` types with short operator-facing messages. |
| `keys` | 32-byte public-key type plus base58 encode/decode through `bs58`. |
| `ix` | Solana instruction helpers for System Program durable nonce advance and SPL Memo. |
| `nonce` | Durable nonce account parsing and initialized nonce-state validation. |
| `rpc` | Minimal JSON-RPC wrapper over an injectable `HttpClient` trait. |
| `shape` | Output length checks and truncation helpers for chat-safe summaries. |
| `tx` | Legacy message/transaction encoding, compact-u16 encoding, and unsigned durable memo transaction assembly. |

Legacy Solana message encoding is implemented first because it keeps the wasip2 substrate simple and dependency-light. Versioned v0 messages can be added later if plugins need address lookup tables or newer transaction features.

## Wire-Format Confidence

`tx` includes a pinned golden `unsigned_tx_base64` fixture for a deterministic durable-nonce memo transaction. That test locks the hand-rolled legacy encoder's signature count, header bytes, account-key order, instruction program indices, instruction data bytes, and final base64 output without adding `solana-sdk` as a normal dependency.

This is a regression guard for this implementation, not an independent Solana SDK oracle. Before a public demo or production signing flow, verify a signed transaction from this encoder against an external oracle: sign the fixture-shaped transaction, submit it to a local validator or devnet, and confirm the transaction is accepted and the Memo instruction renders as expected in validator logs or an explorer.

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
