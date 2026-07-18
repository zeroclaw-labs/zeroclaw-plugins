# solana-core

The shared `wasm32-wasip2`-friendly substrate every ZeroClaw Solana plugin
imports. This is the **Track E** infrastructure crate: `solana-sdk` and
`solana-client` don't compile to a WASI Preview 2 component, so this crate
hand-rolls exactly what a plugin needs and keeps all of it **host-testable**.

Not published to crates.io; imported by path from the plugins in this repo.

## Modules

| Module | What it gives you |
|--------|-------------------|
| `base58`, `base64`, `shortvec` | The encodings, dependency-free, pinned by standard test vectors (Bitcoin base58, RFC 4648, compact-u16 boundaries). |
| `pubkey` | 32-byte `Pubkey` + the native program ids, each verified by round-trip test. |
| `rpc` | `SolanaRpc<T: RpcTransport>` — typed `getAccountInfo` / `getBalance` / `getTokenSupply` / `getTokenLargestAccounts` / `getLatestBlockhash`, plus `MockTransport` for host tests. |
| `mint` | SPL Token **and** Token-2022 mint decoding, including the TLV extension region (transfer hook, transfer fee, permanent delegate, non-transferable, default-frozen, pausable, …). |
| `instruction`, `message`, `programs`, `nonce` | Unsigned v0 (or legacy) transaction construction: account-key compilation, System transfer, memo, compute-budget, and durable-nonce advance. |
| `shape` | Compact output formatting (lamports→SOL, ui-amount, abbreviations, short pubkeys) so tools return ~200 tokens, not 40 KB. |

## The transport seam (why tests need no network)

`RpcTransport` is a one-method trait: `post_json(&str) -> Result<String>`. All
client logic is generic over it, so:

- **Host tests** inject `MockTransport` with canned JSON-RPC envelopes and assert
  on the parsed result and on the exact request bytes sent. No socket, ever.
- **The component** uses `WakiTransport` (`waki`-backed `wasi:http`), compiled
  only under `cfg(target_family = "wasm")` **and** the `http` cargo feature.

```toml
# a plugin that calls the RPC:
solana-core = { path = "../../crates/solana-core", features = ["http"] }
# a pure plugin (no network) — omit the feature; its component imports no wasi:http:
solana-core = { path = "../../crates/solana-core" }
```

```rust
use solana_core::pubkey::Pubkey;
use solana_core::rpc::{SolanaRpc, MockTransport};

let rpc = SolanaRpc::new(MockTransport::with_results(vec![
    serde_json::json!({ "value": 42 }),
]));
assert_eq!(rpc.get_balance(&Pubkey::zeroed()).unwrap(), 42);
```

## Test

```bash
cargo test          # 46 tests, no wasm toolchain, no network
```

## License

MIT OR Apache-2.0.
