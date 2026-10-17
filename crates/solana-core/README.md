# solana-core

The shared, `wasm32-wasip2`-friendly Solana substrate that ZeroClaw Solana tool
plugins are built on. This is the **Track E** core: a clean, MIT-licensed crate
that the plugin tracks *actually import*, so each plugin is a thin shim over it
instead of a copy-paste of hand-rolled byte math.

## Why this exists

`solana-sdk` and `solana-client` do not compile cleanly for `wasm32-wasip2`
inside a WIT component (bounty trap #2). So this crate hand-rolls the small
subset a read-only agent tool actually needs, over `bs58`, `base64`, and
`serde_json` only — all of which build for both the host and the component.

Nothing here is a wasm component itself; it is an `rlib` that the plugin crates
(the `cdylib` components) pull in with a path dependency:

```toml
[dependencies]
solana-core = { path = "../../crates/solana-core" }
```

## What's in it

| Module | Responsibility |
|---|---|
| `base58` | Address encode/decode over `bs58`, with strict 32-byte validation. |
| `rpc` | JSON-RPC request construction + response-envelope parsing (`result`/`error`, `{context,value}`, base64 account data). Pure — the HTTP round-trip stays in each plugin's `waki` shim. |
| `mint` | SPL Token / Token-2022 **mint** decoding: the 82-byte base layout plus a TLV walker for the risk-relevant Token-2022 extensions (permanent delegate, transfer hook, transfer fee, default-frozen, mint-close, non-transferable). |
| `token_account` | SPL / Token-2022 **token account** (balance) decoding. |
| `shape` | Output shaping — UI amounts, grouped/trimmed number formatting, percentages, address abbreviation, hard length caps (bounty trap #3). |

## Design rules

- **Panic-free decoding.** Every decoder is bounds-checked; malformed on-chain
  data returns `Err`, never a trap. A plugin depends on this to *fail closed*
  rather than crash the agent loop.
- **Pure, host-testable.** No wasm or host dependency, so the exact code the
  component runs is covered by `cargo test` on the host.
- **No I/O.** The crate builds requests and parses responses; plugins own the
  `wasi:http` call. That keeps the wire format testable with fixtures and no
  network.

## Validation

The mint and extension decoders are verified against **live mainnet** account
data (USDC, BONK, PYUSD): the 82-byte base layout, the 165-byte account padding,
the TLV walk, and the exact `TransferFeeConfig` (108 bytes) and `TransferHook`
(64 bytes) extension sizes all match reality. See `../../SUBMISSION.md`.

## Test

```bash
cargo test            # 35 host tests, no wasm toolchain needed
```

## License

MIT.
