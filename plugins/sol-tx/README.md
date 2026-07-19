# sol-tx

A read-only [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **WIT tool
plugin**. It implements the `tool-plugin` world from `wit/v0` and compiles to a
`wasm32-wasip2` component.

## What it does

Exposes one tool, **`sol_tx`**, that looks up a Solana transaction by its
base58 signature via the JSON-RPC
[`getTransaction`](https://solana.com/docs/rpc/http/gettransaction) method over
`wasi:http`. It returns whether the transaction succeeded or failed (with the
on-chain error if any), the slot and block time, the fee paid in lamports and
SOL, the transaction version, and the account keys involved — summarized for an
LLM. Requests use `jsonParsed` encoding with `maxSupportedTransactionVersion: 0`
so versioned (v0) transactions are returned rather than erroring.

**Read-only.** This tool holds no keys, signs nothing, and moves no funds; it
only reads confirmed on-chain history.

A signature that is valid base58 (64 bytes) but not found — or not yet finalized
on the queried endpoint — comes back as `found: false`, a legitimate result
rather than an error.

### Input

```json
{
  "signature": "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
}
```

- `signature` — the transaction's base58-encoded signature, validated to decode
  to exactly 64 bytes.

### Output

The tool's `output` is a compact JSON string. A found transaction:

```json
{
  "signature": "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW",
  "found": true,
  "status": "success",
  "success": true,
  "err": null,
  "slot": 355210000,
  "block_time": 1752900000,
  "fee_lamports": 5000,
  "fee_sol": 0.000005,
  "version": 0,
  "account_count": 12,
  "account_keys": ["...", "..."],
  "rpc_url": "https://api.mainnet-beta.solana.com"
}
```

A valid-but-absent signature:

```json
{
  "signature": "...",
  "found": false,
  "message": "transaction not found or not yet finalized on this RPC endpoint",
  "rpc_url": "https://api.mainnet-beta.solana.com"
}
```

`version` is `0` for a v0 transaction and `"legacy"` for a legacy one. Bad input
and RPC errors come back as a `ToolResult` with `success: false` and an `error`
message — a normal tool response the model can react to.

## Config keys

Injected under `__config` only when the manifest declares `config_read`.

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | The Solana JSON-RPC endpoint the tool POSTs `getTransaction` to. Point it at a private/paid endpoint for higher rate limits. |

Set per plugin name, e.g. `zeroclaw config set sol-tx.rpc_url <url>`.

## Permissions

- `http_client` — POSTs to the Solana JSON-RPC endpoint over `wasi:http`.
- `config_read` — lets the host inject the `rpc_url` override.

## Build and test

```bash
cargo test                                          # host tests (incl. live getTransaction smoke)
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2        # the component
cp target/wasm32-wasip2/release/sol_tx.wasm sol_tx.wasm
wasm-tools validate --features all sol_tx.wasm
wasm-tools component wit sol_tx.wasm                # shows the exported tool interface
```

Run `cargo test -- --nocapture` to print a live transaction lookup. The live
test discovers a recent signature via `getSignaturesForAddress`, then looks it
up; it soft-skips on transport/rate-limit errors so offline builds still pass.
