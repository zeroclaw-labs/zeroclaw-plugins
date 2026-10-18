# sol-token-balances

A read-only [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **WIT tool
plugin**. It implements the `tool-plugin` world from `wit/v0` and compiles to a
`wasm32-wasip2` component.

## What it does

Exposes one tool, **`sol_token_balances`**, that lists the SPL Token balances
held by a Solana account. It calls the Solana JSON-RPC
[`getTokenAccountsByOwner`](https://solana.com/docs/rpc/http/gettokenaccountsbyowner)
method (scoped to the SPL Token program, `jsonParsed` encoding) over
`wasi:http`, drops zero balances, and returns each holding as its mint, ui
amount, decimals, and exact raw amount. When `include_usd` is set it enriches
each token with a USD price from Jupiter's key-free price API and adds a
portfolio total. Read-only: it holds no keys, signs nothing, and moves no funds.

### Input

```json
{ "address": "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9", "include_usd": true }
```

- `address` — the owner account's base58 public key. Validated to decode to 32
  bytes before any network call.
- `include_usd` *(optional, default `false`)* — attach USD prices/values.

### Output

The tool's `output` is a compact JSON string:

```json
{
  "address": "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9",
  "rpc_url": "https://api.mainnet-beta.solana.com",
  "token_count": 2,
  "usd_enabled": true,
  "total_usd": 42.5,
  "priced_token_count": 1,
  "tokens": [
    {
      "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      "account": "4i9hvJfB2StTgnb5ekEW44tH66FfTb4SKf8QUEfVWWvS",
      "amount": 42.5,
      "decimals": 6,
      "raw": "42500000",
      "usd_price": 1.0,
      "usd_value": 42.5
    }
  ]
}
```

`raw` is exact; `amount` is the human-readable `raw / 10^decimals`. Without
`include_usd`, the `usd_*` fields are omitted. USD enrichment is best-effort: a
Jupiter failure never sinks the balance lookup, and mints Jupiter can't price
simply get no `usd_price`/`usd_value`.

Bad input and RPC errors come back as a `ToolResult` with `success: false` and
an `error` message — a normal tool response the model can react to.

## Config keys

Injected under `__config` only when the manifest declares `config_read`.

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | JSON-RPC endpoint to query. |
| `jupiter_base_url` | `https://lite-api.jup.ag` | Base URL for Jupiter's price API (`{base}/price/v3`). The free `lite-api` host needs no API key. |

Set per plugin name, e.g. `zeroclaw config set sol-token-balances.rpc_url <url>`.

## Permissions

- `http_client` — POSTs to the RPC endpoint and (for USD) GETs Jupiter over
  `wasi:http`.
- `config_read` — lets the host inject the `rpc_url` / `jupiter_base_url`
  overrides.

## Build and test

```bash
cargo test                                          # host tests (incl. live RPC + Jupiter smoke)
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2        # the component
cp target/wasm32-wasip2/release/sol_token_balances.wasm sol_token_balances.wasm
wasm-tools validate --features all sol_token_balances.wasm
wasm-tools component wit sol_token_balances.wasm    # shows the exported tool interface
```

Run `cargo test -- --nocapture` to print the live balances and prices. The live
tests soft-skip on transport/rate-limit errors so offline builds still pass.
