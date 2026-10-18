# jupiter-quote

A read-only [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **WIT tool
plugin**. It implements the `tool-plugin` world from `wit/v0` and compiles to a
`wasm32-wasip2` component.

## What it does

Exposes one tool, **`jupiter_quote`**, that fetches a swap quote from
[Jupiter](https://jup.ag), Solana's DEX aggregator, via its
[Quote API](https://dev.jup.ag/docs/swap-api/get-quote)
(`{base}/swap/v1/quote`) over `wasi:http`. Given an input mint, output mint, and
input amount in base units, it returns the expected output amount, price impact,
minimum output after slippage, and the DEX route/hops — summarized for an LLM.

**Quote only.** This tool never builds, signs, or sends a swap transaction. It
holds no keys and moves no funds; it only reads a price route.

It uses Jupiter's key-free public host `lite-api.jup.ag` by default (verified
current 2026-07; rate limited to ~30 req/min). The older `quote-api.jup.ag/v6`
host is superseded and `api.jup.ag` now requires an `x-api-key`.

### Input

```json
{
  "input_mint": "So11111111111111111111111111111111111111112",
  "output_mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "amount": "100000000",
  "slippage_bps": 50
}
```

- `input_mint` / `output_mint` — base58 mints, validated to decode to 32 bytes.
- `amount` — the input amount in the token's **base units** (integer, no decimal
  point). E.g. 1 SOL = `1000000000`, 1 USDC = `1000000`. Accepts a string or an
  integer.
- `slippage_bps` *(optional)* — slippage tolerance in basis points (100 = 1%).
  If omitted, Jupiter's default is used.

### Output

The tool's `output` is a compact JSON string:

```json
{
  "input_mint": "So11111111111111111111111111111111111111112",
  "output_mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "in_amount": "100000000",
  "out_amount": "7624348",
  "other_amount_threshold": "7586227",
  "price_impact_pct": 0.0,
  "slippage_bps": 50,
  "swap_mode": "ExactIn",
  "swap_usd_value": "7.62308068150690",
  "hops": 1,
  "route": [
    { "label": "Meteora", "input_mint": "So111...", "output_mint": "EPjF...", "percent": 100 }
  ],
  "route_summary": "Meteora (100%)"
}
```

All amounts stay as exact base-unit strings (`out_amount` for USDC has 6
decimals). `price_impact_pct` is a percentage (`0.12` == 0.12%).

Bad input and API errors (including `NO_ROUTES_FOUND`) come back as a
`ToolResult` with `success: false` and an `error` message — a normal tool
response the model can react to.

## Config keys

Injected under `__config` only when the manifest declares `config_read`.

| Key | Default | Meaning |
|---|---|---|
| `jupiter_base_url` | `https://lite-api.jup.ag` | Base URL for Jupiter's swap host (`{base}/swap/v1/quote`). Point at `https://api.jup.ag` with an API key if you outgrow the free tier. |

Set per plugin name, e.g. `zeroclaw config set jupiter-quote.jupiter_base_url <url>`.

## Permissions

- `http_client` — GETs the Jupiter Quote API over `wasi:http`.
- `config_read` — lets the host inject the `jupiter_base_url` override.

## Build and test

```bash
cargo test                                          # host tests (incl. live Jupiter quote smoke)
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2        # the component
cp target/wasm32-wasip2/release/jupiter_quote.wasm jupiter_quote.wasm
wasm-tools validate --features all jupiter_quote.wasm
wasm-tools component wit jupiter_quote.wasm         # shows the exported tool interface
```

Run `cargo test -- --nocapture` to print the live quote. The live test
soft-skips on transport/rate-limit errors so offline builds still pass.
