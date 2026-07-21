# portfolio-brief

A ZeroClaw **WIT tool plugin** that turns a wallet address into a compact,
model-sized brief of its holdings: native SOL and every SPL / Token-2022 token
balance, each valued in USD with a 24h price delta, sorted by value, with dust
summarized rather than listed. Built to feed a daily-briefing SOP without
nuking the agent's context window.

Implements the `tool-plugin` world from `wit/v0`, compiles to a
`wasm32-wasip2` component, and is built on the shared
[`solana-core`](../../crates/solana-core) substrate (Track E).

## What it does

Given an `owner` address, over read-only calls:

1. `getTokenAccountsByOwner` for the SPL Token **and** Token-2022 programs →
   decodes each balance with `solana-core`'s token-account decoder.
2. `getBalance` → native SOL.
3. `getMultipleAccounts` → each mint's decimals (so amounts are exact even for
   tokens a price source doesn't cover).
4. A price API (Jupiter by default) → USD price + 24h change per mint.

It then aggregates, values, sorts by USD descending, keeps the top holdings, and
summarizes the rest. This is the concrete answer to bounty trap #3: dozens of
raw account blobs become ~200 tokens of text.

## Custody tier: **T0 (read-only)**

The tool holds no key and signs nothing. Capabilities:

- `http_client` — read-only JSON-RPC to the configured Solana endpoint and a
  read-only `GET` to the price API (TLS host-side).
- `config_read` — to read its own `rpc_url` / `price_api_url` settings.

No code path builds, signs, or submits a transaction.

## Threat model

| Vector | Mitigation |
|---|---|
| Prompt-injected model passes a hostile string as `owner` | `owner` is strictly validated as a 32-byte base58 address before any I/O; anything else returns an error and touches nothing. |
| Price API returns junk / is down | Prices are best-effort: a failure downgrades holdings to "unpriced" (counted, not shown wrong); balances still render. |
| Unbounded output floods the context window | Output is capped (top-N holdings, dust summarized, `>100`-mint wallets truncated with a note). |
| Malformed on-chain data | Bounds-checked, panic-free decoding; undecodable mints are counted as unpriced, never displayed with wrong decimals. |
| Operator RPC key leaks via args | Endpoints come from operator `config`, never from model args, and are never echoed. |

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Solana JSON-RPC endpoint. **Set your own** — the public one is rate-limited (trap #5). |
| `price_api_url` | `https://lite-api.jup.ag/price/v3` | Price source returning `{ mint: { usdPrice, priceChange24h } }`. |

## Worked example

```
execute({"owner": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"})

Portfolio for 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU — total ~$1,234.56
- SOL: 12.5 · $977.13 [+2.3% 24h]
- USDC: 250 · $250.00 [-0.0% 24h]
- BONK: 1,200,000 · $7.43 [+5.1% 24h]
(+ 3 smaller priced holdings worth $12.20; 8 unpriced tokens)
```

## Build and test

```bash
cargo test                                     # host tests over the pure core
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release   # the component
cp target/wasm32-wasip2/release/portfolio_brief.wasm portfolio_brief.wasm
```

## Layout (the reference format)

```
src/brief.rs     # pure aggregation/shaping logic, no wasm deps — host-testable
src/lib.rs       # thin #[cfg(target_family = "wasm")] component shim (RPC/HTTP I/O)
tests/           # host-run integration tests
manifest.toml    # name, version, wasm_path, capabilities, permissions
```

## License

MIT.
