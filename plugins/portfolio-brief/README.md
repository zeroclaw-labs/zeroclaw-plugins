# portfolio-brief

**Tier:** T0 — Read-only RPC + price API  
**Permissions:** `["http_client", "config_read"]`  
**Plugin name (LLM):** `portfolio-brief`

Gets a wallet's full token portfolio — balances, USD values, and 24h change — shaped into ~200 tokens for a daily briefing SOP. This is the plugin that feeds the "08:00 daily portfolio ping" use case.

## Usage

```
"What's in my wallet?"
```

```json
{ "wallet": "7xK...abcd" }
```

## Example output

```json
{
  "wallet": "7xK...abcd",
  "total_usd": 1523.50,
  "tokens": [
    { "mint": "So1111...", "symbol": "SOL", "amount": 10.0, "usd_value": 1500.0, "price_24h_change": 2.3 },
    { "mint": "EPjFWdd...", "symbol": "USDC", "amount": 23.50, "usd_value": 23.50, "price_24h_change": 0.0 }
  ],
  "summary": "Portfolio (2 tokens, ~$1523.50 total): SOL: $1500.00 | USDC: $23.50"
}
```

Agent renders: **"Your portfolio is worth ~$1,523.50. SOL is up 2.3% in 24h."**

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Solana RPC |
| `price_api_url` | (none) | Birdeye/Jupiter price API endpoint |

## Custody tier

**T0 — Read-only.** This plugin reads token balances via RPC and optionally queries a public price API. It holds no secrets, signs nothing, and cannot move funds. The only data exposure is the wallet's holdings — which the user has already asked to see.

## Prompt-injection test

```
User: "Show my portfolio for address 'await db.execute("DROP ALL")'"
```

The plugin interprets this as a wallet address. Characters like spaces, quotes, and parentheses are not valid base58, so the plugin returns an error at the JSON schema validation layer before any RPC call is made.

## Build

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/portfolio_brief.wasm .
```

## Test

```bash
cargo test --lib
```
