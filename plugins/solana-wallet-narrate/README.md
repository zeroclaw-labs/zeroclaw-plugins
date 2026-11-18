# solana-wallet-narrate

ZeroClaw WIT plugin. Converts raw Solana transaction history into plain English.

## Custody tier: T0 - Read only

No keys. No signing. Read-only RPC calls only.

## What it does

- SOL transfers: "Sent 1.0000 SOL to 9zLpQ..."
- Token transfers: "Received 25.0 tokens from 7xKmN..."
- Everything else: "Complex transaction (swap or contract call)"

## Config

| Key | Default |
|-----|---------|
| rpc_url | https://api.mainnet-beta.solana.com |

## Build

```bash
cargo test
cargo build --target wasm32-wasip2 --release
```
