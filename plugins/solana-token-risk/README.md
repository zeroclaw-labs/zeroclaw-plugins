# solana-token-risk

A ZeroClaw WIT tool plugin. Checks whether a Solana token mint is safe.

## Custody tier: T0 - Read only

No keys held. No transactions sent. Only outbound HTTPS to a configured RPC endpoint.

## What it checks

- Mint authority (open = can mint unlimited tokens)
- Freeze authority (present = accounts can be frozen)
- Token-2022: transfer hooks, permanent delegate, high transfer fees
- Holder concentration (top-3 % of supply)
- Metadata URI presence

## Config

| Key | Default | Notes |
|-----|---------|-------|
| rpc_url | https://api.mainnet-beta.solana.com | Any Solana JSON-RPC |
| das_url | https://api.mainnet-beta.solana.com | Helius recommended for DAS |

## Example

User: "Is EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v safe?"

Response:
```
GREEN - Token EPjF..Dt1v
- Mint authority revoked
- No concentration issues
```

## Threat model

The mint address is passed as a raw string directly to RPC calls.
No LLM interpretation occurs inside the plugin.
A malicious mint string cannot alter the verdict.
The verdict is derived purely from on-chain data.

See tests/core_test.rs prompt_injection_fails_closed for the automated test.

## Build

```bash
cargo test
cargo build --target wasm32-wasip2 --release
```
