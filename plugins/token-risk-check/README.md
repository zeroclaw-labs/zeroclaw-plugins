# token-risk-check

A ZeroClaw **WIT component** T0 (read-only) tool plugin that checks a Solana
token mint for risk factors. It implements the `tool-plugin` world from
`wit/v0` and compiles to a `wasm32-wasip2` component.

## What it does

A `token-risk-check` tool. Given a Solana mint/token address, it fetches
on-chain data and returns a **risk score (0–100)** with detailed reasoning:

| Risk factor | Weight | Description |
|---|---|---|
| Mint authority | 25 pts | Still active? Owner can mint unlimited new tokens. |
| Freeze authority | 15 pts | Still active? Owner can freeze any holder's account. |
| Holder concentration | 0–30 pts | Top 1 holder >50% (+20), >20% (+10). Top 10 >90% (+10). |
| LP status | 10 pts | Missing LP on Raydium/Orca → untradeable. |
| Risk level | — | **GREEN** (0–19), **AMBER** (20–49), **RED** (50+) |

## Config keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| *(none required)* | — | — | All parameters are provided at invocation time. |

## Custody tier: T0

This plugin is **read-only** — it never submits transactions, never signs
anything, and never alters on-chain state. It queries public RPC endpoints
and returns analysis. Safe to load in any environment.

## Threat model

- **Malicious mint authority**: A token whose mint authority is still active
  can have infinite supply minted at any time — classic rug-pull vector.
- **Freeze authority**: Allows the authority to freeze all holder accounts,
  effectively stealing liquidity.
- **Holder concentration**: If a small number of addresses control >90% of
  supply, a coordinated dump can crash the price.
- **No LP**: Without a verified liquidity pool on Raydium, Orca, or OpenBook,
  the token cannot be traded on major DEXes.
- **Token-2022 extensions**: Non-standard features (transfer hooks, transfer
  fees, permanent delegate) can introduce unexpected behavior.

## Worked example

```json
{
  "mint": "So11111111111111111111111111111111111111112"
}
```

Expected output (shaped to ~200 tokens):

```json
{
  "summary": "GREEN | Score: 0/100 | Supply: ... (9 decimals) | Mint authority REVOKED ✅; Freeze authority REVOKED ✅; Has verified LP (Raydium/Orca) ✅",
  "structured": {
    "mint": "So11111111111111111111111111111111111111112",
    "risk_level": "Green",
    "score": 0,
    "supply": 100000000000000,
    "decimals": 9,
    "reasons": [
      "Mint authority REVOKED ✅",
      "Freeze authority REVOKED ✅",
      "Has verified LP (Raydium/Orca) ✅"
    ],
    "concentration": null,
    "extensions": {
      "has_transfer_hook": false,
      "has_transfer_fee": false,
      "has_permanent_delegate": false,
      "has_non_transferable": false,
      "has_interest_bearing": false
    },
    "mint_authority": null,
    "freeze_authority": null
  }
}
```

## Layout

```
src/risk.rs      # pure logic, no wasm deps — host-testable with `cargo test`
src/lib.rs       # thin #[cfg(target_family = "wasm")] component shim
tests/           # host-run integration tests over the pure core
manifest.toml    # name, version, wasm_path, capabilities, permissions
```

## Build and test

```bash
cargo test                                        # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component
cp target/wasm32-wasip2/release/token_risk_check.wasm token_risk_check.wasm
```

## Install

```bash
zeroclaw plugin install token-risk-check
```

or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins:

```toml
[plugins]
enabled = true
```