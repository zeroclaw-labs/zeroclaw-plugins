# solana-token-safety

A ZeroClaw **WIT component** tool plugin that analyzes SPL token safety on Solana.
Implements the `tool-plugin` world from `wit/v0`, compiles to `wasm32-wasip2`, and
follows the `redact-text` reference layout.

## What it does

Given an SPL token mint address, the plugin queries the Solana JSON-RPC and returns
a safety report:

- **Mint authority**: is it renounced? (no new tokens can be minted)
- **Freeze authority**: is it renounced? (tokens can't be frozen)
- **Holder concentration**: what percentage do the top 10 holders control?
- **Safety score**: 0–100 with colour-coded summary (✅ SAFE / 🟡 CAUTION / 🔴 RISKY)

The agent receives a compact JSON report — not raw RPC responses — so the context
window stays small.

## Custody tier: **T0 (Read)**

This plugin performs read-only RPC calls. It holds **no secrets**, signs **nothing**,
and can't move funds. The only configurable secret is an optional `rpc` URL; if
omitted, it defaults to the Solana public mainnet endpoint.

| Tier | Description | Secrets held |
|------|-------------|-------------|
| T0   | RPC reads, price lookups, health checks | RPC key at most |

## Config keys

| Key | Default | Meaning |
|-----|---------|---------|
| `rpc` | `https://api.mainnet-beta.solana.com` | Solana JSON-RPC endpoint |

No other config keys. The operator can override the RPC URL per-invocation via the
`rpc` argument to `execute`.

## Layout (following redact-text)

```
src/solana_token_safety.rs   # pure Rust core — host-testable, no wasm deps
src/lib.rs                    # thin #[cfg(target_family = "wasm")] component shim
manifest.toml                 # plugin identity, capabilities, permissions
```

## Build and test

```bash
cargo test                                        # host tests (2 tests, 0 deps)
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component (~317 KB)
```

## Usage example

Invoke via Zeroclaw:

```
> solana-token-safety --mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v

{
  "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "decimals": 6,
  "supply": "1000000000000",
  "mint_authority": null,
  "mint_authority_renounced": true,
  "freeze_authority": null,
  "freeze_authority_renounced": true,
  "top_holder_concentration_pct": 45.2,
  "safety_score": 80,
  "warnings": ["🟡 Top holders control 45.2% of supply — moderately concentrated."],
  "summary": "🟡 CAUTION (score 80/100): Some risk factors present."
}
```

This example checks USDC — the mint and freeze authorities are renounced (true),
but top-holder concentration triggers a moderate warning.

## Threat model

| Threat | Mitigation |
|--------|-----------|
| RPC returns malicious data (spoofed token info) | Plugin is read-only; bad data can mislead the agent but can't sign or spend. Operator should use a trusted RPC endpoint. |
| Token metadata changes between calls | The report is a point-in-time snapshot. No caching — each call fetches fresh data. |
| Large responses bloat context | Output is shaped to < 2 KB regardless of RPC response size. |
| Prompt injection via mint address | The mint address is validated as a base58 string before any RPC call. Invalid addresses fail fast with a clear error. |

## Design decisions

- **waki over wasi:http**: The Zeroclaw host currently exposes `wasi:http` via waki
  (blocking HTTP), not the fully async WASI sockets. This plugin uses waki 0.5.
- **Pure-core / thin-shim split**: `solana_token_safety.rs` has zero WASM deps and
  uses an `HttpClient` trait. Host tests inject a `MockClient`. The `lib.rs` shim
  provides the real `WasmHttpClient` behind `#[cfg(target_family = "wasm")]`.
- **No `solana-sdk`**: The standard SDK doesn't compile for `wasm32-wasip2` inside
  a WIT component. Raw JSON-RPC via `serde_json` avoids the dependency entirely.
