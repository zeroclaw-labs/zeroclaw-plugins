# solana-core

Thin Solana JSON-RPC toolkit for wasm32-wasip2 components.

## Why

`solana-sdk` and `solana-client` do not compile cleanly for wasm32-wasip2 inside a WIT component. This crate solves that with hand-rolled serde structs matching the Solana JSON-RPC wire format, using only:

- `waki` (blocking wasi:http) — for wasm
- `ureq` — for host-side `cargo test`
- `bs58` — lightweight base58
- `serde_json` — standard JSON

## Design: Pure Core / Thin Shim

Every function in this crate has zero wasm dependency. The `rpc.rs` module uses conditional compilation:

```rust
#[cfg(not(target_family = "wasm"))]
fn http_post(&self, body: &str) -> Result<String, String> { /* ureq */ }

#[cfg(target_family = "wasm")]
fn http_post(&self, body: &str) -> Result<String, String> { /* waki */ }
```

This means all logic is testable with a plain `cargo test` — no wasm toolchain needed.

## Modules

| Module | Description |
|--------|-------------|
| `rpc` | JSON-RPC client: getAccountInfo, getTokenSupply, getTokenLargestAccounts, getProgramAccounts |
| `types` | Solana wire types: MintAccount, TokenRiskReport, HolderConcentration, Token2022Extensions |
| `tx` | Transaction builder + Solana Pay URL generator |
| `nonce` | Durable nonce manager (blockhash expiry mitigation) |

## Response Shaping

Every RPC method shapes its output to ~200 tokens for LLM consumption. The `format_risk_report()` method returns a `ShapedOutput` with a concise summary string and optional structured JSON.

## Blockhash Expiry

The `durable-nonce` module mitigates the "blockhash expiry will bite you" trap from the ZeroClaw bounty. When a human approval gate delays transaction signing past blockhash expiry, a durable nonce account keeps the transaction valid.

## Usage

```rust
use solana_core::rpc::SolanaRpc;
use solana_core::types::RiskLevel;

let rpc = SolanaRpc::new("https://api.mainnet-beta.solana.com");

// Full token risk check
let report = rpc.token_risk_check("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")?;
println!("Risk: {} (score: {})", report.risk_level, report.score);

// Solana Pay URL
use solana_core::tx::build_solana_pay_url;
let url = build_solana_pay_url(
    "7EcDh...",
    25.0,
    Some("EPjFWdd5..."),
    Some("table-4"),
    None,
);
```

## License

MIT