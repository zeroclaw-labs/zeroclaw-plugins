# solana-wasm-core

Pure Rust helpers for dual-rail **PIX (BRL)** + **Solana Pay (USDC)** invoices on ZeroClaw.

- **No** `wit-bindgen`, **no** `solana-sdk` / `solana-client`, **no** WASM-only deps  
- Host-testable with plain `cargo test`  
- Imported by `plugins/brl-usdc-invoice` and `plugins/invoice-status`

## Modules

| Module | Purpose |
|---|---|
| `amount` | Decimal parse / format / caps (BRL 2 dp, USDC ≤6 dp), and the exact minor-unit comparison (`compare_units_to_decimal`, `format_minor_units`) the settlement check runs on — `u128` throughout, no floating point |
| `pix` | Static PIX Copia e Cola EMV + CRC16-CCITT; CPF/CNPJ sanitize |
| `solana_pay` | Transfer-request URL per [Solana Pay spec](https://docs.solanapay.com/spec) |
| `reference` | Deterministic `bs58(sha256("zc-inv-v1"‖id‖merchant))` |
| `rpc` | `HttpTransport` + JSON-RPC `getSignaturesForAddress` / `getTransaction` (exact token-balance deltas from `uiTokenAmount.amount`) |
| `invoice` | `build_invoice` with caps, allowlist, `recipient_locked`; auto ids salted with the caller-supplied issuance instant |
| `status` | Short PAID/PENDING text + Solscan link; exact PAID/UNDERPAID/OVERPAID verdict with no tolerance band |
| `shape` | Truncate, accents, PIX key sanitize |

## Example

```rust
use solana_wasm_core::invoice::{build_invoice, InvoiceConfig, InvoiceRequest};
use std::collections::HashMap;

let cfg = InvoiceConfig::from_map(&HashMap::from([
    ("pix_key".into(), "merchant@example.com".into()),
    ("pix_name".into(), "Loja Demo".into()),
    ("pix_city".into(), "Sao Paulo".into()),
    ("merchant_solana".into(), "11111111111111111111111111111112".into()),
    ("max_amount_brl".into(), "1000".into()),
    ("max_amount_usdc".into(), "200".into()),
    ("recipient_locked".into(), "true".into()),
]));

let mut req = InvoiceRequest::new("150.00", "inv-001");
req.description = Some("Pedido".into());
// The core reads no clock: the issuance instant (unix ms) is a parameter the
// plugin shim supplies. It only salts an *auto-generated* invoice id, so two
// identical charges never share a payment reference; an explicit id like
// "inv-001" is used verbatim and is unaffected by it.
let issued_at_unix_ms = 1_700_000_000_000;
let result = build_invoice(&req, &cfg, issued_at_unix_ms).unwrap();
assert!(result.pix_payload.starts_with("000201"));
assert!(result.solana_pay_url.starts_with("solana:"));
```

## What fought us on wasm32-wasip2

Documented for the Superteam / ZeroClaw bounty judges:

1. **`solana-sdk` / `solana-client` are not friends** of `wasm32-wasip2` + WIT components. This crate hand-rolls Solana Pay URLs and JSON-RPC shapes; it never links the official Solana crates.
2. **HTTP only via host `wasi:http`**. Core exposes `HttpTransport`; the `invoice-status` plugin implements it with **`waki`** (blocking), gated to `cfg(target_family = "wasm")` so host tests never compile waki.
3. **No sockets / websockets** — registry rejects those permissions today; stay on HTTP.
4. **Blockhash expiry** is avoided in v1: we emit **Solana Pay transfer URLs**, not pre-built versioned transactions sitting in a Telegram queue.
5. **Tool is stateless** (fresh store per `execute`). Deterministic `reference` from `invoice_id + merchant` replaces plugin-local storage — which is exactly why the id has to be unique per sale, and why an auto-generated id is salted with the issuance instant the shim passes in.
6. **No floating point on the money path.** `getTransaction` deltas come from the integer `uiTokenAmount.amount` plus `decimals`, and the PAID/UNDERPAID/OVERPAID verdict is an exact `u128` comparison with no tolerance band. Issuance was already exact integer arithmetic; verification now matches it.
7. **Dual wit-bindgen versions** coexist when plugins also depend on waki (0.34) beside world bindings (0.46) — host links both; no action required in core.
8. **Context budget**: status/invoice formatters return short PT-BR blocks, not raw RPC dumps.

## Packaging note

Plugins path-depend on this crate:

```toml
solana-wasm-core = { path = "../../crates/solana-wasm-core" }
```

Upstream registry zips are per-plugin; include this crate in the monorepo PR so CI can build from source.

## License

MIT
