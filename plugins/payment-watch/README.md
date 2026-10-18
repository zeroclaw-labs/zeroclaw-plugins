# payment-watch

ZeroClaw WIT plugin: **T0 (read-only)** Solana payment watcher.

## What it does

Watches a Solana address for expected payments. Designed for SOP/cron triggers — run every 30 seconds until the payment confirms, then fire an inbound event.

Closes the payment loop started by `solana-pay-request`:

1. Agent generates `solana-pay-request` → QR in chat
2. Customer scans and pays
3. **`payment-watch` detects the incoming payment**
4. Agent confirms: "Invoice #42 paid — 25 USDC received"

## Custody Tier

**T0 — Read.** No secrets held. RPC URL only. Cannot sign or submit transactions.

## Config keys

| Key | Default | Meaning |
|-----|---------|---------|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Solana JSON-RPC endpoint |

## Threat model

Read-only. The agent can check balances and transaction status but cannot move any funds.

## Example SOP config

```toml
# Check every 30s if invoice-42 has been paid
[sops.check-payment]
trigger = "cron"
schedule = "*/30 * * * * *"
action = "tool"
tool = "payment-watch"
args = {
  address = "3XgJKe...",
  expected_amount = 25,
  expected_mint = "EPjFWdd5...",
  reference = "invoice-42"
}
```

When the payment is detected, the SOP fires an inbound event that triggers a confirmation message.

## Build and test

```bash
cargo test
cargo build --target wasm32-wasip2 --release
```