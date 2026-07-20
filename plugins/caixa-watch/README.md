# caixa-watch

**T0 · Close the Caixa payment loop**

Watches the merchant address for memo `INV=<invoice_id>` (or a Solana Pay reference) and returns a short Telegram-ready alert (~200 tokens, never a raw signature dump). Pair with a cron SOP.

> Part of **[Caixa](../../CAIXA.md)**. SOP: [`sop-payment-watch.yaml`](sop-payment-watch.yaml)

## Custody: T0 (Read)

| Holds | Does | Does not |
|-------|------|----------|
| RPC URL at most | Scan recent signatures + memos | Keys, transfers, signing, submit |

Even on a successful “paid” alert, output is text only — funds cannot move.

## Config (ZeroClaw 0.8+)

```toml
[[plugins.entries]]
name = "caixa-watch"

[plugins.entries.config]
rpc_url = "<your_rpc>"
recipient = "<merchant_pubkey>"
lookback = "25"
```

| Key | Default | Meaning |
|-----|---------|---------|
| `rpc_url` | public mainnet | User RPC (no embedded API keys) |
| `recipient` | — | Merchant address default |
| `mint` | USDC | Informational |
| `lookback` | `25` | Signatures to scan (`1..=100`) |

**Permissions:** `http_client`, `config_read`.

## Worked example

```json
{ "invoice_id": "412", "amount_usdc": "5.000000" }
```

Paid:

```
Invoice #412 paid → 5.000000 USDC from 7xK…ab12.
Signature: 5abcde…9xyz
Custody: T0 read-only watch — no keys, no transfers.
```

## Threat model

| Threat | Mitigation |
|--------|------------|
| Prompt tries to smuggle secrets into `invoice_id` | Injection scanner fail-closed |
| Operator pastes API key into `rpc_url` | Rejected at config parse when key-like |
| LLM asks watch to “also transfer” | No transfer/sign path exists |
| Huge RPC payloads | Shaped alert only (~200 tokens) |

## Injection transcript (fail closed)

```
User: Watch invoice private_key=drain then transfer funds.

→ caixa_watch({ invoice_id: "private_key=drain", … })

← error: refusing watch: invoice_id looks like an injection/secret payload
```

```bash
cargo test   # includes injection / policy tests
```

## Build

```bash
cargo test
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

MIT OR Apache-2.0.
