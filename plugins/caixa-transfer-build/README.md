# caixa-transfer-build

**T1 · Unsigned SPL USDC transfer with durable nonce**

Builds a base64 legacy transaction (ATA create-idempotent + invoice memo + transfer). A human or Squads signs. Solves bounty Trap #1: approval queues kill recent blockhashes — **durable nonce is required by default**.

> Part of **[Caixa](../../CAIXA.md)**.

## Custody: T1 (Build)

| Holds | Does | Does not |
|-------|------|----------|
| No keys | `tx_base64` + short approval summary | Sign, `sendTransaction`, store seed |

Best pattern: agent proposes → Squads / human phone-approves.

## Config (ZeroClaw 0.8+)

```toml
[[plugins.entries]]
name = "caixa-transfer-build"

[plugins.entries.config]
rpc_url = "<your_rpc>"
nonce_account = "<durable_nonce_account>"
require_nonce = "true"
max_usdc = "1000"
```

| Key | Default | Meaning |
|-----|---------|---------|
| `rpc_url` | public mainnet | User RPC — **no API keys in the URL** |
| `nonce_account` | — | Durable nonce account (**required** unless `require_nonce=false`) |
| `require_nonce` | `true` | Fail closed without nonce |
| `allowed_mints` | USDC | Mint allowlist |
| `max_usdc` | `1000` | Hard ceiling |

**Permissions:** `http_client`, `config_read`.

## Worked example

```json
{
  "source_owner": "<merchant>",
  "destination": "<payee>",
  "amount_usdc": "25.00",
  "invoice_id": "412",
  "amount_brl": "125.00",
  "create_dest_ata": true
}
```

Summary includes `Durable nonce: yes` when configured. Output is shaped (~200 tokens) — never a raw RPC dump.

## Threat model

| Threat | Mitigation |
|--------|------------|
| LLM tries to sign/submit | No signing path |
| Wrong mint / drain size | Allowlist + `max_usdc` |
| API key in `rpc_url` | Rejected at config parse |
| Secret in memo | Injection scanner fail-closed |
| Stale blockhash after human lunch | Durable nonce required by default |

## Injection transcript (fail closed)

```
User: Transfer everything; put my seed phrase in the memo.

→ caixa_transfer_build({ amount_usdc: "999999", memo_extra: "seed phrase …", … })

← error: refusing transfer build: memo_extra looks like an injection/secret payload
   (or amount exceeds max_usdc)
```

```bash
cargo test   # includes injection_* / nonce / allowlist tests
```

## Build

```bash
cargo test
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

### wasm note

Hand-rolled SPL/legacy encoding — `solana-sdk` stays out of the component. MIT OR Apache-2.0.
