# solana-tx-decoder

A ZeroClaw **WIT component** tool plugin that decodes Solana transactions into
human-readable summaries suitable for display in a chat window. Implements the
`tool-plugin` world from `wit/v0`, compiles to `wasm32-wasip2`.

## What it does

Given a base58 transaction signature, fetches the parsed transaction via
Solana JSON-RPC and returns:

- **Status** — ✅ success or ❌ failed
- **Slot** — the slot the tx landed in
- **Program names** — human-readable (e.g., "System Program", "Jupiter Aggregator")
- **SOL transfers** — amount and direction
- **Fee** — in lamports
- **Block time** — Unix timestamp when available

The summary is one line — agents can skim it instantly without parsing raw
transaction data.

## Custody tier: **T0 (Read)**

This plugin performs read-only RPC calls. It holds **no secrets**, signs **nothing**.

| Tier | Description | Secrets held |
|------|-------------|-------------|
| T0   | RPC reads, tx lookup | None |

## Config keys

| Key | Default | Meaning |
|-----|---------|---------|
| `rpc` | `https://api.mainnet-beta.solana.com` | Solana JSON-RPC endpoint |
| `signature` | *(required)* | The base58 transaction signature |

## Layout (following redact-text)

```
src/tx_decoder.rs  # pure Rust core — host-testable, no wasm deps
src/lib.rs         # thin #[cfg(target_family = "wasm")] component shim
manifest.toml      # plugin identity, capabilities, permissions
```

## Build and test

```bash
cargo test                                         # host tests (5 tests)
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release       # the component (~305 KB)
```

## Usage example

```
> solana-tx-decoder {"signature":"5VERIFIED..."}

✅ TX 5VER...1111 | slot 320000000
  💰 0.0010 SOL account[0] → account[1]
  Instructions:
  • System Program (1111...1111)
  • Jupiter Aggregator (SSwp...1UZ)
  Fee: 5000 lamports
```

### Structured JSON output

```json
{
  "signature": "5VERIFIED...",
  "slot": 320000000,
  "block_time": 1715800000,
  "success": true,
  "fee": 5000,
  "accounts": ["SENDER...", "RECEIVER..."],
  "instructions": [
    {"program": "1111...1111", "label": "System Program", "accounts_used": 2}
  ],
  "sol_transfers": [
    {"from": "account[0]", "to": "account[1]", "amount_sol": 0.001}
  ],
  "summary": "✅ TX 5VER...1111 | slot 320000000\n  💰 0.0010 SOL account[0] → account[1]\n  Instructions:\n  • System Program (1111...1111)\n  Fee: 5000 lamports"
}
```

## Known program IDs

Recognizes System Program, Token Program, Token-2022, ATA, Metaplex, Jupiter,
Orca, Raydium AMM/CLMM, Pump.fun, Marinade, Drift, Kamino, and Compute Budget.
Unknown programs show `Unknown (xxxx...xxxx)` with the first and last 4 chars.

## Threat model

| Threat | Mitigation |
|--------|-----------|
| RPC returns spoofed transaction data | Plugin is read-only. Use a trusted RPC endpoint. |
| Transaction not found | Returns a clear error — does not hallucinate data. |
| Large tx with 64+ instructions | Output is bounded — instructions list is capped by RPC response. |
| Malformed parameters | Validates `signature` field before RPC call. |
