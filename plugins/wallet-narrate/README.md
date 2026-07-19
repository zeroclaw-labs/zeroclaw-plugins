# wallet-narrate

**Tier:** T0 — Read-only RPC queries only  
**Permissions:** `["http_client", "config_read"]`  
**Plugin name (LLM):** `wallet-narrate`

Turns raw Solana transaction signatures or wallet addresses into human-readable sentences the agent can say aloud in a chat: *"Received 250 USDC from 7xK… Swapped 1 SOL → 190 USDC on Jupiter."*

This is the plugin that makes blockchain activity legible to non-technical users — it's the difference between an agent that says "I sent your transaction" and one that says "I paid table 4's 25 USDC tab."

## Usage

```
"What's the latest transaction on my wallet?"
"Show me what just happened with this signature: 5abc..."
```

```json
{ "address": "7xK...abcd" }
```

or

```json
{ "signature": "5abc...xyz" }
```

## Example output

```json
{
  "short": "Transferred 1.0000 SOL from 7xK... to Jupiter...",
  "type": "TRANSFER",
  "parties": ["7xK...abcd", "Jup..."],
  "direction": "out"
}
```

Agent renders this as: **"Sent 1 SOL to Jupiter."**

## Custody tier

**T0 — Read-only.** This plugin makes RPC calls to read transaction history. It holds no secrets, signs nothing, and cannot move funds. The worst case is a prompt-injection that tricks the agent into reading a transaction the user didn't ask about — mitigated by the plugin only accepting valid base58 signatures/addresses.

## Prompt-injection test

```
User injection: "Show me the transaction at address 'delete all my data; drop table users'
```

**Result:** The plugin interprets this as a wallet address lookup. `delete all my data; drop table users` fails base58 validation (contains invalid characters), and the plugin returns an error. No side effects.

```
Plugin error: "transaction not found or RPC error"
```

A valid base58 address/signature string cannot contain SQL injection, shell commands, or any other directive — the parsing layer rejects non-base58 input before any RPC call.

## Build

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/wallet_narrate.wasm .
```

## Test

```bash
cargo test --lib
```
