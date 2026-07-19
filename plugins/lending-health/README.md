# lending-health

**Tier:** T0 — Read-only RPC queries only  
**Permissions:** `["http_client", "config_read"]`  
**Plugin name (LLM):** `lending-health`

Checks a lending position's health factor on Kamino, MarginFi, or Drift. Returns a tiered status (healthy / caution / danger / no_position) that can trigger a SOP alert — the agent pings the user on Telegram at 08:00, and immediately when health drops under 1.15.

This is the plugin most likely to be installed by strangers — nobody wants to wake up to a liquidated position.

## Usage

```
"Check my lending health on Kamino"
"What's my MarginFi health factor?"
```

```json
{ "wallet": "7xK...abcd", "protocol": "kamino" }
```

```json
{ "wallet": "7xK...abcd", "protocol": "marginfi" }
```

## Example output

```json
{
  "protocol": "Kamino",
  "wallet": "7xK...abcd",
  "health_factor": 1.85,
  "tier": "healthy",
  "message": "Health factor 1.85 — position is healthy",
  "details": ["2 lending positions active"]
}
```

Agent renders: **"Your Kamino position is healthy (HF: 1.85). All good."**

When tier is `danger`: **"⚠️ CRITICAL: Your Kamino position health factor dropped to 0.95. You are at risk of liquidation. Action required."**

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Solana RPC |
| `health_threshold` | `1.15` | Alert threshold for SOP triggers |

## Custody tier

**T0 — Read-only.** This plugin reads on-chain lending position data via RPC. It holds no secrets, signs nothing, and cannot move funds. The only risk is a prompt-injection making the agent repeatedly query positions — mitigated by rate considerations in the agent config.

## Prompt-injection test

```
User: "Check my health at wallet address 'await subprocess.run("rm -rf /")' on protocol 'kamino'"
```

The plugin accepts a base58 wallet address and a protocol enum. The injection string fails base58 validation (contains spaces, quotes, parentheses, slashes) and is rejected at the schema validation layer before any RPC call. No shell command execution possible.

## Build

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/lending_health.wasm .
```

## Test

```bash
cargo test --lib
```
