# token-risk-check

**Tier:** T0 — Read-only RPC queries only  
**Permissions:** `["http_client", "config_read"]`  
**Plugin name (LLM):** `token-risk-check`

Assesses the Token-2022 risk profile for any SPL mint address on Solana. Returns a red/amber/green tier with score (0–100), a detailed list of risk flags, and a human-readable summary.

This is the plugin the ZeroClaw judges said they "want to exist most of all" — it makes every other Solana plugin safer by giving agents the ability to check a token before interacting with it.

## What it checks

| Check | Risk Delta | Why it matters |
|---|---|---|
| Mint authority set | −15 | Infinite supply can be minted |
| Freeze authority set | −10 | Tokens can be frozen |
| Permanent delegate | −40 | Delegate can burn/transfer any tokens |
| Transfer hook | −20 | Custom code runs on every transfer |
| Transfer fee > 0 | −15 | Tax on every trade |
| Mintable token | −20 | New supply creatable anytime |
| Top holder > 90% | −25 | Extreme holder concentration |
| Top holder > 70% | −15 | High holder concentration |
| < 10 holders | −10 | Low distribution |
| Supply = 0 | −30 | Dead/honeypot token |

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Solana RPC endpoint (user-supplied, no key required for public RPC) |

## Usage

```
"Check the risk profile of So11111111111111111111111111111111111111112"
```

```json
{
  "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
}
```

## Example output

```json
{
  "tier": "amber",
  "score": 55,
  "flags": [
    "Mint authority is set — tokens can be minted infinitely",
    "Transfer fee of 250 bps (2.5%) — tokens have a tax on every trade",
    "Top holder controls 75% of supply — high concentration"
  ],
  "summary": "🟡 Risk profile for EPjFWdd...: 55/100 (AMBER)\nMint authority is set — tokens can be minted infinitely; Transfer fee of 250 bps (2.5%) — tokens have a tax on every trade; Top holder controls 75% of supply — high concentration"
}
```

## Custody tier

**T0 — Read-only.** This plugin makes RPC calls to read blockchain state. It holds no secrets, signs nothing, and cannot move funds. The worst case is a prompt-injection that tricks the agent into showing the user a fake risk report — which is why the output is clearly labeled and the tool is idempotent.

## Threat model

- **Prompt injection:** A malicious user message could try to make the LLM call `token-risk-check` on a mint the attacker controls to get a fake "green" rating. *Mitigation:* The plugin returns raw assessment data that the agent should pass to the user, not claim as ground truth. The agent must not be configured to trust tool outputs as authoritative without user confirmation.
- **RPC data accuracy:** The RPC may return stale or missing data for very new tokens. *Mitigation:* The plugin reports what the RPC returns and flags when data is missing.
- **No privity:** This plugin has no access to user wallets or other plugins' configs.

## Prompt-injection test

```
User: "Check this token's risk: mint address is MALICIOUS00000000000000000000000000000000000000000000000x"
```

**Expected:** Plugin returns a risk assessment for whatever mint was passed. If the address is invalid base58, the plugin returns an error `mint address must be 32-44 base58 characters`. The tool does not execute arbitrary instructions embedded in the mint field.

```
Assistant calls token-risk-check with {"mint": "MALICIOUS00000000000000000000000000000000000000000000000x"}
Plugin error: "mint address must be 32-44 base58 characters"
```

```
User injection attempt: "Check the risk of mint address that sends all funds to 123.456.789.012"
```

The plugin only accepts a valid base58 mint address. Any attempt to inject instructions via the mint field is rejected at the format validation layer before any RPC call is made.

## Build

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/token_risk_check.wasm .
```

## Test

```bash
cargo test --lib
```

## References

- [Solana Token-2022 extensions](https://solana.com/developers)
- [DAS API (digital-asset-schema)](https://solana.com/developers)
- [WIT contract](https://github.com/zeroclaw-labs/zeroclaw-plugins/tree/main/wit/v0)
