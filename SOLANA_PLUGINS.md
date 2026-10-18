# Solana Plugins for ZeroClaw

Three T0 read-only Solana tool plugins for the [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) agent runtime, submitted for the Superteam Brasil x ZeroClaw Solana bounty.

**PR:** [zeroclaw-labs/zeroclaw-plugins#57](https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/57)

---

## Plugins

### 1. `solana-token-risk`
Check if a Solana token is safe before buying.

**Input:** mint address (base58)
**Output:** RED / AMBER / GREEN verdict with reasons

Checks:
- Mint authority (open = unlimited supply risk)
- Freeze authority (accounts can be frozen)
- Token-2022 extensions: transfer hooks, permanent delegate, high fees
- Top-3 holder concentration
- Metadata URI presence

```
RED - Token RuG1..1111
- Mint authority open - new tokens can be minted anytime
- Top 3 holders own 91% of supply
- No metadata URI - anonymous token
```

---

### 2. `solana-wallet-narrate`
Turn raw transaction history into plain English.

**Input:** wallet address (base58), limit (default 5)
**Output:** Human-readable sentences

```
Recent activity for 7xKm..Nabc:
1. Received 250 USDC from 9zLp...
2. Sent 1.0000 SOL to EPjF...
3. Complex transaction (swap or contract call)
```

---

### 3. `solana-sns-resolve`
Resolve `.sol` domain names to wallet addresses.

**Input:** domain (e.g. `levrone.sol`)
**Output:** `levrone.sol -> 7xKmNabc...`

Pair with other plugins so users type names instead of 44-character addresses.

---

## Custody Tier: T0 — Read Only

All three plugins are T0. No private keys. No transaction signing. No custody of any assets.

| Plugin | Tier | Secrets held | Permissions |
|--------|------|-------------|-------------|
| solana-token-risk | T0 | None | http_client, config_read |
| solana-wallet-narrate | T0 | None | http_client, config_read |
| solana-sns-resolve | T0 | None | http_client |

**Threat model:** All inputs are passed directly to Solana RPC as raw strings. No LLM interpretation occurs inside any plugin. A malicious input string cannot alter the verdict — verdicts are derived purely from on-chain data. See `prompt_injection_fails_closed` test in each plugin.

---

## Architecture

Each plugin follows the pure core / thin shim pattern required by the bounty:

```
plugin/
  src/
    lib.rs          <- WASM shim (#[cfg(target_family = "wasm")] only)
    core/
      mod.rs        <- pure Rust logic, no wasm dependency
      rpc.rs        <- JSON-RPC over waki (HTTP)
      checks.rs     <- risk/narration/resolution logic
      shape.rs      <- output formatter (~200 tokens max)
  tests/
    core_test.rs    <- host-run tests, mocked RPC, no live network
  manifest.toml
  README.md
```

The shim is never tested directly. All logic lives in `core/` and is tested with `cargo test` on the host with no WASM toolchain required.

---

## Test Results

```
solana-token-risk:     9/9  tests passing
solana-wallet-narrate: 6/6  tests passing
solana-sns-resolve:    6/6  tests passing
Total:                 21/21 tests passing
```

Tests include:
- Open mint authority detected as RED
- Clean token detected as GREEN
- Freeze authority detected as AMBER
- Whale concentration detected as RED
- Missing metadata detected as AMBER
- Output length under 400 chars (context window discipline)
- **Prompt injection fails closed** — malicious input cannot change verdict

---

## Build

```bash
# Run tests (no WASM toolchain needed)
cd plugins/solana-token-risk && cargo test
cd plugins/solana-wallet-narrate && cargo test
cd plugins/solana-sns-resolve && cargo test

# Build WASM components
cargo build --target wasm32-wasip2 --release
```

Build verified on `aarch64-unknown-linux-gnu` (ARM64 Ubuntu server).

Output files:
```
plugins/solana-token-risk/target/wasm32-wasip2/release/solana_token_risk.wasm      299KB
plugins/solana-wallet-narrate/target/wasm32-wasip2/release/solana_wallet_narrate.wasm  300KB
plugins/solana-sns-resolve/target/wasm32-wasip2/release/solana_sns_resolve.wasm    280KB
```

---

## Config

Each plugin reads its RPC URL from the host config via `config_read`. No secrets are hardcoded.

```toml
[plugins.solana-token-risk]
wasm_path = "plugins/solana_token_risk.wasm"

[plugins.solana-token-risk.config]
rpc_url = "https://api.mainnet-beta.solana.com"
das_url = "https://api.mainnet-beta.solana.com"
```

---

## What fights you on wasm32-wasip2

- `solana-sdk` and `solana-client` do not compile for `wasm32-wasip2`. All RPC calls are hand-rolled JSON-RPC over `waki` (blocking `wasi:http`).
- `getrandom` requires feature flags in WASM — avoided entirely since T0 plugins need no randomness.
- Background processes on Termux/proot-Ubuntu cannot load the ZeroClaw binary due to `LD_PRELOAD` interference — `unset LD_PRELOAD` required before running.
- The WIT ABI is marked `@unstable` — pinned to the commit cloned at build time.

---

## License

MIT

## Author

Levrone ([@levr_nx](https://x.com/levr_nx)) — [GitHub](https://github.com/cutlerjay109-create)

## What we'd build next

1. **lending-health** (T0) — Kamino/MarginFi health factor monitor with cron SOP alerts when health drops below 1.15
2. **portfolio-brief** (T0) — token balances + prices + 24h delta shaped to ~200 tokens for a daily briefing SOP
3. **solana-pay-request** (T1) — generate Solana Pay QR URLs so any ZeroClaw Telegram agent becomes a payment terminal
4. **governance-watch** (T0) — Realms proposal alerts and summaries

These four would complete a full Track D + Track A suite, giving ZeroClaw agents complete Solana awareness from safety checking through payments.
