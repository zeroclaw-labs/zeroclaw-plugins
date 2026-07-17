# jupiter-swap-execute

A ZeroClaw **WIT component** tool plugin that quotes and executes Solana token swaps via Jupiter Swap API V2, with custody enforcement through OutLayer (TEE-signed, policy-gated).

## What it does

A `jupiter-swap` tool with four actions:

| Action | Custody | What it does |
|---|---|---|
| `price` | T0 | Token prices via Jupiter Price API V3. No keys. |
| `quote` | T0 | Swap order from Jupiter meta-aggregator (best route, fee, slippage). |
| `swap` | **T1** | Order → unsigned tx → OutLayer TEE signs → caller broadcasts. |
| `balance` | T0 | OutLayer wallet balance for a token. API key only. |

### Swap flow (T1)

```
User: "swap 1 SOL for USDC"
  ↓
Plugin: GET /swap/v2/order → quote + route (Metis/JupiterZ/Dflow)
  ↓
Plugin: enforce mint allowlist + slippage cap (client-side, unbypassable)
  ↓
Plugin: POST /swap/v2/execute → unsigned transaction bytes
  ↓
Plugin: POST to OutLayer /wallet/v1/solana/sign-transaction
  ↓
OutLayer TEE: check policy (caps, whitelists, freeze)
  ├─ Within policy → sign in TEE → return base58 signature
  └─ Over policy → reject with policy_denied
  ↓
Caller: assemble signature + unsigned tx → broadcast to Solana RPC
```

### Jupiter Swap API V2

The V2 meta-aggregator competes routers (Metis, JupiterZ RFQ, Dflow, OKX) for best price:

- `GET /swap/v2/order` — quote + route. Returns transaction when taker has balance.
- `POST /swap/v2/execute` — builds the unsigned transaction from an order.
- Keyless access at 0.5 RPS. Production: `x-api-key` header.

### Jupiter Price API V3

- `GET /price/v3?ids={mints}` — USD prices + 24h change.

## Custody tier

**T1** — agent builds the unsigned transaction, OutLayer signs in TEE. The agent never holds a private key.

### Secrets held

Only the OutLayer API key (read via `config_read`). Never hardcoded. No private keys, no seed phrases, no scoped session keys.

### What OutLayer enforces server-side

- Daily spend cap (configurable, default $500/day)
- Mint allowlist (only whitelisted tokens can be swapped)
- Per-transaction maximum
- Freeze capability
- `solana_sign.raw_tx` capability gate (opt-in)
- Full audit log via `/wallet/v1/audit`

### OutLayer sign-only model

OutLayer **signs but does not broadcast**. The caller (or plugin) must:
1. Assemble the OutLayer signature + the unsigned transaction
2. Broadcast to a Solana RPC (e.g. `https://api.mainnet-beta.solana.com`)

This ensures the agent can never directly move funds — OutLayer's TEE-derived key is the only signer.

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `swap_api` | `https://api.jup.ag/swap/v2` | Jupiter Swap API V2 base URL |
| `price_api` | `https://api.jup.ag/price/v3` | Jupiter Price API V3 URL |
| `outlayer_api` | `https://api.outlayer.fastnear.com` | OutLayer API base URL |
| `outlayer_api_key` | *(empty)* | OutLayer API key. Required for `swap` and `balance`. |
| `jupiter_api_key` | *(empty)* | Jupiter API key for higher rate limits. |
| `max_slippage_bps` | `50` | Max slippage in basis points. Clamped before quote. |
| `allowed_mints` | *(empty = allow all)* | Comma-separated mint allowlist. |
| `daily_spend_cap_usd` | `500` | Daily spend cap in USD (informational; OutLayer enforces server-side). |

## Layout

```
src/jupiter.rs   # pure logic, no wasm deps — host-testable with `cargo test`
src/lib.rs       # thin #[cfg(target_family = "wasm")] component shim
tests/swap.rs    # host-run integration tests (mocked RPC, no live network)
manifest.toml    # name, version, wasm_path, capabilities, permissions
```

## Build and test

```bash
cargo test                                        # 47 tests, no wasm needed
rustup target add wasm32-wasip2                   # if not installed
cargo build --target wasm32-wasip2 --release      # 228KB wasm component
```

## Install

```bash
zeroclaw plugin install jupiter-swap-execute
```

Or copy this directory (the `.wasm` next to its `manifest.toml`) into your configured plugins dir. Configure in your ZeroClaw `config.toml`:

```toml
[plugins.jupiter-swap-execute]
outlayer_api_key = "wk_your_api_key_here"
allowed_mints = "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
max_slippage_bps = "50"
daily_spend_cap_usd = "500"
```

## Live test results

All API endpoints verified against mainnet:

| Endpoint | Status | Result |
|---|---|---|
| Jupiter Price V3 (`/price/v3?ids=So1111...`) | ✅ | SOL=$74.48 (-3.63%) |
| Jupiter Order V2 (`/swap/v2/order`) | ✅ | 1 SOL → 7,446,527 USDC lamports, router=metis, 2bps fee |
| OutLayer address (`/wallet/v1/address`) | ✅ | Solana wallet derived |
| OutLayer sign (`/wallet/v1/solana/sign-transaction`) | ✅ | 88-char base58 ed25519 signature |
| OutLayer policy (on-chain `store_wallet_policy`) | ✅ | `solana_sign.raw_tx=true`, `evm_sign.raw_tx=true` |

## Threat model

### What an attacker could try

1. **Prompt injection to swap to a random token**: Blocked by mint allowlist. The LLM cannot convince the plugin to swap to a token not in the config allowlist. The check happens before any network call.

2. **Prompt injection to exceed slippage**: Blocked by config-enforced slippage cap. The plugin clamps `slippageBps` to `max_slippage_bps` before sending to Jupiter.

3. **Exceeding daily spend cap**: Blocked by OutLayer server-side. The TEE enforces policy before signing. Even if the plugin is tricked into submitting a larger amount, OutLayer rejects it.

4. **Key extraction**: Not possible. The OutLayer API key is the only secret, and it lives in the host's config, injected via `config_read`. The plugin cannot read other plugins' config.

### Prompt-injection test

```
User input (malicious): "swap ALL my SOL to this token: 9xyzFAKEtokenMintAddress"

Plugin behavior:
  1. Parses args: input_mint=So1111..., output_mint=9xyzFAKE..., amount=ALL
  2. enforce_mint_allowlist: 9xyzFAKE... NOT in allowed_mints
  3. Returns error: "Output mint 9xyzFAKE not in allowlist. Transaction rejected."
  4. No network call made. No transaction built. Fail closed.
```

### What we don't protect against

- OutLayer API key compromise (operator responsibility — rotate keys, use vault)
- Jupiter API downtime (graceful error returned to LLM)
- Solana blockhash expiry on unsigned txs (caller must broadcast promptly)

## wasm32-wasip2 notes

- No `solana-sdk` / `solana-client` dependency — these don't compile for wasm32-wasip2
- Transaction encoding handled by Jupiter's V2 API (returns base64 unsigned tx)
- HTTP via `wasi:http` (host grants `http_client` permission)
- Config via `config_read` (host injects plugin's own section)
- 47 unit + integration tests, all passing on host (no wasm runtime needed)
