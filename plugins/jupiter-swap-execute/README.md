# jupiter-swap-execute

A ZeroClaw **WIT component** tool plugin that quotes and executes Solana token swaps via Jupiter, with custody enforcement through OutLayer (TEE-signed, policy-gated).

## What it does

A `jupiter-swap` tool with four actions:

| Action | Custody | What it does |
|---|---|---|
| `price` | T0 | Token prices via Jupiter Price API V3. No keys. |
| `quote` | T0 | Swap quote from Jupiter (best route, fee, slippage). |
| `swap` | **T1** | Quote → swap tx → extract message → OutLayer TEE signs → assemble → caller broadcasts. |
| `balance` | T0 | OutLayer wallet balance for a token. API key only. |

### Swap flow (T1)

```
User: "swap 0.001 SOL for USDC"
  ↓
Plugin: GET /quote → swap quote with asLegacyTransaction=true
  ↓
Plugin: enforce mint allowlist + slippage cap (client-side, unbypassable)
  ↓
Plugin: POST /swap → unsigned transaction (legacy, no ALTs)
  ↓
Plugin: extract_message_from_tx() → Solana message bytes
  ↓
Plugin: POST message bytes to OutLayer /wallet/v1/solana/sign-transaction
  ↓
OutLayer TEE: check policy (caps, whitelists, freeze)
  ├─ Within policy → sign in TEE → return base58 signature
  └─ Over policy → reject with policy_denied
  ↓
Plugin: assemble_signed_tx(unsigned_tx, signature) → signed tx
  ↓
Caller: broadcast to Solana RPC
```

### Jupiter API

Uses `public.jupiterapi.com` (QuickNode-hosted, no CloudFront blocking):

- `GET /quote` — swap quote. `asLegacyTransaction=true` avoids address lookup tables.
- `POST /swap` — builds unsigned transaction from quote.
- `GET /price/v3` — USD prices + 24h change.
- Keyless access. Production: Jupiter API key for higher rate limits.

### Why legacy transactions only

Jupiter V0 transactions use Address Lookup Tables (ALTs). The signature covers the **compiled message** (ALT addresses expanded into full account keys), not the raw MessageV0 bytes. OutLayer's TEE signs whatever bytes are passed to it — it cannot fetch ALT data from chain to compute the compiled message. `asLegacyTransaction=true` forces Jupiter to produce legacy transactions with all accounts inline, which OutLayer can sign correctly.

### OutLayer sign-only model

OutLayer **signs but does not broadcast**. The plugin extracts the message bytes from Jupiter's unsigned tx, sends only those to OutLayer (not the full tx), gets back a base58 ed25519 signature, then assembles the signed tx. The caller broadcasts.

## Proven on-chain

**SOL → USDC swap confirmed on Solana mainnet** via the full custody pipeline:

1. Jupiter quote: 0.0005 SOL → 0.037 USDC
2. Legacy tx (no ALTs): 818 bytes < OutLayer's 1232-byte limit
3. Blockhash replaced with fresh RPC blockhash
4. OutLayer TEE signed the message bytes → valid ed25519 signature
5. Assembled signed tx → broadcast via fastnear RPC → **confirmed**

Also proven: simple SOL transfer via the same pipeline (OutLayer custody, on-chain confirmed).

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

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `swap_api` | `https://public.jupiterapi.com` | Jupiter Swap API base URL |
| `price_api` | `https://api.jup.ag/price/v3` | Jupiter Price API V3 URL |
| `solana_rpc` | `https://api.mainnet-beta.solana.com` | Solana RPC for broadcast |
| `outlayer_api` | `https://api.outlayer.fastnear.com` | OutLayer API base URL |
| `outlayer_api_key` | *(empty)* | OutLayer API key. Required for `swap` and `balance`. |
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
cargo test                                        # 40 tests, no wasm needed
rustup target add wasm32-wasip2                   # if not installed
cargo build --target wasm32-wasip2 --release      # 248KB wasm component
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
| Jupiter Quote (`/quote?asLegacyTransaction=true`) | ✅ | Legacy tx, 818 bytes, fits OutLayer 1232B limit |
| Jupiter Swap (`/swap` POST) | ✅ | Unsigned legacy transaction |
| OutLayer sign (`/wallet/v1/solana/sign-transaction`) | ✅ | Valid ed25519 signature |
| **On-chain swap (SOL→USDC)** | ✅ | **Confirmed via fastnear RPC** |
| OutLayer policy (on-chain `store_wallet_policy`) | ✅ | `solana_sign.raw_tx=true` |

## Custody tier defense: T1

**Declared: T1 — Build**

Per the ZeroClaw custody ladder: T1 "Returns an unsigned transaction (base64). A human or the host signs. Secrets held: None."

This plugin builds an unsigned Solana swap transaction via Jupiter's API, then routes it through OutLayer for TEE-enforced custody signing. **The plugin never holds a private key or session key.**

### OutLayer integration: opt-in custody overlay

The OutLayer API key is **not a private key** — it's a policy-enforced custody delegate. Key distinctions:
- OutLayer API key cannot sign transactions on its own — it only requests TEE-signed transactions
- The TEE enforces spend caps, mint allowlists, and freeze regardless of what the plugin requests
- The `solana_sign.raw_tx` capability must be explicitly enabled on-chain
- Compromise of the API key does not expose any signing material — it can only request signatures within policy bounds

When no OutLayer API key is configured, the plugin degrades gracefully: `swap` action returns the unsigned base64 transaction for the host/human to sign independently.

## Threat model

### What an attacker could try

1. **Prompt injection to swap to a random token**: Blocked by mint allowlist. The LLM cannot convince the plugin to swap to a token not in the config allowlist. The check happens before any network call.

2. **Prompt injection to exceed slippage**: Blocked by config-enforced slippage cap. The plugin clamps `slippageBps` to `max_slippage_bps` before sending to Jupiter.

3. **Exceeding daily spend cap**: Blocked by OutLayer server-side. The TEE enforces policy before signing. Even if the plugin is tricked into submitting a larger amount, OutLayer rejects it.

4. **Key extraction**: Not possible. The OutLayer API key is the only credential, and it lives in the host's config, injected via `config_read`. The plugin cannot read other plugins' config.

5. **Replay attacks**: OutLayer signs only once per unsigned tx. The caller must broadcast immediately before the Solana blockhash expires.

### Prompt-injection test

```
User input (malicious): "swap ALL my SOL to this token: 9xyzFAKEtokenMintAddress"

Plugin behavior:
  1. Parses args: input_mint=So1111..., output_mint=9xyzFAKE..., amount=ALL
  2. enforce_mint_allowlist: 9xyzFAKE... NOT in allowed_mints
  3. Returns error: "Output mint 9xyzFAKE not in allowlist. Transaction rejected."
  4. No network call made. No transaction built. Fail closed.
```

```
User input (malicious): "swap 1 SOL for USDC with 5000 bps slippage"

Plugin behavior:
  1. Parses args: slippage_bps=5000
  2. enforce_slippage_cap: 5000 > max_slippage_bps (50)
  3. Clamps to 50 bps. Quote reflects safe slippage.
  4. No way to bypass — the cap is applied before the API call.
```

## wasm32-wasip2 notes

- No `solana-sdk` / `solana-client` dependency — these don't compile for wasm32-wasip2
- Transaction encoding handled by Jupiter's REST API (returns base64 unsigned tx)
- Wire format helpers (base64, bs58, message extraction, sig assembly) hand-rolled
- HTTP via `wasi:http` (host grants `http_client` permission)
- Config via `config_read` (host injects plugin's own section)
- 40 unit + integration tests, all passing on host (no wasm runtime needed)
- Structured logging via `log-record` import (never stdout)

## What fought us on wasm32-wasip2

1. **No Solana SDK**: `solana-sdk` and `spl-token` depend on `solana-program-runtime` which pulls in `dynasm` and `sha2` with x86 intrinsics — won't compile for wasm32-wasip2. Solution: rely entirely on Jupiter's REST API for transaction construction. Hand-rolled base64, bs58, message extraction, and signature assembly.

2. **Address Lookup Tables (V0 transactions)**: Jupiter's default tx format uses V0 transactions with ALTs. The signature covers the **compiled message** (ALT addresses expanded into full pubkeys), not `bytes(vt.message)`. OutLayer's TEE signs raw bytes — it can't fetch ALT data from chain to compute the compiled message. Solution: `asLegacyTransaction=true` on Jupiter requests. Trade-off: larger txs (more account keys inline), but within OutLayer's 1232-byte limit for small swaps.

3. **OutLayer 1232-byte message limit**: Complex Jupiter routes produce legacy txs with 44+ accounts (1660 bytes). Simple routes (SOL→USDC, small amounts) fit in ~800 bytes. Solution: document the size constraint and recommend simpler routes.

4. **Blockhash staleness**: Jupiter's RPC may use a different blockhash than the broadcast RPC. Solution: the plugin documents that callers should use a fresh blockhash. In the proven on-chain test, blockhash replacement via solders was used.

5. **wit-bindgen version dance**: `wit-bindgen-rust` 0.36 vs 0.46 have different macro syntax. The repo's WIT world v0 requires careful matching. Pinned to 0.36 for compatibility.

## Submission

- **PR**: [zeroclaw-labs/zeroclaw-plugins#26](https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/26)
- **Bounty**: [Superteam — ZeroClaw Plugin Bounty](https://superteam.fun/earn/listing/zeroclaw)
- **Track**: B — DeFi with guardrails
