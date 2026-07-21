# Solana DePIN + Core for ZeroClaw — Design Spec

**Date:** 2026-07-22  
**Goal:** Win 1st place on Superteam Brasil “Build Solana-native plugins for Zeroclaw”  
**Wedge:** Track C (DePIN ★) + Track E (shared wasm-friendly core)  
**Custody:** T0 / T1 only — agent never holds a key, never submits transactions

## 1. Why this wedge

Open PRs already flood `token-risk-check` and Solana Pay. Head-to-head on those lanes is a coin flip into 2nd/3rd.

This submission owns:

1. **Sponsor-favorite Track C** — ZeroClaw’s unique Pi / GPIO / MQTT / SOP edge.
2. **Track E substrate** — reusable `solana-core` proven by real plugins (prize surface of its own).
3. **Named structural trap** — durable nonce so approval-gated attestations do not die while a human is AFK.
4. **Monthly utility** — `depin-uptime-watch` on cron is something a stranger still runs after demo day.

Out of scope for v1: GPIO WIT, T2 auto-submit, Helium claims, Jupiter, PIX, Token-2022 transfers.

## 2. Deliverables

| Path | Role | Tier |
|------|------|------|
| `plugins/solana-core/` | MIT pure Rust core (`rlib`) | n/a |
| `plugins/depin-attest/` | WIT tool: build unsigned attestation tx | T1 |
| `plugins/depin-uptime-watch/` | WIT tool: freshness / downtime verdict | T0 |

Submission also includes: MIT license, READMEs (custody + threat model + injection transcript + wiring diagram), demo video ≤3 min on a real channel, PR to `zeroclaw-labs/zeroclaw-plugins` (or public fork with mergeable branch).

Layout must match `plugins/redact-text` (canonical reference).

## 3. Architecture

```
plugins/
  solana-core/           # Track E — pure rlib, no WIT
  depin-attest/          # Track C — T1 tool component
  depin-uptime-watch/    # Track C — T0 tool component
wit/v0/                  # vendored ZeroClaw ABI (unchanged)
```

### Pure core / thin shim

- All Solana and policy logic lives in plain Rust modules with **no** `wit` / `waki` dependency.
- Each plugin’s `src/lib.rs` contains a `#[cfg(target_family = "wasm")]` component shim that:
  - runs `wit_bindgen::generate!` for world `tool-plugin` with `features: ["plugins-wit-v0"]`
  - parses JSON args + `__config`
  - calls the pure core
  - emits `log-record` events (never stdout)
  - returns shaped `ToolResult`
- Plugin crates: `crate-type = ["cdylib", "rlib"]`.
- `solana-core`: `rlib` only, canonical source at `plugins/solana-core/`.
- **CI packaging decision (pinned):** match upstream registry isolation. If each plugin directory must build alone (plugin dir + `wit/v0` only), each plugin vendors an identical copy at `src/vendor/solana_core/` generated from the canonical crate, with a CI/check script that fails if copies drift. Local development may use a path dependency; the PR documents which mode CI uses.

### Data flow

1. Host / SOP obtains a sensor reading (hardware tool, MQTT, or mock).
2. Agent calls `depin_attest` with `device_id`, `reading`, `unit`, `metric`.
3. Core validates policy → fetches/validates durable nonce → builds unsigned memo transaction → returns base64 + ~200-token summary.
4. Human (or ZeroClaw approval gate) signs and submits.
5. Cron SOP calls `depin_uptime_watch`; on `STALE` / `MISSING` the agent alerts Telegram/Discord.

Sensor path note: plugins do **not** talk GPIO directly (no declared GPIO permission in the tool world). Readings are passed in by the agent after the host hardware/SOP layer. README ships a wiring diagram and SOP recipe.

## 4. `solana-core` modules

| Module | Responsibility |
|--------|----------------|
| `rpc` | JSON-RPC over an injectable `HttpClient` trait: `getLatestBlockhash`, `getAccountInfo`, `getSignaturesForAddress`, `getTransaction` (minimal set) |
| `keys` | base58 pubkey encode/decode |
| `tx` | Message encode (legacy and/or v0 as needed), compact-u16, attach durable nonce advance |
| `ix` | System program helpers + SPL Memo instruction builder |
| `nonce` | Parse nonce account data; construct “advance nonce + memo” message |
| `shape` | Output truncation helpers; hard caps for chat-facing strings |
| `error` | Typed errors mapped to short operator-facing strings |

Constraints:

- No `solana-sdk` / `solana-client` dependency (wasm32-wasip2 friction).
- Hand-rolled encoding with `bs58` / `borsh` or equivalent small crates only if they compile cleanly for wasip2; otherwise hand-rolled.
- Money/size arithmetic uses checked ops; release profile enables `overflow-checks = true`.
- Document exactly what compiled for wasip2 in the write-up (scoring signal for Track E).

## 5. Plugin interfaces

### 5.1 `depin-attest` (tool name: `depin_attest`)

**Custody:** T1 — returns unsigned transaction only. Never calls `sendTransaction`. No private key in config.

**Args (JSON Schema)**

- `device_id` (string, required)
- `reading` (number, required)
- `unit` (string, required) — e.g. `celsius`, `seconds`
- `metric` (string, required) — e.g. `temperature`, `uptime`
- `memo_prefix` (string, optional) — default `ZCDEPIN`

**Config (`__config` via `config_read`)**

- `rpc_url` (required) — operator-supplied; never hardcode a keyed endpoint
- `payer` (required) — fee-payer pubkey (human wallet)
- `nonce_account` (required) — durable nonce account pubkey
- `max_abs_reading` (optional number) — reject values outside ±cap
- `allowed_metrics` (optional CSV) — if key present and empty → authorize nothing; if absent → default allowlist: `temperature,humidity,uptime,pressure,air_quality`

**Critical:** `payer` and `nonce_account` are **config-only**. Tool args must not override them (prompt-injection surface). If those keys appear in args, refuse.

**Memo payload (compact, pinned)**

```
{prefix}|{device_id}|{metric}|{reading}|{unit}|{period}|{hash12}
```

- Default `prefix` = `ZCDEPIN` (overridable via arg/config consistently; arg wins only for prefix).
- `reading` rendered with fixed formatting (trim trailing zeros, max 6 decimal places) so hashes are stable.
- `period` = `floor(unix_secs / 300)` (5-minute bucket).
- `hash12` = first 12 hex chars of SHA-256 over the canonical string `{device_id}|{metric}|{reading}|{unit}|{period}` (UTF-8).
- Full 64-char hex hash is returned in tool output as `attestation_hash`.
- Total memo UTF-8 length must stay ≤ 566 bytes (SPL Memo practical limit); refuse if over.

**Output (shaped, budget-tested)**

- Human-readable summary (~200 tokens max)
- `unsigned_tx_base64`
- `attestation_hash`
- `nonce_account`
- `durability: durable-nonce` (not a wall-clock blockhash expiry)

**Permissions:** `["http_client", "config_read"]`  
**Capabilities:** `["tool"]`

### 5.2 `depin-uptime-watch` (tool name: `depin_uptime_watch`)

**Custody:** T0 — RPC reads only.

**Args**

- `device_id` (string, required)
- `max_age_secs` (number, optional) — overrides config default

**Config**

- `rpc_url` (required)
- `payer` (required) — address whose recent txs are scanned for matching memos (config-only; args cannot override)
- `max_age_secs` (default `3600`)
- `memo_prefix` (default `ZCDEPIN`)
- `scan_limit` (default `25`, max `50`) — how many recent signatures to inspect

**Verdicts**

- `OK` — matching attestation newer than `max_age_secs`
- `STALE` — last match older than threshold
- `MISSING` — no matching memo found in scanned window

**Output:** verdict + age + last reading summary; hard size cap; no raw `getProgramAccounts` dumps.

**Permissions:** `["http_client", "config_read"]`  
**Capabilities:** `["tool"]`

## 6. Safety & threat model

| Threat | Defense |
|--------|---------|
| “Sign and submit / drain wallet” | No signing or submit API; tests assert absence |
| Extra JSON fields / `private_key` / `destination` | Unknown fields rejected; fail closed |
| Absurd readings | `max_abs_reading` |
| Wrong metric spam | `allowed_metrics` fail closed |
| LLM overrides payer/nonce | Config-only; ignored/rejected if passed in args |
| Replay | Period bucket + content hash; durable nonce consumes on use |
| Blockhash expiry in approval queue | Durable nonce account |
| Context flood | `shape` + unit tests on output byte/token budget |
| Bad RPC / parse errors | Soft fail: `ToolResult.success = false` with short error; never panic; never stdout |

### Fail-closed checklist (enforced in code)

1. Missing `rpc_url` / `payer` / `nonce_account` (attest) → refuse  
2. Missing `rpc_url` / `payer` (uptime-watch) → refuse  
3. Unknown JSON fields → refuse  
4. Metric not allowlisted → refuse  
5. Reading outside cap → refuse  
6. Nonce account missing / wrong authority → refuse  
7. Present-but-empty `allowed_metrics` → authorize nothing  
8. Args attempting to supply `payer`, `nonce_account`, or `private_key` → refuse  

### Prompt-injection transcript

README includes a chat transcript where a malicious message asks to submit now, use a main wallet key, set reading to `1e99`, and inject `private_key` / `destination`. Expected: refusals, no submit path, no unsigned tx when policy fails. The same scenarios are **executable host tests** so the transcript cannot rot.

## 7. Error & logging semantics

- Invalid args / policy violations → `Ok(ToolResult { success: false, error: Some(...), output: "" })`
- RPC / transport failures → same soft-fail pattern with short reason
- Structured logging only via WIT `logging` / `log-record` import
- Never write to stdout/stderr from the component

## 8. Testing strategy

Host tests only for CI default path (`cargo test`). Mock HTTP; no live network.

| Crate | Coverage targets |
|-------|------------------|
| `solana-core` | base58 roundtrip; memo ix bytes; durable-nonce message construction; mock RPC success/failure |
| `depin-attest` | policy refusals; config-only payer/nonce; output budget; attestation hash stability; no submit symbols/API |
| `depin-uptime-watch` | OK/STALE/MISSING; memo prefix filter; output budget |
| Shared | Injection tests mirroring README transcript |

Release builds:

```bash
cargo test
cargo build --target wasm32-wasip2 --release
cargo clippy --all-targets
cargo clippy --target wasm32-wasip2
```

## 9. Demo plan (≤3 minutes)

1. Real ZeroClaw agent on Telegram (or Discord).  
2. Trigger attestation from a sensor or mock reading.  
3. Show plugin returning unsigned durable tx + short summary in chat.  
4. Human signs/submits; show explorer memo.  
5. Stop feeding attestations; cron watch returns `STALE`; agent alerts channel.  

No slides. Terminal + phone is ideal. README includes Pi wiring diagram (e.g. BME280/DHT22 → I2C/GPIO → ZeroClaw SOP → plugin).

## 10. Docs & merge checklist

Each plugin README must include:

- What it does
- Config keys
- Custody tier and why
- Threat model
- One worked example
- Prompt-injection transcript
- wasm32-wasip2 friction notes / what worked

Hard requirements:

- [ ] Layout matches `plugins/redact-text`
- [ ] Pure core, thin shim; `cdylib` + `rlib`
- [ ] Host tests with mocked RPC
- [ ] Clean `wasm32-wasip2` release build
- [ ] `log-record` only (no stdout)
- [ ] Minimal `manifest.toml` permissions
- [ ] MIT License
- [ ] No private keys; no uncapped T2
- [ ] Early PR + Discord engagement + Superteam Earn submission + demo video

## 11. Implementation order

1. Scaffold `solana-core` + host tests for encode/RPC trait.  
2. Implement durable nonce + memo builders.  
3. `depin-attest` pure module + shim + tests (including injection).  
4. `depin-uptime-watch` pure module + shim + tests.  
5. Manifests, READMEs, wiring diagram, LICENSE.  
6. wasm32-wasip2 release builds; fix friction; document.  
7. Open PR early; iterate with maintainers.  
8. Record demo; submit on Superteam Earn; build-in-public updates.

## 12. Success criteria (judging alignment)

| Criterion | Weight | How we hit it |
|-----------|--------|---------------|
| Real utility | 30% | Cron uptime watch + physical DePIN story strangers keep running |
| Safety & custody | 25% | Honest T0/T1, fail closed, executable injection tests |
| Code quality | 20% | Pure core, real mocks, idiomatic Rust, Track E reusable core |
| Merge-readiness | 15% | Reference layout, minimal perms, docs, versioning |
| Demo & docs | 10% | ≤3 min real channel demo + wiring diagram + clear README |
