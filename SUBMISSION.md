# Superteam Earn — submission pack

**Bounty:** Build Solana-native plugins for Zeroclaw (Superteam Brasil)  
**Author:** darkty0x  
**Tracks:** C (DePIN) + E (shared `solana-core`)

## Links (paste into Earn)

| Deliverable | URL / path |
| --- | --- |
| **PR (primary)** | https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/126 |
| **Public fork / branch** | https://github.com/darkty0x/zeroclaw-plugins/tree/feat/solana-depin-core |
| **Demo video (≤3 min)** | `~/Desktop/zeroclaw-depin-demo.mp4` (~2:25 — terminal attest/sign/submit + Telegram channel scenes + explorer). Upload to Drive/YouTube/Streamable, then paste URL |
| **Telegram bot (live channel)** | https://t.me/zeroclaw_plugin_bot |
| **On-chain proof (devnet)** | https://explorer.solana.com/tx/3vY2Q2aEn9YWy7T9H4JaD1VBdCPhmkn16W9Ukf3wSWZsRwmPnV2WFd3A762yiH7N3NPE7wQ8j3QrvjKs5NGoP5CE?cluster=devnet |

## One-page write-up

### What we shipped

- `solana-core` — wasm-friendly Solana substrate (no `solana-sdk`): keys, memo ix, durable nonce, injectable JSON-RPC, shaped output helpers.
- `depin-attest` (**T1**) — unsigned durable-nonce memo attestation from a sensor reading.
- `depin-uptime-watch` (**T0**) — `OK` / `STALE` / `MISSING` freshness verdict for Telegram cron.

### Custody tier and why

| Plugin | Tier | Why |
| --- | --- | --- |
| `depin-attest` | **T1** | Prepares work that still needs a human wallet signature. No private key, no `sendTransaction`. |
| `depin-uptime-watch` | **T0** | Read-only RPC. Safe to cron into Telegram. |

T2 (agent holds keys / submits) is out of scope on purpose: DePIN uptime should not require trusting the agent with funds.

### Threat model (fail closed)

Malicious chat cannot inject `private_key`, override `payer` / `nonce_account` / `rpc_url`, set absurd readings, or request fund movement (`submit` / `sendTransaction`). Unknown fields refuse before RPC. Executable transcripts: `plugins/*/tests/injection.rs` + README sections.

### What fought us on wasm32-wasip2

`solana-sdk` / `solana-client` are a non-starter inside a WIT component. What worked: `bs58` + `base64` + `sha2` + hand-rolled legacy message / durable-nonce layout, JSON-RPC behind an injectable `HttpClient`, and `waki` only in the wasm shim. Each plugin vendors `solana-core` so isolated CI (`plugins/<name>` + `wit/v0`) still builds. `wit/v0` is experimental (no `.frozen`) — we pin the repo world and expect rebuilds.

### What we'd build next

Pi SOP pack (BME280 → attest → Telegram approve → session-key sign), memo schema v2, fleet watch rollup, optional separate T2 submit crate (never inside these plugins).

### Demo script (≤3 min, no slides)

1. Title + plugin discovery (terminal).  
2. Terminal: durable-nonce `depin_attest` → human sign/submit → explorer Success.  
3. **Telegram `@zeroclaw_plugin_bot`:** user asks to attest `pi-greenhouse-7` → agent returns `✅` T1 card (incl. `unsigned_tx_base64`) → uptime watch `🟢 OK`.  
4. On-chain explorer still.  
5. Custody close: “T0/T1 only — plugin never held a key.”

Render locally:

```bash
demo/recording/.venv/bin/python demo/scripts/render-long-demo-video.py \
  --log demo/recording/depin-demo.txt \
  --explorer demo/recording/explorer.png \
  --out demo/recording/zeroclaw-depin-demo-2min.mp4
```

## Discord / X (tiebreak)

**Discord `#solana-bounty` (or ZeroClaw Discord):**  
> Opened https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/126 — Track C DePIN + Track E `solana-core`. Durable-nonce attest (T1) + uptime watch (T0). Looking for maintainer eyes on the wasm/vendoring approach.

**X thread starter:**  
> Shipping Solana DePIN tools for @ZeroClaw: unsigned durable-nonce attestations that survive Telegram approval queues + a T0 uptime watch.  
> PR: https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/126  
> No keys in the agent. #Solana #DePIN #ZeroClaw

## Earn checklist

- [ ] PR link submitted  
- [ ] Demo video URL submitted (≤3 min, real agent + Telegram)  
- [ ] README / this write-up linked or pasted  
- [ ] Posted in ZeroClaw Discord  
- [ ] At least one public X update during the bounty  
