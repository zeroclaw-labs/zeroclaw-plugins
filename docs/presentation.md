---
marp: true
theme: default
paginate: true
title: ZeroClaw × Solana — Keymaker Plugin Set
description: Bounty submission deck — T1 build-tx + T2 signer, Vault transit, simulation-based validation.
---

<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code:wght@400;500;700&display=swap');

:root {
  --color-background: #0d1117;
  --color-foreground: #c9d1d9;
  --color-heading: #58a6ff;
  --color-accent: #7ee787;
  --color-danger: #ff7b72;
  --color-muted: #8b949e;
  --color-code-bg: #161b22;
  --color-border: #30363d;
  --font-default: 'Inter', 'Helvetica Neue', sans-serif;
  --font-code: 'Fira Code', 'Consolas', 'Monaco', monospace;
}

section {
  background-color: var(--color-background);
  color: var(--color-foreground);
  font-family: var(--font-default);
  font-weight: 400;
  box-sizing: border-box;
  border-left: 4px solid var(--color-accent);
  position: relative;
  line-height: 1.45;
  font-size: 22px;
  padding: 56px;
}

h1, h2, h3, h4, h5, h6 {
  font-weight: 700;
  color: var(--color-heading);
  margin: 0;
  padding: 0;
  font-family: var(--font-code);
}

h1 {
  font-size: 50px;
  line-height: 1.2;
  text-align: left;
}

h1::before {
  content: '# ';
  color: var(--color-accent);
}

h2 {
  font-size: 34px;
  margin-bottom: 28px;
  padding-bottom: 10px;
  border-bottom: 2px solid var(--color-border);
}

h2::before {
  content: '## ';
  color: var(--color-accent);
}

h3 {
  color: var(--color-foreground);
  font-size: 22px;
  margin-top: 20px;
  margin-bottom: 8px;
  font-family: var(--font-default);
  font-weight: 600;
}

ul, ol {
  padding-left: 32px;
}

li {
  margin-bottom: 8px;
}

li::marker {
  color: var(--color-accent);
}

pre {
  background-color: var(--color-code-bg);
  border: 1px solid var(--color-border);
  border-radius: 6px;
  padding: 14px;
  overflow-x: auto;
  font-family: var(--font-code);
  font-size: 14px;
  line-height: 1.45;
}

code {
  background-color: var(--color-code-bg);
  color: var(--color-accent);
  padding: 2px 6px;
  border-radius: 3px;
  font-family: var(--font-code);
  font-size: 0.88em;
}

pre code {
  background-color: transparent;
  padding: 0;
  color: var(--color-foreground);
}

footer {
  font-size: 12px;
  color: var(--color-muted);
  font-family: var(--font-code);
  position: absolute;
  left: 56px;
  right: 56px;
  bottom: 30px;
  text-align: right;
}

footer::before {
  content: '// ';
  color: var(--color-accent);
}

section.lead {
  border-left: 4px solid var(--color-accent);
  display: flex;
  flex-direction: column;
  justify-content: center;
}

section.lead h1 {
  margin-bottom: 18px;
}

section.lead p {
  font-size: 20px;
  color: var(--color-foreground);
  font-family: var(--font-code);
}

strong {
  color: var(--color-accent);
  font-weight: 700;
}

em {
  color: var(--color-danger);
  font-style: normal;
}

table {
  border-collapse: collapse;
  font-size: 16px;
  margin-top: 10px;
}

th, td {
  border: 1px solid var(--color-border);
  padding: 6px 12px;
  text-align: left;
}

th {
  background-color: var(--color-code-bg);
  color: var(--color-heading);
  font-family: var(--font-code);
}

hr {
  border: none;
  border-top: 1px dashed var(--color-border);
  margin: 18px 0;
}
</style>

<!-- _class: lead -->
<!-- footer: ZeroClaw × Solana — Keymaker Plugin Set -->

# ZeroClaw × Solana

### Keymaker Plugin Set — bounty submission

Build any Solana tx from an Anchor IDL.
Sign it through a HashiCorp Vault transit key.
**The private key never enters the ZeroClaw process.**

`zeroclaw-labs/zeroclaw-plugins` · Superteam Earn / ZeroClaw Solana bounty

---

## The thesis

The killer use-case for autonomous agents is **paying people**.
The killer risk is **the agent holding the key**.

Every existing solution picks one of two bad poles:

| Pole                 | Failure mode                                                |
| -------------------- | ----------------------------------------------------------- |
| Agent holds the key  | Prompt-injection → drain. Key exfil. Game over.             |
| Human signs every tx | Not autonomous. Throughput = 1 req / human / cup of coffee. |

We refuse both. The agent **builds** transactions and **chooses** to sign them.
The key lives in a KMS. The agent never sees it.
Policy lives in **simulation**, not in instruction-data parsing.

> Agent-owned execution. Key-never-leaves custody.

---

## Two plugins at a glance

```
                ┌────────────────────────────┐
                │     ZeroClaw agent (LLM)   │
                └─────────────┬──────────────┘
                              │ build_tx  +  sign
            ┌─────────────────┴──────────────────┐
            ▼                                    ▼
  ┌─────────────────────┐            ┌─────────────────────┐
  │  solana-build-tx    │            │ solana-keychain-sign│
  │  (T1 — read-only)   │  base64    │  (T2 — signs +      │
  │                     │ ────────▶  │   submits)          │
  │  • IDL encode       │  unsigned  │  • envelope guards  │
  │  • simulate + diff  │  tx +      │  • Vault transit    │
  │  • policy enforce   │  summary   │  • fresh blockhash  │
  └──────────┬──────────┘            └──────────┬──────────┘
             │ RPC (simulate)                   │ Vault /sign  + RPC (send)
             ▼                                  ▼
        ┌─────────┐                       ┌─────────┐
        │ Solana  │                       │ Vault   │
        │  RPC    │                       │ transit │
        └─────────┘                       └─────────┘
```

`build-tx` is the brain. `keychain-sign` is the (very paranoid) hand.

---

## `solana-build-tx` — architecture

```
  args { program_id, instruction_name, args, accounts }
                  │
                  ▼
   ┌──────────────────────────────────┐
   │ 1. IDL lookup (config)           │   ← Anchor 0.30+ format, registered by program_id
   │ 2. Hardcoded blocklist check     │   ← approve / set_authority / close_account family
   │ 3. Discriminator = sha256(s8)    │   ← 8-byte Anchor discriminator
   │ 4. Borsh-encode args             │
   │ 5. Assemble v0 message           │   ← fee_payer = signer_pubkey, latest blockhash
   │ 6. simulateTransaction           │   ← replaceRecentBlockhash=true, accounts=base64
   │ 7. Layer A: balance diff         │   ← per-mint outflow, recipient allowlist
   │ 8. Layer B: token-state diff     │   ← delegate / close_authority / owner fields
   └──────────────────────────────────┘
                  │
                  ▼
  { instructions_base64, summary, validation_report }
```

**Config-owned**: `rpc_url`, `signer_pubkey`, `idl.*`, `mint_allowlist`,
`per_call_outflow_cap`, `recipient_allowlist`, `expected_delegates_allowlist`,
`blocked_instructions_extra`.

---

## Simulation-based validation — the key insight

The original plan was to parse instruction data per-program
(extract amount for SPL, extract payment_id for Tributary, …).
That's a **pile of special cases** that breaks the moment a new program shows up.

Instead we let the chain tell us. **One technique, any program.**

```
   simulateTransaction (replaceRecentBlockhash=true)
              │
              ▼
   ┌─────────────────────────────────────┐
   │ preTokenBalances  ──┐               │
   │ postTokenBalances ──┤               │
   │                     ▼               │
   │  Δ per (mint, acct)                 │
   │   • every touched mint ∈ allowlist │   ← else reject "mint not in allowlist"
   │   • Δout(signer, mint) ≤ cap        │   ← else reject "exceeds per-call cap"
   │   • every inflow acct ∈ recipients  │   ← else reject "recipient not in allowlist"
   │                                     │
   │ accounts[owner ∈ {token,token22}]   │
   │   AccountLayout-decode pre & post   │
   │   • delegate ∈ expected_delegates   │   ← else reject "unexpected delegate: <pk>"
   │   • close_authority unchanged       │   ← else reject "close_authority changed"
   │   • owner unchanged                 │   ← else reject "owner changed"
   └─────────────────────────────────────┘
```

**Side effect**: we catch **hidden CPIs**. A fake "reward claim" that calls
`approve(attacker, u64::MAX)` internally shows up at Layer B even though the
outer discriminator looked innocent.

---

## `solana-keychain-sign` — architecture

```
  args { instructions_base64 }
              │
              ▼
   ┌────────────────────────────────────────┐
   │ ENVELOPE GUARDS (the only validation): │
   │   • message_bytes.len() ≤ max (1 KiB)  │
   │   • instructions.len() ≤ max (1, v0)   │
   │   • message.fee_payer == signer_pubkey │
   └────────────────────────────────────────┘
              │
              ▼
   fetch fresh blockhash ──▶ inject ──▶ assemble v0 message
              │
              ▼
   backend.sign(message_bytes)   ←── trait, swappable
              │
              ▼
   assemble versioned tx { message, signatures: [sig] }
              │
              ▼
   RPC sendTransaction → poll getSignatureStatuses → confirmed
              │
              ▼
   { signature, explorer_url, slot }
```

The signer **does not inspect instruction content**.
That's build-tx's job. Defense-in-depth = operator configures the same
`signer_pubkey` in both plugins.

---

## Multi-backend signer

`SignerBackend` trait ships in v0 so backends are a pure addition in v1.

| Backend           | v0 status                     | Auth model                                                        |
| ----------------- | ----------------------------- | ----------------------------------------------------------------- |
| **Vault transit** | **Fully working** (waki HTTP) | `X-Vault-Token` header                                            |
| **AWS KMS**       | STUB → `NotImplemented`       | SigV4 hand-roll (~300 LOC pure Rust), planned for v1              |
| **GCP KMS**       | STUB → `NotImplemented`       | Operator-pasted `access_token` for v1; service-account JWT for v2 |

```rust
trait SignerBackend {
    fn sign(&self, message: &[u8]) -> Result<Signature, BackendError>;
    fn pubkey(&self) -> Pubkey;
}
```

Why Vault first? **Dev-mode docker-compose in 5 seconds**, transit engine
never exposes the key, token is revocable, and every CVE has been audited to
death. Perfect for the session-wallet pattern.

Why stub AWS / GCP? Cloud KMS is where production lives. We did the
hard part (the trait + envelope guards + assemble/submit) so v1 is
"just another backend".

---

## Custody ladder — where we sit

```
   T0  ───  No custody. Read-only plugins (redact-text, slack).
            Agent sees stuff. Touches nothing.

   T1  ───  Build custody. solana-build-tx.
            Holds RPC URL + policy config.
            Returns unsigned txs. Cannot move funds.

   T2  ───  Sign + submit custody. solana-keychain-sign.        ◀── we live here
            Holds Vault token. Signs the bytes build-tx made.
            Submits. Polls. Returns signature.

   T3  ───  Full key custody. (We deliberately do NOT do this.)
            Agent holds the private key. Never shipped.
```

**Rules of the house**

- The private key lives **only** inside the Vault transit engine.
- Neither plugin reads process env. Only `__config` from the host jail.
- Neither plugin logs secrets. `vault_token` may live in config;
  it never appears in `log-record` attributes.
- Plugins are stateless. Per-day caps live in ZeroClaw SOP cadence ×
  per-call cap, and on-chain policy for Tributary targets.

---

## Prompt-injection defense — in depth

Three layers compose. The agent consumes untrusted text (chat, web pages,
emails, memos). An adversary tries to coerce it into draining the session
wallet. Here's what stops them.

```
   ┌───────────────────────────────────────────────────────┐
   │ Layer A — BALANCE DIFF       (build-tx, post-sim)     │
   │   catches: cap exceeded, wrong mint, wrong recipient  │
   ├───────────────────────────────────────────────────────┤
   │ Layer B — STATE DIFF         (build-tx, post-sim)     │
   │   catches: hidden CPI approve / close / owner change  │
   ├───────────────────────────────────────────────────────┤
   │ Layer C — HARDCODED BLOCKLIST (build-tx, pre-encode)  │
   │   catches: top-level approve, set_authority,          │
   │            close_account (token + token-2022)         │
   │   NOTE: operator CANNOT remove baseline via config    │
   └───────────────────────────────────────────────────────┘
```

**Special case — memos.** Simulation treats a memo as no-op (no balance
effect). build-tx **accepts** but the ~150-token summary cites the memo
verbatim. The human at the approval gate sees it before SOP cron hands the
unsigned tx to the signer.

---

## Worked example — SPL USDC transfer

```
   Agent:   "Pay Alice 5 USDC"
   build-tx args:
     program_id:      SPL_TOKEN_2022
     instruction_name: transfer
     args:            { amount: 5_000_000 }
     accounts:        { source, destination, authority }

   ┌─ simulate ────────────────────────────────────────┐
   │ pre[session]   = 100_000_000     post =  95_000_000 │
   │ pre[alice]     =   0              post =   5_000_000 │
   │ err = null                                          │
   └─────────────────────────────────────────────────────┘
   policy:   USDC ∈ mint_allowlist ✓
             Δoutflow 5_000_000 ≤ cap 100_000_000 ✓
             alice ∈ recipient_allowlist ✓
             no delegate / close / owner change ✓

   → returns { instructions_base64, summary }

   [SOP cron / human approves]

   signer:   envelope guards ✓
             fresh blockhash
             POST /v1/transit/sign/solana-session → signature
             sendTransaction → confirmed slot 295_000_123

   → { signature: "5K...ABC",
       explorer_url: "https://solscan.io/tx/5K...ABC" }
```

---

## Worked example — Tributary via SOP cron

> User wants a 50 USDC invoice paid every Monday.
> The agent must NOT call `approve` — that's the user's job.

```
   ONCE (out-of-band, hardware wallet):
     user ─── approve(tributary_user_payment_pda, 50_000_000) ──▶ session ATA
     operator adds PDA to expected_delegates_allowlist

   WEEKLY (SOP cron fires):
     agent ─▶ build-tx { tributary::execute_payment,
                         args: { payment_id, amount: 50_000_000 },
                         accounts: { payer, payee, user_payment_pda, delegate } }

   simulate → 50 USDC out session, 50 USDC in merchant,
              delegate field = Tributary PDA (expected) ✓,
              no close / owner change

   → { unsigned tx, summary }
   SOP cron ─▶ signer ─▶ Vault /sign ─▶ submit ─▶ Slack: "Invoice paid: <url>"
```

The user controls delegations. The agent controls recurring executions.
This is the correct security model for autonomous payments.

---

## Blockhash-expiry solve — Trap #1

**The bug**: build-tx fetches a blockhash at build time. By the time
human approval lands (90s later), the blockhash has expired. Tx fails.

**First instinct** (wrong): extend the freshness window. Doesn't compose
with multi-validator quic rpc patches; doesn't survive chain congestion.

**Lazy fix that actually works**:
build-tx **does not** fetch a blockhash. It assembles the message with a
**placeholder**, simulates with `replaceRecentBlockhash=true` (works for
validation), and ships the unsigned tx without a real blockhash.

The signer fetches the **fresh** blockhash **at sign-time**, **after**
approval, **before** the Vault POST. Freshness window starts at the only
moment that matters.

```
   build-tx            signer              Vault
      │                   │                   │
      │ simulate(replace) │                   │
      │ ◀── ok            │                   │
      │                   │                   │
      │  [human review]   │                   │
      │  [approval]       │                   │
      │                   │                   │
      │ ──unsigned tx──▶  │                   │
      │                   │ getLatestBlockhash│
      │                   │ inject blockhash  │
      │                   │ ──message bytes──▶│
      │                   │ ◀──── signature ──│
      │                   │ sendTransaction   │
      │                   │ ◀──── confirmed ──│
```

---

## What fought us on `wasm32-wasip2`

| Trap                                                               | Symptom                                       | Solve                                                                                                                      |
| ------------------------------------------------------------------ | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `solana-sdk` won't compile to wasip2                               | build error within 30s                        | **Hand-roll** the v0 message format. borsh + bs58 + base64 + ed25519-dalek + sha2. ~600 LOC.                               |
| `solana-client` needs `tokio`                                      | linker errors                                 | `waki` for HTTP. Async runtime is the host's problem.                                                                      |
| `reqwest` pulls `tokio` + `mio`                                    | same as above                                 | `waki` only.                                                                                                               |
| `simulateTransaction` returns base64 zstd-encoded accounts         | parse errors on `accounts.data`               | Disable zstd on the request, request `encoding: "base64"` explicitly, AccountLayout-decode (165 bytes for v1, 165 for v2). |
| `[workspace]` at repo root pulled our crates into the host's build | our `cargo build` rebuilt `zeroclaw` itself   | Each plugin has its own `[workspace]` to isolate.                                                                          |
| Test runner needs `cargo test` on host without wasm toolchain      | host builds the wasm-only `cdylib` and chokes | `#[cfg(target_family = "wasm")]` shim in `lib.rs`, pure core in `*.rs`, `crate-type = ["cdylib", "rlib"]`.                 |

No `zc-solana-core` shared crate. Each plugin is standalone. The Solana
primitives inline into `solana-build-tx/src/encoding.rs`; the Vault transit
HTTP shape inlines into `solana-keychain-sign/src/backends/vault.rs`.

---

## What we'd build next

- **Squads proposal mode** for `solana-keychain-sign` — agent proposes,
  multisig disposes. Direct Vault signing becomes the small-value fast-path;
  Squads becomes the large-value checkpoint.
- **AWS KMS SigV4 hand-roll** (~300 LOC pure Rust) — promote the v0 stub
  to working backend. Same for GCP KMS OAuth2 + service-account JWT.
- **Daily / monthly caps** — out of plugin scope (stateless), but the
  ZeroClaw SOP layer can wrap `solana-build-tx` calls with a sliding-window
  ledger keyed on `signer_pubkey + mint`.
- **CPI-aware memo scan** — replace substring matching with a parser that
  walks the simulated inner-instruction trace and flags overt instruction
  phrases even when wrapped.
- **Plug-in policy modules** — operators write WASM-policy components that
  vote on the simulation report (custom constraints, sanctions screening).
- **Publish the inline Solana primitives retroactively** as a crate — the
  shared core was killed in refactor for v0 simplicity; if a third Solana
  plugin appears, the helpers extract cleanly.

---

<!-- _class: lead -->

# Ship it.

```
  ┌─────────────────────────────────────────────────┐
  │  git clone zeroclaw-labs/zeroclaw-plugins        │
  │  git checkout zeroclaw-solana-bounty             │
  │  docker compose -f docker/vault-dev-compose.yml  │
  │           up -d                                  │
  │  bash docker/vault-init.sh                       │
  │  ( cd plugins/solana-build-tx       &&           │
  │        cargo build --target wasm32-wasip2        │
  │                       --release )                │
  │  ( cd plugins/solana-keychain-sign  &&           │
  │        cargo build --target wasm32-wasip2        │
  │                       --release )                │
  └─────────────────────────────────────────────────┘
```

**Bounty**: [Superteam Earn / ZeroClaw Solana](https://github.com/zeroclaw-labs/zeroclaw-plugins)
**Host**: [zeroclaw-labs/zeroclaw](https://github.com/zeroclaw-labs/zeroclaw)
**Reference plugin**: [`plugins/redact-text/`](./plugins/redact-text/)
**Vault transit docs**: <https://developer.hashicorp.com/vault/docs/secrets/transit>
**Tributary**: <https://github.com/tribute-labs/tributary>

`#agent-owned #key-never-leaves #ship-it`
