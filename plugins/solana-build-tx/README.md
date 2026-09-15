# solana-build-tx

> **T1 custody tier** — builds and validates unsigned Solana transactions from
> Anchor IDLs. Never signs, never holds private keys. Pair with
> `solana-keychain-sign` for T2 signing via HashiCorp Vault / AWS KMS / GCP KMS.

## What it does

1. Looks up the program's Anchor IDL from operator config.
2. Checks the instruction against a **hardcoded blocked list** (the `approve`
   family — see [Why `approve()` is blocked](#why-approve-is-blocked)).
3. Borsh-encodes the instruction args + resolves named accounts.
4. Fetches a fresh blockhash and assembles a versioned (V0) unsigned tx.
5. Calls `simulateTransaction` with `replaceRecentBlockhash=true`.
6. Runs **two validation layers** against the simulation result:
   - **Layer A — balance diff**: every touched mint must be in `mint_allowlist`;
     signer's net outflow per mint must be ≤ `per_call_outflow_cap`; any
     inflow account must be in `recipient_allowlist` (if set).
   - **Layer B — token-account state diff**: no unexpected delegate, no
     `close_authority` change, no `owner` change on writable SPL accounts.
7. Returns the unsigned tx (base64) + a ~150-token human summary citing net
   flows and simulation CU.

## Config keys

Under `[plugins.entries.solana-build-tx.config]`:

| Key                            | Format                          | Description                                                             |
| ------------------------------ | ------------------------------- | ----------------------------------------------------------------------- |
| `rpc_url`                      | string                          | Solana RPC endpoint for simulation + blockhash.                         |
| `signer_pubkey`                | base58                          | Wallet controlled via Vault/KMS. Fee-payer of every tx.                 |
| `per_call_outflow_cap`         | JSON `{"mint":"base_units"}`    | Per-call cap per mint. USDC 6dp → `100000000` = 100 USDC.               |
| `mint_allowlist`               | comma-sep                       | Mints the agent may touch at all.                                       |
| `recipient_allowlist`          | comma-sep                       | Allowed inflow addresses. Empty = allow any.                            |
| `expected_delegates_allowlist` | comma-sep                       | Delegates pre-approved on signer's token accounts (e.g. Tributary PDA). |
| `blocked_instructions_extra`   | comma-sep `program:instruction` | Operator-added blocks beyond the hardcoded baseline.                    |
| `idl.<program_id>`             | stringified IDL JSON            | Anchor 0.30+ IDL for a program. SPL Token ships as default.             |

## Why `approve()` is blocked

The `approve` family (`approve`, `approve_checked`, `set_authority`,
`close_account` on both `spl_token` and `spl_token_2022`) is **hardcoded
blocked** in v0. Operators cannot remove these entries via config — only add
more via `blocked_instructions_extra`.

**Rationale**: a single `transfer` is bounded by the tx amount AND the
`per_call_outflow_cap`. An `approve(attacker, u64::MAX)` creates a delegate
with unlimited transfer authority for the entire token account — every cap
the plugin enforces becomes meaningless because the attacker can drain later,
outside any per-call check.

**Tributary works correctly under this stance**: the user runs
`approve(tributary_user_payment_pda, amount)` from their OWN wallet (hardware
wallet, Phantom). The agent NEVER calls `approve`. The agent only signs
`tributary::execute_payment`, which the Tributary program performs via the
pre-existing delegation. The user controls delegations; the agent controls
recurring executions.

**Hidden-CPI defense (Layer B)**: a malicious program could internally CPI
into `spl_token::approve` (e.g. a fake "reward claim" hiding an approve). The
top-level discriminator block in `idl.rs` only sees the OUTER instruction.
Layer B catches this: after simulation, it decodes writable SPL token
accounts and rejects if any `delegate` field is non-null and not in
`expected_delegates_allowlist`.

## Threat model

| Threat                                   | Mitigation                                  |
| ---------------------------------------- | ------------------------------------------- |
| Agent builds tx for unregistered program | IDL lookup rejects before encoding          |
| Agent calls `approve` to create delegate | Hardcoded blocked list (Layer 0)            |
| Agent exceeds spending cap               | Layer A outflow diff rejects                |
| Agent touches disallowed mint            | Layer A mint allowlist rejects              |
| Agent pays attacker address              | Layer A recipient allowlist rejects         |
| Hidden CPI into `approve`                | Layer B delegate/close_authority/owner diff |
| Malformed instruction causes sim failure | Sim `err` = hard reject                     |

## Architecture

```
src/
├── lib.rs        — wasm shim (#[cfg(target_family = "wasm")])
├── builder.rs    — public API: build_transaction(), types, RpcClient trait
├── policy.rs     — PolicyConfig, HARDCODED_BLOCKED, spending caps
├── idl.rs        — Anchor IDL registry + instruction lookup + blocked check
├── encoding.rs   — borsh arg encoding → instruction data
├── validation.rs — Layer A (balance diff) + Layer B (state diff)
└── summary.rs    — ~150-token human summary for approval gate
```

## Build

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

## Test

```bash
cargo test
```

All tests run on host — no wasm toolchain, no live network.

## License

MIT
