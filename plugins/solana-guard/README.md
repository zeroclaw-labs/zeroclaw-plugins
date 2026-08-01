# ogige — Solana Guard

ZeroClaw **WIT tool plugin** — a Solana transaction safety gate for autonomous agents.

Pass a base64-encoded transaction. Get back:

1. A **human-readable narration** of what the transaction does
2. Structured **risk findings** (authority changes, unlimited approvals, program upgrades, …)
3. A fail-closed verdict: **ALLOW** / **HOLD** / **REJECT**

Never signs. Never broadcasts. Custody tier **T0/T1** only — the agent proposes, a human (or ZeroClaw approval gate) decides.

Built for the [Superteam Brasil × ZeroClaw bounty](https://superteam.fun/earn/listing/zeroclaw).

## Why it exists

Agents that can touch Solana need a brake pedal. `ogige` is that brake: decode → narrate → classify → verdict, all inside the `wasm32-wasip2` sandbox with no `solana-sdk`.

## Tool surface

| | |
|---|---|
| Plugin name | `solana-guard` |
| Tool name | `solana_guard` |
| Input | `{ "transaction": "<base64>" }` |
| Output | JSON `GuardReport` (verdict, summary, narration, findings, …) |

### Example verdict

```json
{
  "verdict": "REJECT",
  "summary": "REJECT — dangerous primitive detected (TOKEN_APPROVE_MAX)",
  "narration": "Solana legacy transaction · …\n1. [SPL Token] Approve MAX (unlimited) delegate → …",
  "findings": [
    {
      "code": "TOKEN_APPROVE_MAX",
      "severity": "CRITICAL",
      "instruction_index": 0,
      "message": "Approve with u64::MAX — unlimited spending delegate"
    }
  ]
}
```

## Danger primitives (v0.1)

| Code | Severity | Trigger |
|---|---|---|
| `SYSTEM_ASSIGN` | CRITICAL | System Program Assign / AssignWithSeed |
| `TOKEN_APPROVE_MAX` | CRITICAL | SPL Approve with `u64::MAX` |
| `MINT_AUTHORITY_CHANGE` / `FREEZE_AUTHORITY_CHANGE` / `TOKEN_OWNER_CHANGE` | CRITICAL | Token SetAuthority |
| `PROGRAM_UPGRADE` / `UPGRADE_AUTHORITY_CHANGE` | CRITICAL | BPF Upgradeable Loader |
| `TOKEN_2022_PERMANENT_DELEGATE` | CRITICAL | Delegate can transfer or burn from any holder account |
| `TOKEN_2022_TRANSFER_HOOK_INIT` / `TOKEN_2022_TRANSFER_HOOK_UPDATE` | HIGH | External program runs on every transfer |
| `TOKEN_2022_NON_TRANSFERABLE` | MEDIUM | Mint is made non-transferable |
| `NONCE_AUTHORIZE` | HIGH | Durable nonce authority change |
| `TOKEN_APPROVE` / `TOKEN_MINT_TO` | HIGH | Delegates / minting |
| `TOKEN_BURN` / `TOKEN_FREEZE_ACCOUNT` | HIGH | Destruction / account freeze |
| `ALT_USED` / `UNKNOWN_PROGRAM` | HIGH | Unresolved accounts / unrecognized behavior default to HOLD |
| `SOL_TRANSFER` / `TOKEN_TRANSFER` | LOW | Normal transfers (ALLOW by default) |

## Config keys

Injected via the plugin's jailed `__config` section under its sole `config_read` permission. The plugin cannot read global or other plugin configuration:

| Key | Default | Meaning |
|---|---|---|
| `reject_on_critical` | `true` | Critical findings → REJECT |
| `hold_on_high` | `true` | High findings → HOLD |
| `hold_on_medium` | `false` | Medium findings → HOLD |

## Layout

```
src/core/     # SDK-less Solana decode / narrate / risk (no wasm deps)
src/guard.rs  # analyze() → GuardReport
src/lib.rs    # thin #[cfg(target_family = "wasm")] WIT shim
tests/        # host-run fixtures (cargo test)
../../wit/v0/ # registry-vendored ZeroClaw tool-plugin contract
manifest.toml
```

## Build and test

```bash
cargo test
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/solana_guard.wasm solana_guard.wasm
```

## Install

Once published in the ZeroClaw registry:

```bash
zeroclaw plugin install solana-guard
```

For local development, place `solana_guard.wasm` beside `manifest.toml` in the
configured plugin directory and enable plugins in ZeroClaw.

## Security boundary

- Offline and deterministic: no RPC, files, wallet, signing, or broadcast access.
- Invalid, non-canonical, truncated, or trailing transaction bytes fail analysis.
- Address lookup tables and unknown programs default to `HOLD` because their
  accounts or behavior cannot be fully resolved offline.
- A verdict is a pre-signing policy signal, not proof of runtime behavior. CPI,
  account state, and balance deltas require simulation or RPC enrichment.

## Roadmap

- [ ] Optional RPC enrichment (`simulateTransaction`, mint/authority lookups) behind `http_client`
- [x] Token-2022 transfer-hook / permanent-delegate detection
- [ ] Squads / multisig CPI surface narration
- [ ] Fixture corpus from real exploit txs

## License

MIT OR Apache-2.0
