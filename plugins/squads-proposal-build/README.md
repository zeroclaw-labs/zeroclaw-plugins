# squads-proposal-build

The final stage of the Safe Hands path: builds an **unsigned Squads v4
multisig proposal** for a transaction that needs human approval. The agent
proposes; multisig members dispose from their own wallets.

**Custody tier: T1.** It holds no keys and signs nothing.

## The trust boundary (why this component exists)

A caller (the agent) may present a prior "authorization decision" from
`solana-tx-authorize`. **This component never trusts it.** Before building
anything, it independently:

1. loads the operator policy from its own host-injected config,
2. re-decodes the transaction,
3. re-simulates it,
4. re-runs the full deterministic policy evaluation,
5. only then builds `vaultTransactionCreate` + `proposalCreate`.

If the caller's record claims ALLOW while the independent evaluation
disagrees, that is tamper evidence:

```
SH-TRUST-FORGED: caller-provided verdict is not trusted. The supplied
decision record claims ALLOW, but independent re-evaluation returned DENY
(SH-DENY-CAP-001). No proposal constructed.
```

This is conformance fixture #20 — run `just prove-safety` to see it.

## What it builds

- Byte-exact Squads v4 encoding, golden-tested against the official
  `@sqds/multisig` SDK (PDAs, both instruction discriminators, borsh args,
  and Squads' own inner `TransactionMessage` format — `SmallVec<u16>` data
  lengths, no blockhash).
- The inner instructions are **rebound to the multisig vault** — the agent
  drafts "spend from the shared vault", never from a personal wallet.
- No blockhash in the inner message: the proposal is the durable object, so
  approval queues never die to blockhash expiry (bounty trap #1).
- The output is unsigned; the proposer signs and submits, then members
  approve from their wallets (Squads UI or CLI).

## Args

```json
{
  "transaction_base64": "required",
  "intent": { "action": "transfer", "amount_raw": "50000000", "recipient": "9hSR…" },
  "decision_record": { "verdict": "ALLOW", "…": "audited, never trusted" },
  "memo": "optional note on the vault transaction"
}
```

## Config keys

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | ✓ (https) | Multisig state, blockhash, simulation |
| `squads_create_key` | ✓ | The multisig's create_key (PDA derived here) |
| `proposer` | ✓ | Member pubkey creating proposals — **Initiate-only recommended** (cannot approve or execute) |
| `squads_vault_index` | optional | default 0 |
| `policy_json` | ✓ | The operator spend policy (independent evaluation) |

## Squads setup (one-time, ~5 min)

1. Create or select a multisig in the Squads app.
2. Add the agent's proposer as a member with **Initiate** permission only
   (no Approve, no Execute).
3. Put the multisig's `create_key` and the proposer pubkey in config.
4. (Optional) create a Squads Spending Limit; keep the local policy
   stricter of the two.

## Threat model

Everything the guard checks, this component re-checks independently —
including the caller's own honesty. A compromised agent can forge records,
mutate transactions, or misreport intents; none of it produces a proposal
unless the transaction independently passes policy at proposal time.

## Worked example

```
agent: "propose this 0.05-SOL payment to the multisig"
tool : unsigned proposal tx — "Squads proposal #1 created (unsigned)."
       (independent re-authorization: ALLOW)
human: signs + submits, approves from phone → multisig executes
       (verified on devnet — see EVIDENCE.md)
```

Build: `cargo build --target wasm32-wasip2 --release` · Test: `cargo test`.
