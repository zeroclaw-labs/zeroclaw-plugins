# spl-transfer-build

Builds an **unsigned** SOL or SPL transfer transaction (base64) with a
matching declared-intent object for `solana-tx-authorize`. ATA-aware: token
transfers land in the recipient's Associated Token Account, created
idempotently. Optional invoice memo for reconciliation.

**Custody tier: T1.** It holds no keys and signs nothing. A human or the host
signs its output.

## The builder invariant

The builder runs the **same policy engine** as the guard before serializing.
If the requested transfer violates the operator policy, the tool returns an
error — it never emits a transaction its own guard would deny. This is
asserted by the round-trip test: `build → authorize = ALLOW` on the happy
path.

## Args

```json
{
  "recipient": "base58 wallet (tokens land in its ATA)",
  "amount_raw": "25000000",
  "mint": "optional — omit for native SOL",
  "memo": "optional, ≤ 566 bytes (invoice id etc.)",
  "token_program": "optional override (default: classic SPL Token)"
}
```

## Output

```json
{
  "transaction_base64": "…",
  "intent": { "action": "spl_transfer", "mint": "EPjF…", "amount_raw": "25000000", "recipient": "7xK…", "memo": "invoice-412" },
  "destination_account": "…ATA…",
  "human_summary": "Send 25,000,000 raw USDC to 7xK…p91. Memo: \"invoice-412\". Unsigned — a human or the host signs.",
  "unsigned": true
}
```

## Config keys

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | ✓ (https) | Blockhash + mint metadata |
| `fee_payer` | ✓ | The wallet paying fees / owning source tokens (public key, never a secret) |
| `policy_json` | recommended | The operator spend policy (enables the builder pre-check) |

## Threat model

The builder constructs exactly one transfer from validated inputs (pubkeys
parsed, amounts bounded integers, memo length capped). It cannot create
arbitrary instructions, cannot sign, and refuses out-of-policy requests at
build time. The mandatory check still happens downstream in
`solana-tx-authorize` — defense in depth, not trust.

## Worked example

```
agent: "charge table 4: 25 USDC, memo invoice-412"
tool : unsigned tx (ATA create idempotent + transferChecked + memo) + intent
agent: "now 500 USDC to the same table"
tool : error — violates the operator policy (SH-DENY-CAP-001)
```

Build: `cargo build --target wasm32-wasip2 --release` · Test: `cargo test`.
