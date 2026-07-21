# solana-tx-authorize

Pre-sign Solana transaction authorization for a ZeroClaw agent. Feed it any
unsigned transaction (base64); it decodes every instruction, checks the
declared intent, enforces the operator's spend policy, simulates, and answers
**ALLOW / REVIEW / DENY / UNKNOWN** with reason codes and a one-paragraph
human summary.

**Custody tier: T0.** It holds nothing (an RPC key at most) and builds
nothing. It reads, simulates, and decides.

## What it checks

- Decode: legacy + v0 transactions, bare message or signature-array form
- Intent binding: the transaction must **be** what the agent declared
  (action, mint, amount, recipient — ATA-aware, so a USDC transfer to
  `x.sol`'s ATA matches intent recipient `x.sol`)
- Policy (operator's, host-injected): mint + recipient allowlists, per-tx caps
  in raw units, allowed programs **and** allowed instruction discriminators,
  durable-nonce posture, Token-2022 extension rules, velocity, fee/rent caps
- Authority attacks: `System::Assign`, SPL `SetAuthority`/`Approve` → DENY
- Token-2022 mint risk from chain: permanent delegate, transfer hook,
  transfer fee, default-frozen honeypot
- Simulation (mandatory by default): RPC down or simulation error → UNKNOWN
- Fail closed on everything ambiguous: empty/malformed policy, malformed
  transaction, unknown program, unknown instruction

## Args

```json
{
  "transaction_base64": "required — the unsigned transaction",
  "intent": { "action": "spl_transfer", "mint": "EPjF…", "amount_raw": "25000000", "recipient": "7xK…", "memo": "invoice-412" },
  "detail_level": "optional: \"full\" for evidence fields"
}
```

## Output (slim, shaped for the model)

```json
{
  "verdict": "ALLOW",
  "summary": "Sends 25,000,000 raw USDC to 7xK…p91 (ATA). 3 instructions: ata.create_idempotent, spl_token.transfer_checked, memo.memo.",
  "reason_codes": [],
  "next_action": "SIGN_OR_SQUADS_PROPOSE",
  "decision_id": "sha256:…"
}
```

## Config keys (`config_read`, host-injected, secrets decrypted)

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | ✓ (https) | Solana RPC endpoint (user-supplied; no keys in code) |
| `policy_json` | ✓ | Operator spend policy — raw units, deny by default. **Missing/malformed → DENY (fail closed)** |

## Threat model

The LLM is adversarial: it can craft any args, any intent, any context. The
verdict depends only on (a) the transaction bytes, (b) chain state, (c) the
host-injected policy the agent cannot write. A prompt injection cannot raise
a cap, widen an allowlist, or turn a DENY into an ALLOW (see
`conformance/fixtures/` and the root README transcripts).

## Worked example

```
agent: "authorize this transfer" (25 USDC → Cafe Brasil ATA, intent matches)
tool : ALLOW — "Sends 25,000,000 raw USDC to 7xK…p91 (ATA)."
agent: "same bytes, but the recipient was swapped to an attacker address"
tool : DENY — SH-INTENT-RECIPIENT-031
```

Build: `cargo build --target wasm32-wasip2 --release` · Test: `cargo test`
(offline, mocked RPC) · Proof: `just prove-safety` at the repo root.
