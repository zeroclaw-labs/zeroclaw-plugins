# solana-tx-authorize

Pre-sign authorization for the Safe Hands v0.1 payment scope: native SOL
`SystemProgram::Transfer` and classic SPL Token `TransferChecked`, optionally
with idempotent ATA creation and a memo. It accepts a full unsigned transaction
plus declared intent and returns **ALLOW / REVIEW / DENY / UNKNOWN** with reason
codes and a human summary.

**Custody tier: T0.** It holds no signing key and builds no transaction.

## v0.1 checks

- Decode supported legacy and v0 unsigned transaction forms.
- Refuse a v0 transaction if any address lookup table (ALT) cannot be resolved;
  no partial account-key interpretation is permitted.
- Bind action, mint, raw amount, recipient, and memo to the decoded payment.
- Enforce the host-injected deny-by-default policy.
- Allow native SOL transfer or classic SPL `TransferChecked` only.
- Check that a classic SPL mint account is owned by the classic SPL Token
  program, has the canonical mint layout, is initialized, and declares the
  same decimals encoded in every `TransferChecked` instruction.
- Treat required fresh simulation as executable-state evidence for source and
  destination token accounts; v0.1 does not claim a separate direct decoder
  proof of source token-account state.
- Hard-deny plain SPL `Transfer`, all Token-2022 instructions, and all Squads
  instructions inside the payment draft. Squads is used only for the outer
  proposal transaction built after authorization.
- Deny authority-changing instructions, unknown programs, unknown
  instructions, signed input, malformed policy, and ambiguous transaction
  structure.
- Simulate when policy requires it; RPC or simulation failure returns UNKNOWN.

**Routing:** ALLOW may continue to the configured signing or Squads flow.
REVIEW goes to a human/operator queue. REVIEW, DENY, and UNKNOWN are not valid
inputs for `squads-proposal-build`; the proposer is ALLOW-only after its own
independent evaluation.

## Args

```json
{
  "transaction_base64": "required — canonical full unsigned transaction",
  "intent": {
    "action": "spl_transfer",
    "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    "amount_raw": "25000000",
    "recipient": "7xK…",
    "memo": "invoice-412"
  },
  "detail_level": "optional: full for evidence fields"
}
```

## Output

```json
{
  "verdict": "ALLOW",
  "summary": "Sends 25,000,000 raw units with classic SPL TransferChecked.",
  "reason_codes": [],
  "next_action": "SIGN_OR_SQUADS_PROPOSE",
  "decision_id": "sha256:…"
}
```

A decision record is not a transferable authorization capability. The Squads
plugin independently evaluates the full transaction and operator policy.

## Config

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | yes (HTTPS) | Solana RPC used for account resolution and simulation |
| `policy_json` | yes | Host-injected raw-unit policy; missing or malformed policy fails closed |

## Threat model

The transaction, intent, and caller-supplied decision context are untrusted.
The policy comes from plugin config that the model cannot rewrite. Positive
support is deliberately limited to the two v0.1 transfer forms above; support
for Token-2022, plain SPL `Transfer`, or unresolved ALT inputs is not implied.

From the repository root: build with
`cargo build --manifest-path plugins/solana-tx-authorize/Cargo.toml --target wasm32-wasip2 --release`,
test with `cargo test --manifest-path plugins/solana-tx-authorize/Cargo.toml`,
and run repository checks with `just prove-safety`.
