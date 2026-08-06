# spl-transfer-build

Builds the canonical full unsigned transaction and matching intent for a Safe
Hands v0.1 payment:

- native SOL via `SystemProgram::Transfer`; or
- classic SPL Token via `TransferChecked`, with optional idempotent ATA
  creation.

An optional memo is supported. Plain SPL `Transfer`, Token-2022, arbitrary
instructions, extra required signers, and unresolved address lookup tables
(ALTs) are refused.

**Custody tier: T1.** It holds no keys and signs nothing.

## Proposal-flow invariant

For a Squads proposal flow, set `fee_payer` to the **derived Squads vault public
key** for the selected vault index. The builder then creates a vault-native
draft: the vault pays fees, owns the SOL or classic SPL source account, and is
the sole required signer of the inner transaction.

This invariant must exist before authorization. `squads-proposal-build` embeds
the authorized inner instructions unchanged and does not perform
post-authorization authority or account rebinding. Squads instructions inside
the authorized draft are hard-denied; `squads-proposal-build` constructs the
outer Squads proposal instructions only after independent authorization.

The builder performs input and policy pre-checks, but
`solana-tx-authorize` remains the authorization boundary and simulation source.

## Args

```json
{
  "recipient": "base58 recipient wallet; classic SPL tokens land in its ATA",
  "amount_raw": "25000000",
  "mint": "omit for SOL; otherwise a classic SPL mint",
  "memo": "optional invoice note",
  "token_program": "omit or set to the classic SPL Token program"
}
```

For classic SPL, the builder checks that the mint account is owned by the
classic SPL Token program, has the canonical mint layout, and is initialized.
A Token-2022 mint/program or a request for plain `Transfer` is hard-denied.

## Output

```json
{
  "transaction_base64": "canonical full unsigned transaction",
  "intent": {
    "action": "spl_transfer",
    "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    "amount_raw": "25000000",
    "recipient": "7xK…",
    "memo": "invoice-412"
  },
  "destination_account": "…ATA…",
  "human_summary": "Vault-native classic SPL TransferChecked draft; unsigned.",
  "unsigned": true
}
```

The output is a canonical full unsigned transaction, not an instruction
fragment. Send those exact bytes and the matching intent to
`solana-tx-authorize`.

## Config

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | yes (HTTPS) | Blockhash and classic mint validation |
| `fee_payer` | yes | Public key that pays fees and supplies the source; use the derived Squads vault for proposal flows |
| `policy_json` | yes | Host-injected deny-by-default operator policy used for the builder pre-check |

Public keys are not secrets. Never configure a private key, seed phrase, or
signer material.

## Worked proposal flow

```text
operator: derive Squads vault index 0
config  : fee_payer = that derived vault public key
agent   : build 25 Devnet USDC with memo invoice-412
tool    : canonical full unsigned vault-native transaction
operator: authorize the exact bytes; continue only on ALLOW
```

From the repository root: build with
`cargo build --manifest-path plugins/spl-transfer-build/Cargo.toml --target wasm32-wasip2 --release`
and test with `cargo test --manifest-path plugins/spl-transfer-build/Cargo.toml`.
