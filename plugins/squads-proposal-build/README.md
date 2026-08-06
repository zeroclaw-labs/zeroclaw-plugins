# squads-proposal-build

Builds a canonical full unsigned Squads v4 proposal transaction for a
vault-native Safe Hands v0.1 payment that independently evaluates to
**ALLOW**. Multisig members retain approval and execution authority in their
own wallets.

**Custody tier: T1.** The plugin holds no keys and signs nothing.

## ALLOW-only trust boundary

A caller may include a prior `solana-tx-authorize` decision record, but the
record is audit context rather than authority. Before producing a proposal,
this component loads its own host-injected policy, resolves and decodes the
full unsigned transaction, and performs an independent evaluation.

Only an independent **ALLOW** can continue. REVIEW is routed to a human/operator
outside this plugin. REVIEW, DENY, UNKNOWN, forged decision records,
unresolved address lookup tables (ALTs), and caller/independent-decision
mismatches are refused without constructing a proposal. When a decision record
is supplied, its verdict must exactly equal the independent verdict;
`SH-TRUST-FORGED` identifies a false caller `ALLOW`, while other disagreements
use `SH-TRUST-MISMATCH`.

## Vault-native, unchanged inner transaction

The input draft must already be built for the derived Squads vault:

- the vault is the sole required signer of the inner transaction;
- the SOL or classic SPL source authority is the vault;
- classic SPL payments use `TransferChecked` only; and
- classic mint ownership, canonical layout, initialized state, and decimals
  must match each `TransferChecked` instruction.

Required fresh simulation is the executable-state check for source and
destination token accounts. Safe Hands v0.1 does not claim a separate direct
source token-account decoder proof.

The proposal builder preserves the authorized inner instructions and account
metas unchanged. It does **not** rebind a personal-wallet draft to the vault
after authorization. Plain SPL `Transfer`, Token-2022, and every Squads
instruction inside the payment draft are hard-denied. The only Squads
instructions produced are the outer proposal instructions constructed after
independent authorization.

The output is the canonical full unsigned outer transaction containing the
Squads `vaultTransactionCreate` and `proposalCreate` instructions. The
Initiate-only proposer signs and submits that outer transaction; multisig
members separately approve and execute.

## Args

```json
{
  "transaction_base64": "canonical full unsigned vault-native transaction",
  "intent": {
    "action": "spl_transfer",
    "amount_raw": "25000000",
    "recipient": "9hSR…"
  },
  "decision_record": {
    "verdict": "ALLOW",
    "note": "audit context only; independently checked"
  },
  "memo": "optional proposal note"
}
```

## Config

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | yes (HTTPS) | Solana RPC for multisig state, ALT resolution, and evaluation |
| `squads_create_key` | yes | Public multisig create key used to derive Squads PDAs |
| `proposer` | yes | Member public key whose permissions are exactly `Initiate=1`, `Approve=0`, `Execute=0` |
| `squads_vault_index` | no | Vault index, default `0`; must match the vault used as builder `fee_payer` |
| `policy_json` | yes | Host-injected operator policy used for independent evaluation |

## Squads setup

1. Create or select the Squads multisig and vault index.
2. Derive the vault public key and use it as `spl-transfer-build.fee_payer`.
3. Add the proposer member with permission bits exactly **Initiate=1,
   Approve=0, Execute=0**. “Initiate plus another permission” is not accepted.
4. Configure the public create key, proposer key, vault index, and policy.
5. Keep all private keys and signer material outside plugin configuration.

## Worked flow

```text
builder   : canonical full unsigned vault-native payment draft
authorizer: ALLOW for those exact bytes and intent
proposer  : independent ALLOW; unchanged instructions embedded in an unsigned
            Squads proposal transaction
human     : Initiate-only account submits; multisig members approve/execute
```

The historical signatures in the root `EVIDENCE.md` predate the current
remediation and are not proof that the current exact artifacts exercised these
invariants. A fresh live run and recording are required.

From the repository root: build with
`cargo build --manifest-path plugins/squads-proposal-build/Cargo.toml --target wasm32-wasip2 --release`
and test with `cargo test --manifest-path plugins/squads-proposal-build/Cargo.toml`.
