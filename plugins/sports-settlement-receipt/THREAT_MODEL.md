# Threat model

## Objective and custody

Return `verified` only when a fresh authenticated TxLINE final-score proof and
an existing finalized Solana transaction bind the same fixture, sequence,
predicate, proof-derived instruction, daily PDA, and Boolean result through a
2-provider quorum. Otherwise return `unknown`.

This is T0. The plugin holds TxLINE/API and optional RPC access credentials,
but no wallet seed or signing key. It cannot sign or submit transactions and
never accepts arbitrary transaction bytes or RPC methods.

## Trust boundaries

- **ZeroClaw host:** injects jailed config and enforces `http_client` and
  `config_read`. A compromised host is out of scope.
- **TxLINE:** authenticates the proof but may omit, delay, or misreport data.
  Fixture, fixed stat keys, period, values, timestamps, and proof structure are
  checked. Sequence is bound by the authenticated URL and finalized memo.
- **RPC providers:** may lie, lag, truncate history, or disagree. Distinct
  hosts and 2-of-3 fingerprint quorum reduce one-node failure. Any explicit
  contradiction wins; common-mode collusion remains possible.
- **Solana/TxLINE programs:** runtime or program bugs and upgrades are outside
  scope. The fixed IDs and instruction bytes require a plugin update on change.
- **Downstream consumer:** owns identity, replay, dispute, approval, and funds
  policy. The receipt itself authorizes nothing.

## Principal controls

| Threat | Control | Residual risk |
|---|---|---|
| Prompt-selected key, endpoint, RPC method, or raw transaction | Closed schema, denied unknown fields, operator-only config, fixed request builders | Compromised host |
| Credential exfiltration | HTTPS operator origins; secrets excluded from schema, output, and structured logs | Malicious operator configuration |
| Wrong or running score | Fixture equality, keys 1/2, bounded values, both periods exactly 100 | Legacy response omits action/status ID |
| Proof or market substitution | Fresh Borsh bytes and PDA rebuilt locally and matched byte-for-byte on chain | TxLINE/program bugs |
| Unrelated transaction replay | First signature, exact five-key layout, three instructions, strict memo fixture/sequence/predicate, return program/value | Downstream still needs replay policy |
| Failed transaction presented as success | Finalized status, matching slot/meta fingerprints, and `meta.err: null` | Common-mode RPC collusion |
| RPC disagreement | Any intra- or cross-provider contradiction => `unknown`; two complete matches required | Two colluding providers |
| Context/memory exhaustion | Response, proof, wire, return-data, instruction, and output caps; deadlines; no retry | Bounded availability loss |
| Accidental funds action | No private-key type, signer, transaction builder input, or `sendTransaction` branch | Host compromise |

## Failure policy

Transport errors, stale/non-final status, missing archival transaction, malformed
JSON/wire data, signature mismatch, program/account/instruction/memo/return-data
mismatch, or insufficient quorum all produce a stable reason code inside:

```json
{
  "version": "sports-settlement-receipt-v1",
  "verdict": "unknown",
  "settlement_ready": false,
  "transaction_submitted_by_plugin": false
}
```

There is no cached value, best-effort majority over a contradiction, guessed
outcome, automatic credential refresh, or provider fallback.
