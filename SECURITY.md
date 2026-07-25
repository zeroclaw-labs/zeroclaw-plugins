# ProofKiosk — security & third-party trust model

ProofKiosk handles real money and drives real hardware. This document states
exactly what the system trusts, what it does not, and the invariants that hold
even against a fully compromised agent.

## Key custody

- **The agent never holds a spendable key.** None of the three plugins sign a
  transaction or hold private key material of any kind.
  - `kiosk-charge` (T1) builds a Solana Pay URL; the **customer's own wallet**
    signs the payment.
  - `kiosk-watch` (T0) only *reads* the chain.
  - `kiosk-attest` (T1) emits an **unsigned** transaction for an external
    operator signer; it attaches zero signatures.
- Recipient, mint, prices, RPC endpoint, nonce account/authority, and metric
  bounds are all **operator config** (`__config`), never model input. The model
  can choose only an item/amount (charge), a reference/amount (watch), or a
  bounded reading/event (attest).

## What ProofKiosk TRUSTS

1. **The operator's chosen Solana RPC endpoint** (`rpc_url`). `kiosk-watch` and
   `kiosk-attest` believe the chain state this endpoint reports. Point it at an
   endpoint you trust (your own validator, or a reputable provider). A malicious
   RPC could lie about whether a payment landed — so the operator, not the model,
   configures it, and `finality = confirmed`/`finalized` raises the bar.
2. **The operator's own config values** — a wrong `merchant_address` sends funds
   to the wrong (operator-chosen) place; it cannot be redirected by the model.

## What ProofKiosk does NOT trust or require

- **No payment facilitator / no x402.** Funds move customer-wallet → merchant
  directly. There is no third party in the money path.
- **No MCP server, no external oracle, no price feed** in the trust path. The
  optional fiat label (`display_currency`) is a *static, operator-set* rate used
  only for a cosmetic display string — the on-chain amount is always the USDC
  figure and is what is verified.
- **No custodial service, no bridge, no swap.**
- **The LLM/agent is not trusted.** Every model-facing argument surface uses
  `serde(deny_unknown_fields)` plus an explicit raw-key allowlist, so a smuggled
  `recipient`/`mint`/`nonce_authority` fails closed before any logic runs.

## Invariants (each is a host test)

- **Funds cannot be redirected.** The charge recipient and watch/attest addresses
  come only from config; no model input reaches them.
- **The relay fires only on a verified payment.** `kiosk-watch` returns
  `success = true` iff the exact amount reached the merchant at the configured
  finality. RPC failure, pending, mismatch, and replay all fail closed.
- **The attestation transaction cannot move funds.** It is built from exactly the
  Memo and System (advance-nonce) programs; a transfer is not expressible
  (`tx_contains_only_memo_and_system_programs`).
- **Fail closed on untrusted input.** RPC bodies, account data, and base58/base64
  strings are parsed without panicking; malformed input is always an error, never
  a silent success (property + fuzz tests in `crates/kiosk-core`).
- **No network where none is claimed.** `kiosk-charge` imports zero `wasi:http`,
  proven against the built binary by `scripts/verify-no-network.sh`.

## Residual risk (stated honestly)

- A charge for the *wrong catalog item* can be shown to a customer, who sees the
  amount in their own wallet before signing. Funds still cannot be redirected.
- The attestation chain is tamper-evident **ordering** (seq/prev back-reference),
  not a content-hash Merkle tree: an authorized signer could branch history. The
  tradeoff buys a self-contained design with no attestation-service program.

## Reporting

This is a hackathon submission. For security concerns, open an issue on the PR.
