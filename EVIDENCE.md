# Historical on-chain record (Solana devnet, 2026-07-20/21)

> **Pre-remediation demo only.** The signatures below are preserved unchanged
> as historical records from an earlier demo. They show that the listed devnet
> transactions and account changes occurred, but they are **not proof that the
> current exact staged artifacts ran**, nor that the current implementation
> enforced every v0.1 invariant. Fresh live validation and a new recording of
> the exact release artifacts are required before making that claim.

## Chain 1 — SOL (0.05 moved from the multisig vault)

| Step | Signature |
|---|---|
| Multisig created (1 member, threshold 1) | `2xZf8s5NMWB5U8xBym5XcBWMsEZC7GTz8A271tiSKicpwoQKH6rZaitk1avDwA3b5tf9EUv9zdssv3cecGyRT3TH` |
| Vault funded (0.15 SOL) | `2FSj9nsx71Tr4s7HfMCU7rzLFnjgpEvQcQZ3JV42VtahnWdVk3SVDCtuHNZFNXpo3pbgepA9YPbA7LRuJVYCy98A` |
| **Safe Hands proposal submitted** | `nc3pUFa4ELDJBde8XiHpEqWaqWMqnuQWfMM6A521WMj37LE3RfcEw3Vqfqy4rmLMBCnD33QRpkdVXX1Wu7DLu8b` |
| Proposal approved | `L25eLjb8tP4vSB7mGTZaDWmtdw75tnyhQ6njSd2KfBu95cEPKeoD1L48hzKwzTcuWC2VoVkNgBNuXQPqBM6CR3k` |
| **Vault executed — 0.05 SOL paid out** | `4frEaEqV7mmGwQYeGWaiHkqRDrqyqrNhHhbnEKU5oEBGUCQffKZDoGafbS4sWZGe361F7gTvEQEDeoJCVq5R5jLs` |

Destination balance recorded at the time: 68.382979804 → 68.432979804 SOL
(+0.05).

## Chain 2 — SPL token (25 tokens moved from the multisig vault)

| Step | Signature / account |
|---|---|
| Demo token mint (6 decimals, devnet) | `xJoaZT3mVadxt2apoPjasDyA1byYcJ9VVZ6nj8Exj1h` |
| **Safe Hands proposal #2 submitted** | `3V1czaE9upxkBeNAYoK7Ywyeg3j2ssjeLH1cCce7PbpmMeNfwKMDW8CmBLVg7B2Gr8BNzrCLJV389HbTWvEBFsQS` |
| Proposal approved | `5EBzt9rKuvSz3np6ZAF4x61caLRLUSs2n57z3y1oRKBvSTNLFTAuVgQVQVnQNVv3tM6wrEc75GeeRUGU1uVbUTaH` |
| **Vault executed — 25 tokens paid out** | `48FXAQhucsVttuJMJbn8QRgnxiyQ3nrKzMGr9mK6HSJreAQDmJtZS8967Zw2YrdCocqDsMiAUYd21r7yHE9rpqaj` |

Vault ATA `4rVEeDWz8JsXiTnCH4XJ7poFAzZHxcpv9Wy7SN4ZbMyn`: 500 → 475 tokens.
Destination ATA `84bcNCcYGHVHcYV9VGPCGSqUXGh62ET66M4TFJ8Tgc4p`: 0 → 25 tokens.

## Accounts

- Multisig PDA: `7jmBsJmAV5aAwEQkw3AybYgTMHVUzbWgWMGvyMjhSEDQ`
- Vault PDA (index 0): `46t5cnapyYC1RNVCgezqxNssv65qnF3FgddyG86egHL1`
- Proposal PDAs: #1 `AN41Vs9C4fPfhks89jJ7wUj5gxesvuw9gqyLx4F4UnTN`, #2 `35BTqdTQsVrMLEtQo5uoC6Ji8h8Tpy8G18ZmWs2AbShY`
- create_key: `J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf`
- Proposer/member (demo): `5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf`

## Historically reported flow

The pre-remediation demo reported that:

1. `spl-transfer-build` produced unsigned SOL and SPL drafts;
2. `solana-tx-authorize` returned ALLOW after policy checks and simulation;
3. `squads-proposal-build` produced unsigned Squads v4 proposals; and
4. a human demo key submitted and approved them before multisig execution.

This section records what the earlier demo reported. It must not be used as
current exact-artifact implementation evidence. Re-run the staged v0.1
artifacts, capture their hashes and inputs, and record a fresh live session to
establish current proof.
