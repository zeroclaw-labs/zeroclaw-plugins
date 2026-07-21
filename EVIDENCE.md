# On-chain evidence (Solana devnet, 2026-07-20)

The complete Safe Hands path, proven end-to-end with real signatures and real
lamports. Every link is independently verifiable on any devnet explorer.

## Chain of transactions

| Step | Signature |
|---|---|
| Multisig created (1 member, threshold 1) | `2xZf8s5NMWB5U8xBym5XcBWMsEZC7GTz8A271tiSKicpwoQKH6rZaitk1avDwA3b5tf9EUv9zdssv3cecGyRT3TH` |
| Vault funded (0.15 SOL) | `2FSj9nsx71Tr4s7HfMCU7rzLFnjgpEvQcQZ3JV42VtahnWdVk3SVDCtuHNZFNXpo3pbgepA9YPbA7LRuJVYCy98A` |
| **Safe Hands proposal submitted** (built by our component) | `nc3pUFa4ELDJBde8XiHpEqWaqWMqnuQWfMM6A521WMj37LE3RfcEw3Vqfqy4rmLMBCnD33QRpkdVXX1Wu7DLu8b` |
| Proposal approved (member, from own wallet) | `L25eLjb8tP4vSB7mGTZaDWmtdw75tnyhQ6njSd2KfBu95cEPKeoD1L48hzKwzTcuWC2VoVkNgBNuXQPqBM6CR3k` |
| **Vault executed — 0.05 SOL paid out** | `4frEaEqV7mmGwQYeGWaiHkqRDrqyqrNhHhbnEKU5oEBGUCQffKZDoGafbS4sWZGe361F7gTvEQEDeoJCVq5R5jLs` |

## Accounts

- Multisig PDA: `7jmBsJmAV5aAwEQkw3AybYgTMHVUzbWgWMGvyMjhSEDQ`
- Vault PDA (index 0): `46t5cnapyYC1RNVCgezqxNssv65qnF3FgddyG86egHL1`
- Proposal PDA #1: `AN41Vs9C4fPfhks89jJ7wUj5gxesvuw9gqyLx4F4UnTN`
- create_key: `J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf`
- Proposer/member (demo): `5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf`

## The flow that produced it (all in a real ZeroClaw agent)

1. `spl-transfer-build` built the unsigned 0.05-SOL transfer.
2. `solana-tx-authorize` simulated + policy-checked it → **ALLOW**
   (an earlier attempt was **DENY** with `SH-INTENT-MATCH-030` — intent
   binding caught a malformed declaration, fail-closed as designed).
3. `squads-proposal-build` **independently re-authorized** against operator
   policy (never trusting the prior verdict) and built the unsigned
   Squads v4 proposal.
4. A human (demo key) signed + submitted, approved from their own wallet,
   and the multisig executed the payment. Destination balance verified:
   68.382979804 → 68.432979804 SOL (+0.05).

The agent never held a key.
