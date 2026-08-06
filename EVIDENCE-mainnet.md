# Mainnet, without spending anything

`just mainnet-check` — the real pipeline against `api.mainnet-beta.solana.com`.

Safe Hands is T0/T1, so its output is an *unsigned* transaction. That is why
this costs 0 SOL: correctness on mainnet can be established without ever
funding anything. Only the signing step is absent, and no component here holds
a key to perform it.

```text
  SAFE HANDS — mainnet reality check
  rpc: https://api.mainnet-beta.solana.com
  No key is held and nothing is signed, submitted, or spent.

  chain      genesis 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
             mainnet-beta confirmed
             slot 437491470

  USDC mint  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
             owner TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
             82 bytes, decimals 6 — classic SPL Token, as expected

  BUILD      spl-transfer-build, against mainnet state
             1.000000 USDC → 9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu
             destination ATA ASZ2TDDNJG2n42TxAezqNNzwWipykHrENDKMCoLKgzup
             444 bytes, unsigned=true

  AUTHORIZE  solana-tx-authorize, real mainnet simulateTransaction
             verdict      ALLOW
             reason codes []
             decision id  sha256:3ba78756a75141225fbaace341fece314409bc6df9e35edb586a94156e19912c

  REFUSE     same builder, same mainnet, unlisted recipient 5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9
             built=false — builder refused: policy returned DENY (SH-DENY-RECIPIENT-003)

  WHAT THIS SHOWS
    Reads, mint decode, ATA derivation and transaction construction all
    ran against mainnet-beta. The transaction above is mainnet-valid and
    unsigned, and the ALLOW came from a real simulateTransaction against
    real mainnet state — not a fixture.

    The same builder, on the same chain, refused a recipient the operator
    never listed. The allowlist is not advice the model may weigh.

    Signing is the one step absent, and it is absent by design: nothing
    here holds a key. That is also why this check costs 0 SOL — a T1
    system can be proven correct on mainnet without ever spending on it.

```

## What is actually established

| | |
|---|---|
| The chain is mainnet | genesis `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`, checked, not assumed |
| The mint decoder works on real state | USDC read at finalized commitment, 82 bytes, decimals 6, owner is the classic token program |
| The builder emits mainnet-valid bytes | 444-byte versioned transaction, ATA derived on chain-real inputs, `unsigned=true` |
| The authorizer decides on real evidence | ALLOW from a live `simulateTransaction`, with a `decision_id` that re-derives |
| The allowlist holds on mainnet too | same builder, same chain, unlisted recipient → `SH-DENY-RECIPIENT-003` |

## What is not established

No mainnet transaction has been signed, submitted, or executed by this project,
and none will be by the code in it. The executed end-to-end record — proposal,
human approval, payout — is on devnet and is in [`EVIDENCE.md`](EVIDENCE.md).
See the mainnet-readiness gates in the README for what would have to be true
before real funds belong anywhere near this.
