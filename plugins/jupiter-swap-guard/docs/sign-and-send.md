# Signing and sending a `jupiter-swap-guard` transaction

This plugin returns an **unsigned** transaction. It never holds a key, never
signs, and never broadcasts. You sign it out of band, after reviewing the decoded
bytes.

> **Verify the decoded transaction, not the chat summary.** The plugin's summary
> reaches you through the agent's LLM, which can be prompt-injected into rewriting
> it. The only thing that cannot be tampered with is the transaction bytes — so
> the safety guarantees live there, and you confirm them by decoding the tx, not
> by trusting the chat. This is the whole point of the T1 design.

## 1. Get the unsigned transaction

`execute` returns JSON:

```json
{
  "summary": "SWAP (unsigned — requires your signature) …",
  "unsigned_tx_b64": "AQAAA…",
  "guard": { "min_out": "…", "priority_fee_lamports": "…", "output_ata": "…", … }
}
```

Do **not** copy `unsigned_tx_b64` out of a chat window — LLMs corrupt long base64.
Read it from the ZeroClaw audit/log trail, or re-run the tool from an interactive
CLI session so the value is exact.

## 2. Decode and verify it before signing

```bash
# Decode the base64 and inspect the message the way the network will read it.
echo "$UNSIGNED_TX_B64" | base64 -d > /tmp/swap.tx
solana decode-transaction < /tmp/swap.tx    # or your wallet's "view decoded" screen
```

Confirm, against the decoded transaction (not the summary):

- the **fee payer / only signer** is your wallet;
- the swap's writable destination is **your own** associated token account for the
  output mint (the `guard.output_ata`);
- there is no lamport transfer to an address you do not control;
- the priority fee matches `guard.priority_fee_lamports`.

The plugin already enforced all of these before emitting the bytes; this step is
your independent confirmation.

## 3. Sign and send

Recommended: a **Squads** multisig — the agent proposes, a human approves from
their phone, the agent never holds a key at all. The plugin emits the transaction;
you submit it as a Squads proposal and approve it.

Or, for a single-signer wallet:

```bash
solana sign-offchain-message  # if your flow separates signing
# or, with the fee-payer keypair on an air-gapped/hardware signer:
solana send-transaction /tmp/swap.tx --signer <your-keypair-or-ledger>
```

## Blockhash expiry

An unsigned transaction sitting in an approval queue can outlive its blockhash
(~60–90 s). If signing is delayed, re-run the tool to rebuild against a fresh
blockhash, or configure the plugin's `nonce_account`/`nonce_authority` to use a
durable nonce so the transaction stays valid until you sign.

## Cluster

A Jupiter swap references mainnet-only programs and pools, so it lands on
**mainnet** (or a mainnet **fork** such as surfpool for testing) — never plain
devnet. The plugin's `expected_genesis_hash` pin guards against pointing it at the
wrong cluster by mistake.
