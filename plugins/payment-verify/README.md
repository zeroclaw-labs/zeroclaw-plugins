# payment-verify

Confirms whether a Solana Pay invoice was paid, using only **finalized** chain
evidence read from **two independent RPC endpoints that must agree**.

**Custody tier: T0 — read only.** It holds no keys, moves no funds, and
authorizes nothing.

The reference is re-derived from the order id, so verification needs no record
that the invoice was ever created.

## Args

```json
{
  "order_id": "A-1042",
  "amount_raw": "25000000",
  "expiry_unix": 1700000000
}
```

## Verdicts

| Status | Meaning |
|---|---|
| `UNPAID` | No finalized transaction references this invoice |
| `PAID` | Exactly one owner-signed classic SPL transfer of the exact amount |
| `UNDERPAID` / `OVERPAID` | Amount mismatch; both amounts reported, never auto-resolved |
| `LATE` | Exact amount, but finalized after `expiry_unix` |
| `REVIEW` | Money moved but is not attributable to one owner-signed transfer |
| `UNKNOWN` | Evidence could not be trusted |

Lateness never replaces the amount: a payment that is both late and the wrong
amount reports `UNDERPAID`/`OVERPAID` with a `late` flag, because telling a
merchant only "late" would hide that they were short-paid.

**`UNKNOWN` is not proof of non-payment.** It means the verifier refused to
claim anything in either direction. Treating it as `UNPAID` is the mistake this
distinction exists to prevent, and the tool says so in its own output.

## How a payment is proven

1. `getSignaturesForAddress(reference)` at `finalized`.
2. `getTransaction` at `finalized`, `jsonParsed`.
3. `meta.err` must be null.
4. The reference must be in the transaction's account keys.
5. `meta.pre/postTokenBalances` give the **owner** of every token account at
   execution time — that is what makes the payer attributable without a
   follow-up account fetch that could race a closed account.
6. The merchant ATA must show a positive delta in the expected mint.
7. Exactly one distinct owner may show a negative delta.
8. The instruction `authority` must equal that owner — a delegate is not the
   payer. `multisigAuthority` is read as the authority when `authority` is
   absent: attaching the reference makes the RPC render the multisig variant of
   `TransferChecked`, with the real payer under `multisigAuthority` and the
   reference listed as a "signer" despite signing nothing. Rejecting that shape
   would reject every correctly formed Solana Pay payment.
9. That owner must have signed the transaction. This is what still refuses a
   genuine SPL multisig, whose Multisig account never appears in the signer
   list.

## Threat model

**One endpoint is not evidence.** The plugin refuses to run with a single RPC
configured. Both endpoints are queried independently and must produce the same
verdict; disagreement is `UNKNOWN`, never a merge of the two answers. A single
compromised, lagging, or lying endpoint cannot mark an invoice paid.

**Token-2022 cannot reach the amount comparison.** The mint is validated with
the same classic-SPL layout proof used elsewhere in Safe Hands, so a
transfer-hook or fee-on-transfer mint fails before any amount is compared.

**A delegate is not the payer.** A delegated transfer is `REVIEW`, because
refunding the delegate would send money to an address the customer does not
control. This is the attack the design exists to stop.

**Split and multi-owner payments are `REVIEW`.** Two funding owners make the
payer ambiguous, so the verdict refuses to pick one.

**Duplicate payments are `REVIEW`, listing every signature.** Silently
accepting the first would leave the second as unaccounted-for money.

**Griefing is bounded.** Anyone can attach an invoice reference to an unrelated
transaction. A transaction that does not credit the merchant in the expected
mint is ignored rather than escalated, so a flood cannot force every invoice
into manual review. A flood large enough to exceed the signature cap is
reported explicitly rather than silently truncated.

**A reported payer is evidence, not authorization.** The field is deliberately
named `payer_owner_evidence`, and the output states that a refund is only
possible if the operator has already placed that address in
`allowed_recipients`. `solana-tx-authorize` re-checks that independently
against host policy. This tool cannot widen policy and never sees a key.

**`merchant_owner`, `invoice_salt` and the settlement mint are host-only.** A
prompt cannot make the verifier check a reference the operator never issued,
and there is no `mint` argument at all — a merchant settles in one configured
currency. A live run had a model invent a mint address; if the LLM could choose
it, an injection could invoice a customer in a worthless lookalike token.

**A reference attached to an unrelated transaction is ignored, not escalated.**
References are public. A transaction that does not credit the merchant in the
expected mint is skipped, so a flood of them cannot force every invoice into
manual review.

## Config

| Key | Purpose |
|---|---|
| `merchant_owner` | The merchant wallet. **Host-only.** |
| `invoice_salt` | Makes references unguessable. Keep it stable forever — changing it re-derives every reference and orphans open invoices. **Host-only.** |
| `default_mint` | The merchant's settlement mint. There is no caller override. **Host-only.** |
| `rpc_url` | Primary endpoint |
| `rpc_url_fallback` | Independent second endpoint. **Required.** |

Use two genuinely different providers. Two URLs pointing at the same backend
satisfy the check without providing the independence it exists to buy.
