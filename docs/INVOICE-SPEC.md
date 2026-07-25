# Safe Hands invoice spec — stateless Solana Pay merchant desk

Status: v1, binding. Written before implementation; the fixtures in
`libs/safe-hands-core/src/invoice/tests.rs` are derived from this document.

## Why there is no database

A `wasm32-wasip2` tool component cannot persist a byte. The host builds its
WASI context with `WasiCtx::builder().build()` and preopens no directory, and
the `tool-plugin` world imports only `logging`. `file_read` / `file_write` exist
in `PluginPermission` but are wired to nothing.

That constraint is not worked around here, it is designed for. Every
safety-critical fact is re-derived from a source that is already trusted:

| Fact | Source of truth |
|---|---|
| Invoice reference | Derived deterministically from `(merchant, order_id, salt)` |
| Payment occurred, amount, payer | Finalized chain evidence, indexed by the reference |
| Refund destination | Host static policy (`allowed_recipients`), enforced independently by `solana-tx-authorize` |
| Double-refund prevention | Chain: a refund transfer for this reference either landed or did not |

No local record can desync from the chain, because there is no local record.
The LLM cannot override a stored refund destination, because none is stored:
the only destination that can pass is one the operator put in host config.

What this deliberately does not cover: an invoice that was created but never
paid leaves no on-chain trace, so open/expired invoices cannot be enumerated.
`invoice_check <order_id>` answers per order. A durable ledger is a later,
optional addition and must never become a dependency of the safety path.

## Reference derivation

```text
reference = find_program_address(
    [ b"safe-hands-invoice", merchant[..32], sha256(order_id)[..32], sha256(salt)[..32] ],
    REFERENCE_NAMESPACE,
)
```

- `order_id` and `salt` are hashed so any length is accepted while respecting
  the 32-byte seed limit.
- The result is off-curve by construction: no private key exists for it, so it
  can never sign, own, or hold anything. It is an index and nothing else.
- Deterministic: the same order re-derives the same reference, which is what
  removes the need to store it.
- `salt` comes from host config (`invoice_salt`). It only makes references
  unguessable; it is not a security boundary. A reference is public the moment
  the invoice is paid — it appears in the transaction account keys.

## Solana Pay URL

```text
solana:<merchant_owner>?amount=<decimal>&spl-token=<mint>&reference=<reference>[&label=][&message=][&memo=]
```

`amount` is decimal token units per the Solana Pay spec, converted from raw
smallest units by exact integer string manipulation. No floats appear anywhere
in this path. Trailing fractional zeros are trimmed; a whole amount emits no
decimal point.

Labels, messages and memos are untrusted operator/customer text. They are
percent-encoded, length-capped, and control characters are rejected.

## Payment verification contract

Evidence is read at `finalized` commitment only, from two independent RPC
endpoints that must agree. Anything unexplained fails closed.

### Procedure

1. `getSignaturesForAddress(reference, {commitment: "finalized"})`.
   Empty → `Unpaid`.
2. For each signature, `getTransaction(sig, {commitment: "finalized",
   encoding: "jsonParsed", maxSupportedTransactionVersion: 0})`.
3. Reject the transaction if `meta.err` is non-null.
4. Confirm the reference appears in the transaction account keys.
5. Read `meta.preTokenBalances` / `meta.postTokenBalances`. These carry the
   `owner` of every token account at execution time, which is what makes the
   payer attributable without a follow-up account fetch that could race a
   closed account.
6. The merchant ATA (`ata_address(merchant_owner, TOKEN_PROGRAM, mint)`) must
   show a positive delta in the expected mint. Absent pre-entry means zero.
7. Exactly one distinct owner may show a negative delta in that mint. Two or
   more → `Review(split_payment)`.
8. The transferring instruction's `authority` must equal that source owner —
   a delegate is not the payer, so a delegated transfer is `Review`.

   `multisigAuthority` is read as the authority when `authority` is absent.
   This is not a concession: Solana Pay attaches the reference as an extra
   account on the transfer, and the RPC's `jsonParsed` formatter therefore
   renders the *multisig* variant of `TransferChecked` — the real payer appears
   under `multisigAuthority`, and the reference is listed under `signers`
   despite signing nothing. Rejecting that shape would reject every correctly
   formed Solana Pay payment. A genuine SPL multisig is still refused at step
   9, because a Multisig account never appears in a transaction's signer list.
9. That owner must appear as a signer in the transaction.
10. Compare observed against requested amount, and `blockTime` against expiry.

### Verdicts

| Verdict | Condition |
|---|---|
| `Unpaid` | No finalized signature references this invoice |
| `Paid` | Exactly one owner-signed classic SPL transfer of the exact amount, on time |
| `Underpaid` / `Overpaid` | Amount mismatch, both amounts reported, never auto-resolved |
| `Late` | Exact amount, but `blockTime` is after expiry |
| `Review(reason)` | Split, delegated, multi-owner, ambiguous, or duplicate payment |
| `Unknown(reason)` | RPC error, malformed envelope, or primary/fallback disagreement |

**Lateness never masks the amount.** A payment can be both late and the wrong
amount, so `late` is a field on the evidence rather than a verdict that
replaces the amount comparison. Telling a merchant only "LATE" about a payment
that was also short would let them ship goods they were not paid for.

A non-positive `expiry_unix` means no expiry. Models emit `0` as a stand-in for
"none", and honouring it as a 1970 deadline marks every payment late.

`Unknown` and `Review` are terminal for automation: neither may produce a
refund proposal. Only `Paid`, `Overpaid` and `Late` describe money actually
received, and each names its exact observed amount.

### Rejected by construction

- **Token-2022** — the mint is validated with `fetch_classic_mint_decimals`,
  which requires the mint account owner to be the classic SPL Token program.
  A Token-2022 mint cannot reach the amount comparison at all.
- **Delegated authority** — step 8.
- **Multiple source owners / split payments** — step 7.
- **Wrong mint, recipient, or reference** — steps 4 and 6.
- **Failed transactions** — step 3.
- **Unfinalized evidence** — commitment is pinned at every call site.
- **A single lying RPC** — both endpoints must produce the same verdict.

### Duplicate payments

If more than one finalized transaction satisfies every check, the result is
`Review(duplicate_payment)` carrying all signatures. The merchant decides.
Silently accepting the first would make the second unaccounted-for money.

## Refund path

Unchanged from the existing, already-proven pipeline:

```text
payment-verify (observed amount, payer owner)
  -> spl-transfer-build      canonical unsigned transfer
  -> solana-tx-authorize     independent exact-byte decode against host policy
  -> squads-proposal-build   independent re-authorization, unsigned proposal
  -> human approval + execution in Squads
```

The payer owner reported by verification is evidence, not authorization. A
refund reaches the chain only if that address is already in the operator's
static `allowed_recipients`. Verification never widens policy.
