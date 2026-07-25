# invoice-watch

Checks one open invoice against finalized chain evidence and tells the operator
what changed. It holds no keys and can call exactly one read-only tool, so the
worst outcome of a bad run is a wrong sentence, never a lost lamport.

The order to watch is supplied by the operator when the procedure is armed.

## Steps

1. **Check the order** — Call `payment-verify` with the watched `order_id` and
   its invoiced `amount_raw`. Nothing is stored anywhere, so this call
   re-derives the invoice reference and reads finalized evidence from both
   configured RPC endpoints. Report only the `status` field and, when present,
   the observed amount and signature.
   - tools: payment-verify

2. **Announce only on a change** — If `status` is `UNPAID`, stop silently: the
   operator does not need a message every two minutes. If it is `PAID`, post a
   short confirmation with the amount and signature. If it is `UNDERPAID`,
   `OVERPAID`, or `LATE`, post both the invoiced and the received amount and
   ask the operator what to do — never resolve it automatically. If it is
   `REVIEW`, post the reason and the signatures and say a human must inspect
   it. If it is `UNKNOWN`, say the check could not be completed and that this
   is **not** proof of non-payment; never report `UNKNOWN` as unpaid.
   - tools: channel_send
