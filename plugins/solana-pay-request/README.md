# solana-pay-request

**Tier 1 (build-only, zero secrets)** tool plugin for ZeroClaw: build Solana Pay
transfer-request URLs and QR-ready payloads — recipient, amount, SPL mint, memo,
reference keys, label, message.

Turns any ZeroClaw agent on Telegram/WhatsApp into a payment terminal:

```
user:  "charge table 4 for 25 USDC"
agent: solana-pay-request(recipient=Cafe…, amount=25, mint=USDC,
                          memo="Invoice #412", label="Café Sol")
       → {"url": "solana:Cafe…?amount=25&spl-token=EPjF…&memo=Invoice%20%23412…",
          "qr_payload": "…", "summary": "Charge 25 SPL to Cafe… — memo: Invoice #412"}
host:  renders qr_payload as a QR in the chat; the customer scans, their wallet signs
agent: payment-watch(address, 25, mint=USDC, reference="Invoice #412") → confirms
```

## Custody tier: T1 — the safest tier that can move money at all

This plugin **performs no network I/O and holds no key material of any kind** —
not even an RPC key. Its `manifest.toml` declares **zero permissions**. It emits
a URL; the payer's own wallet (a human, on their phone) builds and signs the
transaction. There is no agent-side key to prompt-inject, exfiltrate, or drain:
money moves only when a *customer's* wallet approves, which is outside the
agent's trust boundary entirely.

Paired with `payment-watch` (T0) for settlement confirmation, the full
charge-and-confirm loop runs with **no private key anywhere in the agent stack**.

## What it does

- Implements the Solana Pay transfer-request URL spec:
  `solana:<recipient>?amount=<n>&spl-token=<mint>&reference=<k>&label=&message=&memo=`
- Amount formatting per spec: plain decimal, no exponent, no trailing zeros
- RFC 3986 percent-encoding for memo/label/message (UTF-8 safe: "Café Sol" → `Caf%C3%A9%20Sol`)
- Base58 shape validation on recipient / mint / references (rejects garbage
  before a URL ever reaches a payer)
- Multiple reference keys, order-preserved, for `payment-watch` reconciliation

## Tool schema

| arg | type | required | notes |
|---|---|---|---|
| `recipient` | string | ✓ | receiving address (base58) |
| `amount` | number | ✓ | SOL or SPL ui amount, > 0 |
| `mint` | string | | SPL mint; omit or `"SOL"` for native |
| `memo` | string | | on-chain memo, e.g. `"Invoice #412"` |
| `reference` | string[] | | reference pubkey(s) for watch reconciliation |
| `label` | string | | merchant name for payer UI |
| `message` | string | | charge description for payer UI |

## Permissions

None. (`http_client` is not needed — construction is pure string work.)

## Engineering notes

Pure core (`src/solana_pay_request.rs`), zero wasm imports, host-tested: 9 tests
covering spec URL construction, amount formatting, SPL vs native, encoding,
reference ordering, and input rejection. CI-validated with
`tools/ci/validate_components.sh solana-pay-request`: tests 9/9, clippy clean
(host + wasm), artifact `solana_pay_request.wasm`.
