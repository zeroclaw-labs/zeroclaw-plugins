# solana-payment-verify

A read-only ZeroClaw tool plugin that verifies whether a finalized or confirmed
Solana transaction satisfies a strict invoice policy.

It is the verification half of **Solana Invoice Guard**. Pair it with
[`solana-pay-request`](../solana-pay-request/) for an agent payment flow in
which a human wallet remains the only signer.

## The problem

Finding a signature is not proof that an invoice was paid. A transaction may:

- fail on chain;
- pay the wrong recipient or mint;
- be underpaid or unexpectedly overpaid;
- omit the Solana Pay reference used for reconciliation;
- contain the wrong memo;
- exist only below the operator's required commitment.

This plugin checks the transaction result and computes the recipient's actual
post-balance minus pre-balance. It does not trust a claimed instruction amount.

## Custody tier: T0 read-only

- Holds no private key and exposes no signing or submission path.
- Calls exactly one operator-selected Solana JSON-RPC endpoint over HTTPS.
- Defaults to `finalized`; `confirmed` must be selected by operator config.
- Treats missing, malformed, failed, or mismatched transactions as unpaid.
- Rejects SOL verification when the recipient is also the fee payer, because
  fees make the net balance delta ambiguous.

Permissions are limited to `http_client` and `config_read`.

## Verification policy

The tool requires these fields:

| Field | Rule |
|---|---|
| `signature` | Base58 value decoding to exactly 64 bytes |
| `recipient` | Base58 wallet decoding to exactly 32 bytes |
| `amount` | Positive decimal string, converted to raw units without floats |
| `asset` | Literal `SOL` or an exact 32-byte SPL mint |

Optional policy fields:

| Field | Rule |
|---|---|
| `reference` | Exact account key that must occur in the transaction |
| `memo` | Exact text from an SPL Memo instruction |
| `amount_policy` | `exact` (default) or `at_least` |

For SOL, the observed amount is the recipient's lamport increase. For SPL and
Token-2022 assets, it is the sum of raw token-balance increases for accounts
owned by the recipient and matching the exact mint. This means transfer fees
are handled as net received: the invoice is valid only if the recipient's
actual balance increase satisfies the policy.

## Output

The tool returns a compact JSON report:

```json
{
  "valid": true,
  "status": "paid",
  "signature": "<signature>",
  "slot": 321,
  "recipient": "<recipient>",
  "asset": "SOL",
  "expected_amount": "1.25",
  "observed_amount": "1.25",
  "amount_policy": "exact",
  "reference_matched": true,
  "memo_matched": true,
  "checks": [
    "transaction_succeeded",
    "recipient_matched",
    "amount_matched",
    "reference_matched",
    "memo_matched"
  ],
  "summary": "Verified 1.25 SOL received by 8qbHbw...wB4Y."
}
```

`success=true` means the tool call completed. Downstream automation must use
`valid` or `status == "paid"` as the payment decision. A mismatched transaction
is a normal, structured result rather than a component fault.

## Live mainnet check

The same release component was exercised through the real ZeroClaw host against
`https://solana-rpc.publicnode.com` at `finalized` commitment. The successful
case is publicly reproducible at
[`2BwJJ2vHxqHuRJLa2W3aTu9SqLsqqSAiRuiDUf1yGVYkSeyEyry7HdwBvLxaFC9LUMk2oWpqSxeZGz9ioqXWqJxX`](https://solscan.io/tx/2BwJJ2vHxqHuRJLa2W3aTu9SqLsqqSAiRuiDUf1yGVYkSeyEyry7HdwBvLxaFC9LUMk2oWpqSxeZGz9ioqXWqJxX):

```text
status: paid
valid: true
observed amount: 0.0013 SOL
recipient: 2c8efKRr1x2APVrL5rResqAGZSFxSvC4mE8XsVs9PsSu
slot: 434260296
```

The adversarial mainnet check used a transaction whose transfer instruction
claimed `1.446010628 SOL`, while the recipient's finalized net balance delta
was zero. The verifier returned `mismatch` and never treated the instruction's
claimed amount as payment. The deterministic test suite also covers failed
transactions, wrong recipients, missing references/memos, underpayment,
overpayment, prompt-injection fields, unsafe RPC endpoints, and malicious
token precision.

## Configuration

ZeroClaw injects this plugin's jailed config section as `__config`. A caller
cannot supply or replace it.

| Key | Default | Rule |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Public HTTPS endpoint, no credentials/query/fragment, max 512 characters |
| `commitment` | `finalized` | `finalized` or `confirmed` |
| `timeout_secs` | `10` | Integer from 1 to 30 |

Example plugin entry:

```toml
[[plugins.entries]]
name = "solana-payment-verify"
enabled = true

[plugins.entries.config]
rpc_url = "https://api.devnet.solana.com"
commitment = "finalized"
timeout_secs = "10"
```

## Threat model

### Protected against

- LLM-supplied unknown override fields (`#[serde(deny_unknown_fields)]`).
- Floating-point rounding and exponent notation.
- Wrong recipient, mint, reference, or memo.
- Failed, missing, underpaid, or malformed transactions.
- Caller-controlled RPC endpoints: the host strips caller `__config` before
  injecting the operator's config.
- Local metadata endpoints and plaintext RPC transport: credentials,
  localhost/reserved domains, private or special-purpose IP literals, and
  non-HTTPS URLs are rejected.
- Malicious token precision values: SPL decimals above the largest safe `u64`
  decimal scale (19) fail closed.

### Trusted boundary

The configured RPC provider is trusted to report canonical chain state. The
plugin does not implement an independent light client or multi-RPC quorum. An
operator requiring that property should point it at a trusted gateway or run
multiple checks outside this stateless component.

### Intentionally unsupported

- Signing, submitting, simulating, or altering transactions.
- Versioned transactions newer than version 0.
- A SOL recipient that is also the fee payer.
- Fuzzy memo matching or recipient/mint aliases.
- Amounts above `u64` raw units.

## Prompt-injection test

Attempt:

```json
{
  "signature": "<valid signature>",
  "recipient": "<invoice recipient>",
  "amount": "10",
  "asset": "SOL",
  "recipient_override": "<attacker wallet>",
  "ignore_previous_invoice": true
}
```

Result:

```text
success=false
error="invalid arguments: unknown field `recipient_override`"
```

No field can disable recipient, amount, transaction-success, reference, or memo
checks. The component has no action enum and no fund-moving capability.

## Pure core, thin shim

```text
src/verify.rs  validation, decimal math, RPC JSON parsing, balance-delta checks
src/lib.rs     WIT exports, one HTTPS RPC call, structured logging
tests/         host-run SOL, SPL, malformed, and adversarial cases
```

The host tests use Solana RPC-shaped fixtures and exercise the exact core called
by the WebAssembly shim. No live endpoint is needed for deterministic CI.

## Build and test

```bash
cd plugins/solana-payment-verify
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target wasm32-wasip2 -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
```

The component is written to
`target/wasm32-wasip2/release/solana_payment_verify.wasm`.

## Install

Place the built component beside `manifest.toml`, then install the directory:

```bash
cp target/wasm32-wasip2/release/solana_payment_verify.wasm .
zeroclaw plugin install .
```

## License

MIT OR Apache-2.0. See [LICENSE](./LICENSE) for the MIT terms.
