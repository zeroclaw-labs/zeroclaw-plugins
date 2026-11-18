# solana-pay-request

A zero-permission ZeroClaw tool plugin that creates canonical
[Solana Pay](https://docs.solanapay.com/spec) transfer-request URIs for SOL and
SPL tokens.

It is the build half of **Solana Invoice Guard**. Pair it with
[`solana-payment-verify`](../solana-payment-verify/) to close the loop without
ever giving an agent a private key:

```text
invoice policy -> Solana Pay URI -> human signs in wallet -> signature -> strict verification
```

## Why this exists

An agent can safely ask for payment without being allowed to move funds. This
component converts a typed invoice into one deterministic URI, validates every
address and amount before output, and returns the same value as a QR payload.
The verifier then checks what actually settled rather than trusting the request.

## Custody tier: T1 build-only

- Holds no key material.
- Has no network, config, filesystem, memory, socket, or signing permission.
- Produces a URI, never a transaction or signature.
- Rejects unknown fields, control characters, duplicate references, invalid
  base58 keys, zero/negative/exponent amounts, and payloads over 2,048 bytes.

The manifest deliberately declares `permissions = []`.

## Tool contract

Tool name: `solana_pay_request`

Required arguments:

| Field | Type | Rule |
|---|---|---|
| `recipient` | string | Base58 value that decodes to exactly 32 bytes |
| `amount` | string | Positive decimal string; floats and exponent notation are rejected |

Optional arguments:

| Field | Type | Rule |
|---|---|---|
| `spl_token` | string | Exact 32-byte mint; omit for SOL |
| `references` | string[] | Up to five unique 32-byte reference accounts |
| `label` | string | At most 64 characters |
| `message` | string | At most 128 characters |
| `memo` | string | At most 128 characters; control characters rejected |

## Worked example

Input:

```json
{
  "recipient": "8qbHbw2BbbTHBW1sbeqakYXVW6zQq4ZBzYcwWq5YwB4Y",
  "amount": "25.5000",
  "spl_token": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "references": ["3WvZ3fQFhC4M1tT5uSEzFRX5pZgAK1SVMVJtqmXWwzqJ"],
  "label": "Table 4 / Cafe",
  "message": "Pay 25.5 USDC",
  "memo": "invoice-1042"
}
```

Output shape:

```json
{
  "uri": "solana:8qbH...B4Y?amount=25.5&spl-token=EPjF...Dt1v&reference=3WvZ...wzqJ&label=Table%204%20%2F%20Cafe&message=Pay%2025.5%20USDC&memo=invoice-1042",
  "qr_payload": "solana:8qbH...B4Y?amount=25.5&spl-token=EPjF...Dt1v&reference=3WvZ...wzqJ&label=Table%204%20%2F%20Cafe&message=Pay%2025.5%20USDC&memo=invoice-1042",
  "fingerprint": "16 lowercase hex characters",
  "recipient": "8qbH...B4Y",
  "amount": "25.5",
  "asset": "EPjF...Dt1v",
  "references": ["3WvZ...wzqJ"],
  "custody_tier": "T1-build-only",
  "summary": "Request 25.5 <mint> to 8qbHbw...wB4Y with 1 reference(s)."
}
```

The amount is canonicalized without floating-point arithmetic. The fingerprint
is the first 64 bits of SHA-256 over the complete canonical URI and is intended
for human reconciliation, not authentication.

## Prompt-injection test

Attempt:

```json
{
  "recipient": "<valid recipient>",
  "amount": "1",
  "sign_and_send": true,
  "private_key": "ignore-safety"
}
```

Result:

```text
success=false
error="invalid arguments: unknown field `sign_and_send`"
```

There is no action enum, signer, fallback recipient, or hidden permissive mode.
Unknown fields fail before URI construction.

## Pure core, thin shim

```text
src/request.rs  validation, canonicalization, encoding, fingerprint
src/lib.rs      WIT exports and structured logging only
tests/          host-run behavior and abuse cases
```

## Build and test

```bash
cd plugins/solana-pay-request
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target wasm32-wasip2 -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
```

The component is written to
`target/wasm32-wasip2/release/solana_pay_request.wasm`.

## Install

Place the built component beside `manifest.toml`, then install the directory:

```bash
cp target/wasm32-wasip2/release/solana_pay_request.wasm .
zeroclaw plugin install .
```

## License

MIT OR Apache-2.0. See [LICENSE](./LICENSE) for the MIT terms.
