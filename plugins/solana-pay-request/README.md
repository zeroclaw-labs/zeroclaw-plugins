# solana-pay-request

`solana-pay-request` is a **T1 (Build)** ZeroClaw tool. Given a recipient,
exact decimal amount, SPL mint, optional memo, and required reference public
key, it returns a standards-compatible `solana:` transfer URL and an identical
QR-ready payload. A wallet performs the separate transaction construction,
approval, signing, and submission.

## Safety and custody

The component has no permissions, network access, configuration access, or
secrets. It cannot hold a private key or send money. It validates all supplied
public keys and accepts the amount as a decimal string so it never rounds money
through a floating-point value.

## Example

```json
{
  "recipient": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "amount": "25.0",
  "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "memo": "Table 4 / Invoice #412",
  "reference": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
}
```

The result includes `solana_pay_url` and `qr_payload`, such as
`solana:...?...`; pass `qr_payload` directly to a chat QR renderer.

## Prompt-injection behavior

Text in `memo` is percent-encoded URL data only; it cannot change the
recipient, amount, mint, or reference. Invalid keys and non-positive/malformed
amounts fail with `success: false`. `tests/core.rs` covers this case.

## Build and test

```bash
cargo test --locked
cargo clippy --all-targets -- -D warnings
rustup target add wasm32-wasip2
cargo build --locked --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
cp target/wasm32-wasip2/release/solana_pay_request.wasm solana_pay_request.wasm
```

## Next steps

The chat/channel layer should render `qr_payload` as a QR image. A payment
watch SOP can use the returned reference key to report settlement.

## License

MIT
