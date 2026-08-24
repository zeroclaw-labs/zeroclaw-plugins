# signature-status

`signature-status` is a T0 read-only ZeroClaw tool. Inspect confirmation, slot, and error state for a public Solana transaction signature.

It performs exactly one `getSignatureStatuses` request against an operator-configured
Solana RPC endpoint and returns a compact, bounded JSON report. It exposes no
wallet, signer, key, transaction builder, token approval, or write RPC method.

## Configure

```toml
[plugins.signature-status]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
```

Non-loopback endpoints must use HTTPS and may not contain embedded credentials.

## Prompt example

```text
Use signature-status with signature 3Bwv8nYQ7GbJvgCuRtqNzma3y5pCCqcRhENPHDTFuGbzgFyYodUp9echDd6iktfxQx8cpH3RpforaniwXEAaKxM6. Return the public read-only result and do
not sign or submit anything.
```

## Verify

```bash
cargo test --manifest-path plugins/signature-status/Cargo.toml
cargo clippy --manifest-path plugins/signature-status/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/signature-status/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The tool accepts only a public Solana identifier or slot and
fails closed on malformed input, unsafe endpoint configuration, RPC errors,
null results, and output above 8 KiB.
