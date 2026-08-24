# token-supply

`token-supply` is a T0 read-only ZeroClaw tool. Inspect the current amount and decimals of a public SPL token mint.

It performs exactly one `getTokenSupply` request against an operator-configured
Solana RPC endpoint and returns a compact, bounded JSON report. It exposes no
wallet, signer, key, transaction builder, token approval, or write RPC method.

## Configure

```toml
[plugins.token-supply]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
```

Non-loopback endpoints must use HTTPS and may not contain embedded credentials.

## Prompt example

```text
Use token-supply with mint_address So11111111111111111111111111111111111111112. Return the public read-only result and do
not sign or submit anything.
```

## Verify

```bash
cargo test --manifest-path plugins/token-supply/Cargo.toml
cargo clippy --manifest-path plugins/token-supply/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/token-supply/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The tool accepts only a public Solana identifier or slot and
fails closed on malformed input, unsafe endpoint configuration, RPC errors,
null results, and output above 8 KiB.
