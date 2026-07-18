# token-account-balance

`token-account-balance` is a T0 read-only ZeroClaw tool. Inspect the amount and decimals held by a public SPL token account.

It performs exactly one `getTokenAccountBalance` request against an operator-configured
Solana RPC endpoint and returns a compact, bounded JSON report. It exposes no
wallet, signer, key, transaction builder, token approval, or write RPC method.

## Configure

```toml
[plugins.token-account-balance]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
```

Non-loopback endpoints must use HTTPS and may not contain embedded credentials.

## Prompt example

```text
Use token-account-balance with token_account AxTkKX5modwZPPs1FMhkKeuc9mtR9yQTQVzHDn5aag2u. Return the public read-only result and do
not sign or submit anything.
```

## Verify

```bash
cargo test --manifest-path plugins/token-account-balance/Cargo.toml
cargo clippy --manifest-path plugins/token-account-balance/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/token-account-balance/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The tool accepts only a public Solana identifier or slot and
fails closed on malformed input, unsafe endpoint configuration, RPC errors,
null results, and output above 8 KiB.
