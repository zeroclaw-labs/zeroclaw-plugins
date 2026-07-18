# account-balance

`account-balance` is a T0 read-only ZeroClaw tool. Inspect the lamport balance and RPC context of a public Solana account.

It performs exactly one `getBalance` request against an operator-configured
Solana RPC endpoint and returns a compact, bounded JSON report. It exposes no
wallet, signer, key, transaction builder, token approval, or write RPC method.

## Configure

```toml
[plugins.account-balance]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
```

Non-loopback endpoints must use HTTPS and may not contain embedded credentials.

## Prompt example

```text
Use account-balance with account_address 11111111111111111111111111111111. Return the public read-only result and do
not sign or submit anything.
```

## Verify

```bash
cargo test --manifest-path plugins/account-balance/Cargo.toml
cargo clippy --manifest-path plugins/account-balance/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/account-balance/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The tool accepts only a public Solana identifier or slot and
fails closed on malformed input, unsafe endpoint configuration, RPC errors,
null results, and output above 8 KiB.
