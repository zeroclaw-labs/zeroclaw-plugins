# block-time

`block-time` is a T0 read-only ZeroClaw tool. Resolve the estimated Unix production time for a public Solana slot.

It performs exactly one `getBlockTime` request against an operator-configured
Solana RPC endpoint and returns a compact, bounded JSON report. It exposes no
wallet, signer, key, transaction builder, token approval, or write RPC method.

## Configure

```toml
[plugins.block-time]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
```

Non-loopback endpoints must use HTTPS and may not contain embedded credentials.

## Prompt example

```text
Use block-time with slot 100000000. Return the public read-only result and do
not sign or submit anything.
```

## Verify

```bash
cargo test --manifest-path plugins/block-time/Cargo.toml
cargo clippy --manifest-path plugins/block-time/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/block-time/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The tool accepts only a public Solana identifier or slot and
fails closed on malformed input, unsafe endpoint configuration, RPC errors,
null results, and output above 8 KiB.
