# block-commitment

`block-commitment` is a T0 read-only ZeroClaw tool. Inspect cluster commitment stake for a public Solana slot.

It performs exactly one `getBlockCommitment` request against an operator-configured
Solana RPC endpoint and returns a compact, bounded JSON report. It exposes no
wallet, signer, key, transaction builder, token approval, or write RPC method.

## Configure

```toml
[plugins.block-commitment]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
```

Non-loopback endpoints must use HTTPS and may not contain embedded credentials.

## Prompt example

```text
Use block-commitment with slot 100000000. Return the public read-only result and do
not sign or submit anything.
```

## Verify

```bash
cargo test --manifest-path plugins/block-commitment/Cargo.toml
cargo clippy --manifest-path plugins/block-commitment/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/block-commitment/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The tool accepts only a public Solana identifier or slot and
fails closed on malformed input, unsafe endpoint configuration, RPC errors,
null results, and output above 8 KiB.
