# blockhash-validity

`blockhash-validity` is a T0 read-only ZeroClaw tool. Check whether a public recent blockhash is still valid for transaction processing.

It performs exactly one `isBlockhashValid` request against an operator-configured
Solana RPC endpoint and returns a compact, bounded JSON report. It exposes no
wallet, signer, key, transaction builder, token approval, or write RPC method.

## Configure

```toml
[plugins.blockhash-validity]
rpc_url = "https://api.mainnet-beta.solana.com"
commitment = "finalized"
```

Non-loopback endpoints must use HTTPS and may not contain embedded credentials.

## Prompt example

```text
Use blockhash-validity with blockhash 91cmfM46bCQ9fX8DQFCYzbhjjnKSeNAzADwDXZfpbazf. Return the public read-only result and do
not sign or submit anything.
```

## Verify

```bash
cargo test --manifest-path plugins/blockhash-validity/Cargo.toml
cargo clippy --manifest-path plugins/blockhash-validity/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path plugins/blockhash-validity/Cargo.toml --target wasm32-wasip2 --release
```

## Safety level

T0 (read-only). The tool accepts only a public Solana identifier or slot and
fails closed on malformed input, unsafe endpoint configuration, RPC errors,
null results, and output above 8 KiB.
