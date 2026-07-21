# depin-attest

ZeroClaw tool plugin for building unsigned durable-nonce Solana memo
attestations from DePIN device sensor readings.

The `depin_attest` tool reads policy and Solana account settings from the
plugin config section, fetches the durable nonce account over the host-provided
HTTP client, and returns a summary plus unsigned transaction payload. It does
not sign or submit transactions.

Build:

```bash
rustup target add wasm32-wasip2
cargo build --manifest-path plugins/depin-attest/Cargo.toml --target wasm32-wasip2 --release
```
