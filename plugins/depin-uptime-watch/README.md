# depin-uptime-watch

ZeroClaw tool plugin for checking recent Solana DePIN attestation memos and
returning a shaped uptime freshness verdict.

The `depin_uptime_watch` tool is T0 custody: it only reads RPC data, scans
recent successful transactions for matching memo attestations, and returns
`OK`, `STALE`, or `MISSING`. It never signs or submits transactions.

Build:

```bash
rustup target add wasm32-wasip2
cargo build --manifest-path plugins/depin-uptime-watch/Cargo.toml --target wasm32-wasip2 --release
```
