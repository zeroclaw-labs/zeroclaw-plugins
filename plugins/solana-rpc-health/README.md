# solana-rpc-health

A ZeroClaw **WIT component** tool plugin that checks the health of a Solana RPC
endpoint. Implements the `tool-plugin` world from `wit/v0`, compiles to
`wasm32-wasip2`, follows the `redact-text` reference layout.

## What it does

Pings a Solana JSON-RPC node and returns a health summary:

- **getHealth** — is the node healthy and synced?
- **getVersion** — what version of solana-core is running?
- **getSlot** — current confirmed slot
- **getEpochInfo** — current epoch, progress within epoch, total transaction count

The agent receives a one-line summary plus structured JSON — lightweight context-friendly output.

## Custody tier: **T0 (Read)**

This plugin performs read-only RPC calls. It holds **no secrets**, signs **nothing**.

| Tier | Description | Secrets held |
|------|-------------|-------------|
| T0   | RPC reads, health checks | None |

## Config keys

| Key | Default | Meaning |
|-----|---------|---------|
| `rpc` | `https://api.mainnet-beta.solana.com` | Solana JSON-RPC endpoint |

No other config keys. Override per-invocation via the `rpc` argument.

## Layout (following redact-text)

```
src/rpc_health.rs   # pure Rust core — host-testable, no wasm deps
src/lib.rs          # thin #[cfg(target_family = "wasm")] component shim
manifest.toml       # plugin identity, capabilities, permissions
```

## Build and test

```bash
cargo test                                        # host tests (2 tests)
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component (~269 KB)
```

## Usage example

```
> solana-rpc-health

{
  "healthy": true,
  "version": "solana-core 2.1.0 (feature-set 12345)",
  "slot": 320000000,
  "epoch": 700,
  "epoch_progress_pct": 23.1,
  "transaction_count": 999999999,
  "summary": "✅ RPC healthy | slot=320000000 epoch=700 | solana-core 2.1.0"
}
```

## Threat model

| Threat | Mitigation |
|--------|-----------|
| RPC returns spoofed health data | Plugin is read-only. Use a trusted RPC endpoint. |
| RPC unreachable | Returns `healthy: false` with a clear error. Does not crash. |
| Large responses | Output is shaped to < 1 KB regardless of RPC response size. |
