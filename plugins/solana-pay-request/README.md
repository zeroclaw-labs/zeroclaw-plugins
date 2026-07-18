# Solana Pay Request — ZeroClaw Plugin

**T1 tool plugin** — generates Solana Pay transfer request URLs (`solana:` protocol) that an agent can render as a QR code for payment. Holds no secrets.

## Classification

| Property       | Value                |
| -------------- | -------------------- |
| **Type**       | T1 (no secrets)      |
| **Capability** | `tool`               |
| **WASM**       | `solana_pay_request.wasm` |
| **Permission** | `config_read`        |

## What It Does

Given a recipient address and amount, this plugin returns a `solana:` URL conforming to the [Solana Pay](https://solanapay.com) transfer request specification. The URL can be rendered as a QR code for a wallet to scan and sign.

Optional parameters:

- `mint` — SPL token mint address (omit for native SOL)
- `memo` — invoice memo text
- `reference` — reference key for payment tracking / verification

## Config Keys

Config keys (supplied via the `__config` block on the `execute` call):

| Key       | Default                                          | Description                     |
| --------- | ------------------------------------------------ | ------------------------------- |
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Solana JSON-RPC endpoint (unused in T1 URL construction but available for future blockhash lookup). |

## Threat Model

This plugin is **T1** — it holds no secrets and builds only an **unsigned** URL. The URL is a request for payment; the actual transaction is signed by the user's wallet when they scan the QR code. An attacker who intercepts the URL can see the payment details but cannot modify them or steal funds (the recipient address is embedded in the URL). The agent should deliver the URL over an authenticated channel.

## Example

> Agent: "Table 4 owes 25 USDC. Generating payment request..."

```
solana:7EcDhSYGxXyscszYEp35KHN8vvw3svAuEt8JaVipkGCf?spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&amount=25&memo=table-4&label=ZeroClaw+Agent
```

The agent renders this as a QR code in chat. Table 4 scans it with their wallet, reviews the 25 USDC charge, and signs.

## Build

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

## Test

```bash
cargo test
```

Host tests exercise the pure `pay` module without any wasm dependency.