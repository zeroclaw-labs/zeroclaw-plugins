# depin-attest

> **WIP — full docs (config keys, custody tier, threat model, worked example, prompt-injection test) land in slice H.**

A ZeroClaw WIT **tool plugin** (`tool-plugin` world, `wit/v0`) from the
[Palinurus](https://github.com/RECTOR-LABS/palinurus) project — the reference
implementation for "the Solana DePIN node that talks."

## What it does

Turns a physical sensor reading into a Solana attestation. The agent calls
`execute` with a reading (`sensor_id`, `value`, `unit`, `timestamp`); the plugin
builds an unsigned versioned transaction containing a Solana Attestation Service
`create_attestation` instruction, composed with a **durable nonce** so the tx
survives an approval queue (the blockhash-expiry fix), and returns a ~200-token
summary the model can relay to the user.

**Custody:** T1 default (unsigned — a human or Squads multisig signs) + T2 opt-in
(a scoped session key signs + submits, guarded by a program allowlist, hard caps,
and a fail-closed prompt-injection test). The agent never holds a main wallet key.

Built on [`palinurus-core`](https://github.com/RECTOR-LABS/palinurus) — the
minimal `wasm32-wasip2`-friendly Solana substrate (Track E).

## Build and test (WIP — will be expanded in slice H)

```bash
cargo test                                        # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component
```