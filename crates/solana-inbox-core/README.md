# solana-inbox-core

A pure, dependency-light Rust library that turns Solana JSON-RPC responses
(`getSignaturesForAddress` + `getTransaction` with `encoding: "jsonParsed"`)
into agent-shaped `Inbound` events. Built for the ZeroClaw
`solana-inbox` channel plugin, reusable by any Rust plugin that wants to
treat Solana as an inbound message stream.

- No `solana-sdk`, no `solana-client`, no async, no network, no wallet.
- Builds cleanly for `wasm32-wasip2` inside a WIT component.
- Every load-bearing invariant is stated in `PROOFS.md` (in the consuming
  plugin) and verified by property-based tests plus Kani harnesses.
- ~700 lines, MIT / Apache-2.0.

## Why this crate exists

Every existing Solana Rust SDK (`solana-sdk`, `solana-client`,
`spl-token-2022`) drags transitive dependencies — `getrandom`,
`curve25519-dalek`, native TLS providers — that break inside a
`wasm32-wasip2` component. Plugin authors for agent runtimes
(ZeroClaw, ElizaOS, custom) end up hand-rolling the same wire-format
decoders over and over. This crate is the smallest useful cut of that
work for the specific case of building a Solana-as-a-channel plugin.

## Example

```rust
use serde_json::json;
use solana_inbox_core::{extract_inbounds, parse_signatures_response, Config};

let cfg = Config::from_json(&json!({
    "rpc_url": "https://api.mainnet-beta.solana.com",
    "watched_address": "So11111111111111111111111111111111111111112"
}).to_string()).unwrap();

// Your HTTP client goes here. Feed the parsed JSON to this crate:
let sigs_response: serde_json::Value = /* getSignaturesForAddress result */;
for sig in parse_signatures_response(&sigs_response) {
    let tx_response: serde_json::Value = /* getTransaction result for sig */;
    let events = extract_inbounds(
        &tx_response,
        &sig.signature,
        &cfg.watched_address,
        cfg.include_transfers,
        sig.block_time_secs,
    );
    for ev in events {
        println!("[{}] {}: {}", ev.timestamp_ms, ev.sender, ev.content);
    }
}
```

## Coverage

Handles the shapes real mainnet-beta production returns as of 2026-07-25:
versioned transactions with address lookup tables, durable-nonce advance
instructions, ComputeBudget priority fees, jsonParsed accountKey objects
(`{pubkey, signer, writable, source}`) as well as bare-string variants.
Real captured fixtures live under `tests/fixtures/` in the consuming
plugin.

## Related

- Consumer plugin: [`solana-inbox`](https://github.com/zeroclaw-labs/zeroclaw-plugins/tree/main/plugins/solana-inbox)
- Sister crates in the same tradition:
  - [`cupel-core`](https://crates.io/crates/cupel-core) — tx-preflight decoder from bounty PR #137
  - [`quorum-squads-core`](https://crates.io/crates/quorum-squads-core) — Squads v4 codecs from bounty PR #97

## License

MIT OR Apache-2.0.
