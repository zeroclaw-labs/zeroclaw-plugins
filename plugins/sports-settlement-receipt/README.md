# sports-settlement-receipt

`sports-settlement-receipt` is a ZeroClaw `wasm32-wasip2` tool that binds an
authenticated TxLINE final-score Merkle proof to an **existing finalized
Solana SettleTrace attestation**. It uses two or three independently configured
archival RPC providers and requires a 2-provider match. Any contradiction
returns `unknown`.

**Custody tier: T0 (read-only).** The component has no wallet-key input,
signing code, `sendTransaction` method, or transaction-construction input. It
does not create, sign, or broadcast the attestation it verifies.

## One tool, one evidence path

The model supplies only:

```json
{
  "fixture_id": 18179550,
  "sequence": 1315,
  "market": { "kind": "match_winner", "selection": "home" },
  "attestation_signature": "EXISTING_SOLANA_SIGNATURE"
}
```

The component performs:

1. one authenticated, fixed-key TxLINE
   `GET /api/scores/stat-validation?fixtureId=...&seq=...&statKey=1&statKey2=2`;
2. fixed `getSignatureStatuses` and finalized/base64 `getTransaction` reads
   against each configured RPC (two or three, with no retry or fallback).

It verifies the response fixture, stat keys 1/2, score bounds, period 100,
proof shape, TxLINE `validate_stat` Borsh bytes, and daily-score PDA. Each
finalized transaction must then have exactly this legacy-message shape:

- one signer and the fixed TxLINE, Compute Budget, Memo, and daily-PDA keys;
- `SetComputeUnitLimit(1_400_000)`;
- a strict `SettleTrace v1` memo binding fixture, sequence, receipt hash, and
  compact predicate;
- one byte-for-byte matching TxLINE `validate_stat` instruction; and
- `meta.err: null` plus TxLINE return data equal to the locally evaluated
  Boolean predicate.

Providers are fingerprinted by finalized slot, raw transaction SHA-256,
`meta.err`, and return data. Two matching complete providers are required.
Intra-provider conflicts, cross-provider conflicts, or binding mismatches have
priority over a majority and result in `unknown`.

## Configuration

```toml
[[plugins.entries]]
name = "sports-settlement-receipt"

[plugins.entries.config]
txline_base_url = "https://txline-dev.txodds.com"
txline_api_token = "YOUR_TXLINE_API_TOKEN"
txline_session_jwt = "YOUR_CURRENT_TXLINE_SESSION_JWT"
rpc_url_1 = "https://FIRST-INDEPENDENT-ARCHIVAL-RPC"
rpc_url_2 = "https://SECOND-INDEPENDENT-ARCHIVAL-RPC"
# rpc_url_3 = "https://OPTIONAL-THIRD-INDEPENDENT-ARCHIVAL-RPC"
```

RPC URLs must be HTTPS and have distinct hosts. `txline_base_url` is optional
and defaults to the TxLINE dev endpoint. Credentials are injected by the host;
they are absent from the model schema, output, and logs. The tool intentionally
does not call a guest-auth endpoint, so the operator must supply a current JWT.

## Prompt-injection boundary

Inputs containing `rpc_url`, `method`, `sendTransaction`, raw transaction
bytes, `private_key`, or a threshold override are rejected by both the closed
JSON Schema and `serde(deny_unknown_fields)`. The only RPC request builders in
the component hard-code `getSignatureStatuses` and finalized
`getTransaction`.

## Bounds and evidence limits

- responses: 1 MiB at the HTTP layer, 512 KiB at quorum parsing;
- transaction: 4 KiB decoded; return data: 2 KiB;
- Merkle proof: 64 nodes/vector and 192 total; output: 8 KiB;
- network timers: 5 s connect/idle, 10 s first byte, 15 s request/body;
- no arbitrary endpoint, path, RPC method, stat key, program, instruction, or
  transaction input;
- all incomplete or contradictory states are `unknown`, never a guessed win
  or loss.

Period `100` is the TxLINE final marker proven by the instruction. The legacy
stat-validation response does not echo `action=game_finalised`, `statusId=100`,
or the requested sequence; sequence is bound to the authenticated request path
and independently to the strict on-chain memo. RPC quorum reduces single-node
trust but does not eliminate common-mode provider or Solana/TxLINE program
risk. This receipt is evidence metadata, not a bet, payout, or authorization
to move funds.

The public SettleTrace reference signature
`2NeFGwjPRQ3sZLjUZ6PsAHCnPjnmsDBzpUoTBPpFV34mMFJadP4HFx33CAvhWU29XbPw2uU6SyGsNGFJ5bsSab8y`
demonstrates the accepted top-level memo/TxLINE shape. A live end-to-end run
still needs a current TxLINE session and at least two archival devnet RPCs.

## Build and test

```bash
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --target wasm32-wasip2 --release
```

Release artifact:

```text
target/wasm32-wasip2/release/sports_settlement_receipt.wasm
```

The pure core and quorum have no WASI dependency; host tests use only local
synthetic fixtures. See [THREAT_MODEL.md](./THREAT_MODEL.md). Licensed MIT.
