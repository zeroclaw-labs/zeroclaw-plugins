# `solana-wasip2-core` — design note (Track E)

**Status:** design, pre-implementation. Written 2026-07-25.

## The problem this exists because of

`solana-sdk` does not compile for `wasm32-wasip2`. Every ZeroClaw plugin that
wants to touch Solana therefore hand-rolls the same primitives from the wire
format, and gets to make the same mistakes privately.

I know this because I did it twice. `token-risk-check` (PR #91) and
`depin-attest` (PR #92) were written a few hours apart and independently grew:

| Primitive | token-risk-check | depin-attest |
|---|---|---|
| base58 → 32-byte pubkey, length-checked | `spl.rs` | `tx.rs::decode_pubkey` |
| JSON-RPC envelope + error surfacing | `rpc.rs::rpc_result` | `rpc.rs` |
| base64 of account data | `rpc.rs` | `tx.rs::to_base64` |
| commitment-tagged request builders | `rpc.rs` ×3 | `rpc.rs` ×2 |

That is not two plugins sharing an idea — it is the *same code* written twice
because there was nowhere to put it. The third, fourth and tenth plugin will do
it again, each with its own bounds-checking bugs, in a component model where a
parsing mistake is a fail-open risk rather than a panic.

## What it is

One `no_std`-friendly, dependency-light crate holding exactly the Solana
primitives a `wasm32-wasip2` component needs, with no `solana-sdk` anywhere.

```
solana-wasip2-core
├── pubkey     base58 ⇄ [u8; 32], strict length validation, no silent truncation
├── shortvec   compact-u16 encode/decode (the format everyone gets wrong first)
├── tx         unsigned legacy transaction assembly; zeroed signature slots so
│              wallets and hosts recognise it as unsigned and require approval
├── rpc        JSON-RPC envelope: request builders, `result` extraction,
│              RPC-level error surfacing as typed errors, never as an empty Ok
├── spl        SPL-Token + Token-2022 mint layout, COption tags, and the TLV
│              extension walk (bounds-checked; overruns are errors, not guesses)
└── b64        base64 encode/decode for account data and tx payloads
```

**Non-goals, deliberately.** No signing. No key handling. No network I/O — the
host owns `wasi:http` and the permission gate, and this crate must never become
the thing that quietly acquires authority. It is parsing and serialisation only.
That boundary is what makes it safe to share.

## Why this is worth a Track E slot

- **It ships with two real consumers, not a promise.** The proof of the design
  is refactoring `token-risk-check` and `depin-attest` onto it and showing both
  test suites (19 + 21 host tests) still green with less code in each plugin.
- **It moves the risky code to where it gets audited once.** TLV walking and
  compact-u16 decoding are exactly the parsing that fails open if sloppy. One
  bounds-checked implementation reviewed once beats N private copies.
- **It is the piece nobody else is building.** The board rewards depth over
  breadth, and public bounty markets are agent-saturated on the obvious work
  ([[reference_bounty_payout_rails_2026-07-25]]). A shared substrate is
  unglamorous, hard to fake, and compounds for every later plugin.

## Execution order

1. Extract `pubkey`, `shortvec`, `b64` — pure functions, golden-vector tested.
2. Extract `rpc` envelope handling; keep per-plugin method builders local at
   first, promote only what both plugins genuinely share.
3. Extract `spl` mint + TLV walk — the highest-value and highest-risk module;
   port `token-risk-check`'s existing extension-type table and its tests wholesale.
4. Refactor both plugins onto the crate. **Green tests before and after is the
   deliverable** — if the suites do not stay green, the extraction is wrong.
5. `cargo build --target wasm32-wasip2 --release` on both plugins; confirm the
   component sizes did not regress.

## Field notes worth carrying into the README

- `solana-sdk` is unusable here; `waki` + `bs58` + `borsh` + hand-rolled encoding
  is the working combination.
- Blockhash expiry versus human approval lag: build rebuild-idempotent
  transactions (same sequence number until one lands) rather than assuming the
  blockhash survives the gate.
- Shape RPC output to ~200 tokens before it reaches a model. The raw response is
  40 KB and the judges are counting tokens.
- `getTokenLargestAccounts` has a hard protocol ceiling — mega-holder tokens fail
  on **paid** endpoints too (USDC: `-32600, 10000000 pubkeys`). Any concentration
  feature must degrade explicitly rather than estimate.

## Open questions

- Crate name: `solana-wasip2-core` is descriptive but claims a lot of namespace.
  Ask the maintainers in the PR before publishing anything.
- Whether the maintainers want this vendored per-plugin or as a workspace member.
  **Ask before restructuring their tree** — an unsolicited layout change is the
  fastest way to make a useful PR unmergeable.
