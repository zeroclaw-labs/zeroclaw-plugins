# kiosk-attest

**Part of ProofKiosk** — a Raspberry Pi that sells for USDC, physically delivers, and
proves it on-chain, while the agent never holds a key. This is component 3 of 3
(`kiosk-charge` → `kiosk-watch` → **`kiosk-attest`**), Track C (DePIN & the physical
edge).

`kiosk_attest` is the **proof**: it records a tamper-evident, hash-chained attestation
of a sensor reading or a sale event on Solana. It builds an **unsigned**, durable-nonce
memo transaction and hands it back for the operator's signer to submit — the agent never
signs and cannot move funds.

It is **channel-agnostic** and stateless: the chain sequence is recovered from the chain
itself on every call, so a fresh host with no local state produces the next correct link.

## Custody tier: T1 — funds cannot move, by construction

- **No secrets, no signing.** The plugin reads the chain (recover seq/prev; read the
  durable nonce) and emits an *unsigned* transaction. Zero signatures are attached.
- **The transaction is structurally incapable of moving funds.** It is built from
  exactly two instructions — System `AdvanceNonceAccount` and SPL Memo — and a transfer
  is not constructed anywhere in the crate. A host test asserts the compiled program set
  is exactly `{System, Memo}`, so even a fully compromised model cannot make this plugin
  emit a spend.
- **The model can never choose the device, nonce account/authority, or RPC endpoint.**
  Those are operator config. The model supplies only a reading (`metric`, `value`) or an
  event label — and a reading must clear the operator's allowlist and bounds.

## How the hash chain works

Each attestation writes a memo:

```json
{ "v": 1, "dev": "kiosk01", "seq": 8, "ts": 1700000000,
  "metric": "temp_c", "val": 4.2, "prev": "<previous attestation signature>" }
```

- `seq` / `prev` link every attestation to the one before it (the previous landed
  signature). The whole record is anchored on-chain; a missing or reordered entry breaks
  the walk, so gaps are **detectable**.
- Recovery is one RPC call: `getSignaturesForAddress(nonce_account, limit 1)` returns the
  newest attestation and its memo; the next `seq` is `memo.seq + 1` and `prev` is that
  signature. A device with no history starts at `seq 0, prev null`.
- This is tamper-evident **ordering**, not a content-hash Merkle tree: an authorized
  signer could in principle branch history. It needs no attestation-service program
  deployed and is self-contained — that is the deliberate tradeoff.

## Why a durable nonce

The transaction uses a durable nonce in place of a recent blockhash, so an attestation
built now stays valid to submit later — the Pi can attest across brief connectivity gaps.
`AdvanceNonceAccount` is always **instruction 0** (Solana requires it), enforced by a
test.

## Config keys (`__config`, injected by the host)

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | yes | Solana JSON-RPC endpoint. |
| `device_id` | yes | Human device id written into each memo as `dev`. |
| `nonce_account` | yes | Durable nonce account pubkey (base58). The chain is scanned here. |
| `nonce_authority` | yes | Nonce authority / fee payer pubkey; must own the nonce account. |
| `allowed_metrics` | no | `"temp_c:-40:85, humidity:0:100"` — metric → inclusive `[min,max]`. |
| `custody_mode` | no | Default `t1`. |

## Args (model-facing, `deny_unknown_fields`)

| Arg | Kind | Meaning |
|---|---|---|
| `kind` | both | `"reading"` (default) or `"event"`. |
| `metric`, `value` | reading | Metric name (allowlisted) and numeric value (bounded, finite). |
| `event`, `item`, `payment_sig` | event | Event label; optional item id and payment signature. |
| `ts` | both | Unix seconds; defaults to now. |

## Worked example

Args from the model:

```json
{ "kind": "reading", "metric": "temp_c", "value": 4.2 }
```

Output (`success = true`), token-budgeted:

```
ATTESTED reading seq=8 metric=temp_c val=4.2 ts=1700000000 — unsigned durable-nonce tx built (263 bytes), ready for the operator signer.
unsigned_tx_base64=AQABBQ...
```

## Threat model & injection transcript (fail closed)

All executed as host tests (`cargo test`, RPC mocked, **no network**):

| Attack / failure | Result |
|---|---|
| "Attest to MY account" → smuggled `{"nonce_authority": …}` / `{"recipient": …}` arg | **Rejected** — `deny_unknown_fields` + a raw-key allowlist; fails before any logic. |
| Metric not in the operator allowlist | **Rejected** — refuse to attest an unknown metric. |
| Value out of the operator's `[min,max]` | **Rejected** — a bad reading is refused, never clamped into a plausible lie. |
| Value `NaN` / `±inf` | **Rejected** — non-finite values cannot be attested. |
| Attempt to move funds | **Impossible** — the tx has only Memo + System programs; asserted structurally. |
| RPC node errors / returns garbage | **`Err`, never a successful attestation.** |
| Newest device tx has no readable attestation memo | **Chain gap surfaced** — not silently treated as a fresh device. |

No path yields a signed transaction or a fund movement; the plugin holds no key and the
built transaction carries zero signatures.

## Layout, wasip2 & tests

Pure core (`src/attest.rs`, no wasm deps) + thin `#[cfg(target_family = "wasm")]` shim
(`src/lib.rs`), matching the other kiosk plugins. All Solana primitives come from
`crates/kiosk-core` (hand-rolled base58, base64, shortvec, memo/nonce instruction
builders, legacy message serialization, JSON-RPC seam) — **no `solana-sdk`**, which does
not compile for `wasm32-wasip2`. The real HTTPS transport (`waki`) is compiled only for
the wasm target via a target-gated `http` feature, so `cargo test` stays zero-network.

```
cargo test                                      # 14 host tests, no network
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release    # ~384 KB component
cargo clippy --all-targets -- -D warnings
```
