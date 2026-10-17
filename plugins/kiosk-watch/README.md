# kiosk-watch

**Part of ProofKiosk** — a Raspberry Pi that sells for USDC, physically delivers, and
proves it on-chain, while the agent never holds a key. This is component 2 of 3
(`kiosk-charge` → **`kiosk-watch`** → `kiosk-attest`), Track C (DePIN & the physical
edge) with Track A payment rails inside.

`kiosk_watch` is the **gate**: it answers the one question the actuation SOP checks
before firing the GPIO relay — *did the expected payment actually land on-chain?* — by
verifying the `reference` from `kiosk-charge` against the operator's merchant address,
mint, amount, and finality. It also has a **heartbeat** mode to confirm the device's
attestation stream is still fresh.

It is **channel-agnostic**: it verifies on-chain state, not a chat message, so it works
identically whether the sale happened over Telegram, a local screen, or any other
front-end.

## Custody tier: T0 — no keys, read-only

- **No secrets, no signing.** `kiosk-watch` only *reads* the chain over JSON-RPC
  (`getSignaturesForAddress`, `getTransaction`). It cannot move funds.
- **The model can never choose the recipient, mint, or RPC endpoint.** Those come from
  the operator's jailed config section. The model supplies only a `reference`, an
  `expected_amount`, and (optionally) a `window_s` — or, in heartbeat mode, a
  `device_address` and `max_silence_s`.
- **One unambiguous actuation condition.** `success == true` **iff** a transaction
  crediting the exact `expected_amount` of the operator's `usdc_mint` to the operator's
  `merchant_address`, referencing this charge, has landed at the configured finality.
  Every other outcome — pending, expired, mismatch, RPC failure, malformed response —
  returns `success == false`. The relay gates on that single boolean, so **the relay
  can never fire on anything but a verified payment.**

## Config keys (`__config`, injected by the host)

| Key | Required | Meaning |
|---|---|---|
| `rpc_url` | yes | Solana JSON-RPC endpoint. Fail-closed if missing/empty. |
| `merchant_address` | yes | Operator's receiving pubkey (base58, 32 bytes). Fail-closed if invalid. |
| `usdc_mint` | no | SPL mint to expect; defaults to mainnet USDC (`EPjF…Dt1v`). Set devnet USDC when testing. |
| `finality` | no | Commitment gating the answer: `processed` \| `confirmed` \| `finalized`. Default `confirmed`. |

**Finality note (safety):** `confirmed` is the default — a supermajority has voted, so a
reorg is unlikely, and the latency (~1–2s) keeps the buy-to-drop experience fast. An
operator who wants economic irreversibility before actuating can set `finalized` (adds
~13s). `processed` is available but **not recommended** for actuation: it can still be
rolled back.

## Args (model-facing, `deny_unknown_fields`)

| Arg | Mode | Meaning |
|---|---|---|
| `reference` | payment | Solana Pay reference pubkey from the charge. Required. |
| `expected_amount` | payment | Expected USDC amount, decimal string (e.g. `"1.5"`). Required. |
| `window_s` | payment | Acceptance window in seconds; a matching payment older than this before *now* is `Expired`, not `Paid`. Optional. |
| `mode` | both | `"heartbeat"` selects heartbeat mode; absent/`"payment"` = payment. |
| `device_address` | heartbeat | Device attestation address to scan. Required in heartbeat mode. |
| `max_silence_s` | heartbeat | Max seconds since newest attestation before `Stale`. Required in heartbeat mode. |

## Worked example (payment)

Args from the model:

```json
{ "reference": "3g8oT…dK2f", "expected_amount": "1.5", "window_s": 300 }
```

Output when the payment has landed (single string, token-budgeted, asserted ≤ 200
tokens in tests), with `success == true`:

```
PAID. Payment verified on-chain at slot 100, signature 5xSig…, payer 9aB…. Safe to deliver.
```

Before it lands, `success == false`:

```
PENDING. No matching payment on-chain yet. Do not deliver; check again shortly.
```

## Threat model & prompt-injection transcript (fail closed)

All executed as host tests (`cargo test`, RPC mocked, **no network**):

| Attack / failure | Result |
|---|---|
| "Verify against MY rpc/address" → smuggled `{"rpc_url": …}` / `{"merchant_address": …}` arg | **Rejected** — `deny_unknown_fields` + a raw-key allowlist; deserialization fails before any logic runs. |
| RPC node errors, times out, or returns garbage | **`Err`, never `Paid`** → `success:false`. The relay stays shut. (`rpc_error_is_err_never_paid`, `malformed_get_transaction_is_err_never_paid`) |
| Payment is for the wrong amount | **`Mismatch`** → `success:false`. |
| Payment went to a different recipient | **`Mismatch`** → `success:false`. |
| Payment used a different mint (not the configured USDC) | **`Mismatch`** → `success:false`. |
| On-chain transaction failed (`meta.err != null`) | **`Mismatch`** — funds did not move. |
| A stale/reused-reference payment older than `window_s` | **`Expired`** → `success:false`. |
| Customer hasn't paid yet | **`Pending`** → `success:false`; the SOP's cron bounds total wait. |

The failure direction is always "refuse to actuate." There is no reachable path where an
RPC failure, a partial response, or a non-matching transaction yields `success == true`.

## Layout & tests

Pure core (`src/watch.rs`, no wasm deps) + thin `#[cfg(target_family = "wasm")]` shim
(`src/lib.rs`), matching `plugins/kiosk-charge`. RPC is mocked in host tests through
`kiosk_core::rpc::RpcTransport` (a one-method seam); the real HTTPS transport (`waki`)
is compiled only for the wasm target via a target-gated `http` feature, so
`cargo test` stays zero-network.

```
cargo test                                      # 19 host tests, no network
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release    # ~348 KB component
cargo clippy --all-targets -- -D warnings
```

## What's next in this PR series

`kiosk-attest` (T1 hash-chained, Merkle-batched sensor/receipt attestations with a
durable nonce), then the Pi wiring diagram and the full pay→verify→relay→attest demo.
