# payment-watch

**Tier 0 (read-only RPC)** tool plugin for ZeroClaw: watch a Solana address for an
expected payment — amount, optional SPL mint, optional memo/reference — and
report the matching transaction when it lands.

This is the component that closes the loop on Solana Pay / invoice flows:

```
agent: solana-pay-request("charge table 4 for 25 USDC")   → QR in chat
agent: payment-watch(address, 25, mint=USDC, reference="Invoice #412")
       → {"found": true, "signature": "5xK…", "amount": 25.0, "memo": "Invoice #412"}
```

## Custody tier: T0 — and why that is the right design

This plugin **never builds, signs, or submits a transaction** and holds **no key
material**. The only secret it can ever possess is an RPC API key embedded in the
configured endpoint URL (`config.rpc_url`), which the operator chooses.

Payment *confirmation* is the read side of the payment loop. Pairing it with a
T1 builder (`solana-pay-request`, `spl-transfer-build`) keeps the write side
keyless too: the agent proposes, a human (or Squads multisig) disposes. An agent
that can both request money and confirm receipt without ever touching a private
key has no prompt-injection drain surface — there is nothing to drain.

## What it does

1. `getSignaturesForAddress` on the watched address (recent N, default 25, max 50)
2. `getTransaction` (jsonParsed) per signature until one satisfies the watch spec:
   - **Amount match** within configurable relative tolerance (default 0.5%)
   - **Native SOL**: pre/post balance delta of the watched account
   - **SPL**: post−pre `uiTokenAmount` delta filtered to the exact mint AND owner
     (other mints / other owners' accounts in the same tx are ignored)
   - **Reference**: substring match against Memo-program instruction data
     (`MemoSq4g…` / `Memo1Uhk…`) or account keys (Solana Pay reference keys)
   - **Recency**: `since_unix` cutoff via `blockTime`
   - Failed transactions (`meta.err`) are never matched
3. Returns `{"found": true, signature, amount, kind, memo, block_time}` or
   `{"found": false, checked: N, watching: {...}}`

## Tool schema

| arg | type | required | notes |
|---|---|---|---|
| `address` | string | ✓ | receiving address (base58) |
| `expected_amount` | number | ✓ | SOL or SPL ui amount |
| `mint` | string | | SPL mint; omit or `"SOL"` for native |
| `reference` | string | | memo/reference substring, e.g. `"Invoice #412"` |
| `since_unix` | integer | | ignore older transactions |
| `tolerance` | number | | relative, default `0.005` |
| `scan_limit` | integer | | default 25, max 50 |

Config section (`config_read`): `rpc_url` — endpoint override; falls back to the
`rpc_url` arg, then public mainnet-beta.

## Permissions

`http_client` (RPC over host `wasi:http`, TLS host-side), `config_read`. Nothing
else. No sockets, no websockets — HTTP-only per the registry constraint.

## Engineering notes

The pure matching core (`src/payment_watch.rs`) has zero wasm imports and is
host-tested: 10 tests covering SOL/SPL deltas, tolerance bounds, failed-tx and
outgoing-transfer rejection, memo matching, mint/owner isolation, and request
builders. The component (`src/lib.rs`) is a thin I/O shim via `waki`.

Built and validated with the repo CI (`tools/ci/validate_components.sh
payment-watch`): tests 10/10, clippy clean (host + wasm), artifact
`payment_watch.wasm` ≈ 344 KiB.
