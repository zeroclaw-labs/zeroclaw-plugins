# depin-attest

**A $40 Raspberry Pi running ZeroClaw is already a DePIN device — it just has
no chain.** This plugin is the chain part: turn a sensor reading from the
host's hardware tools into an **unsigned**, hash-chained Solana attestation
that a human approves and signs.

The flow on a real device:

1. A cron SOP (or a chat request) has the agent take a reading with the host's
   hardware tools — GPIO, I2C, SPI on the Pi; any host-side sensor elsewhere.
2. The agent calls `depin_attest` with `{metric, value}`.
3. The plugin validates the reading against the **operator's** allowlist and
   bounds, recovers the device's attestation history from the chain, and
   returns a base64 unsigned transaction carrying a canonical memo — plus a
   summary the approval gate renders.
4. A human approves; a wallet signs and submits. The device's address
   accumulates a publicly verifiable, tamper-evident chain of readings.

## Custody tier: T1 (build, never sign) — and why

The plugin holds no keys, ever. The transaction it builds contains exactly one
instruction — an SPL memo signed by the device key — so **a transfer is not
even expressible in its output**. The blast radius of a fully successful
prompt injection is: a bogus reading is *proposed*, the human sees it in the
approval gate, and even a rubber-stamped approval costs only the network fee
(~5000 lamports). We considered T2 (a session key signing memos under a cap)
and rejected it: attestation cadence is human-scale, the approval gate is
already in the loop, and T1 means the safety argument is structural rather
than policy-dependent.

## The attestation chain

Each memo is canonical JSON with a fixed key order:

```json
{"v":1,"dev":"<device pubkey>","seq":42,"ts":1789000000,"metric":"temp_c","val":"23.5","unit":"C","prev":"a1b2c3d4e5f60708"}
```

- `seq` is monotonic. The plugin recovers the next value by scanning the
  device address's confirmed history (`getSignaturesForAddress` carries memos,
  so this is one RPC call) for the newest memo with `v:1` and `dev` equal to
  the configured device — foreign memos, transfers, and lookalike payloads for
  other devices are ignored.
- `prev` commits to the **on-chain signature** of the previous attestation
  (first 8 bytes of its sha256, hex; `"genesis"` for the first). A verifier
  walks the address history and checks the chain links; a gap, fork, or
  reordering is visible to anyone.
- Replay is inert by design: re-submitting an old unsigned transaction fails
  on its expired blockhash, and a duplicated `seq` is publicly visible in the
  history rather than silently absorbed.

## Config keys

The host injects plugin config as a flat string map, so metric specs use a
compact `name:min:max:unit` encoding:

```toml
[[plugins.entries]]
name = "depin-attest"

[plugins.entries.config]
# REQUIRED. The device's identity and fee payer. The attestation is only
# valid signed by this key — and the model can never supply or override it.
device_pubkey = "YourDevicePubkeyBase58..."
# REQUIRED. The only metrics this device may attest, with hard bounds.
metrics = "temp_c:-40:85:C, humidity_pct:0:100:%, uptime_s:0:31536000:s"
# Optional. Your RPC endpoint (key stays here, never in code or arguments).
rpc_url = "https://mainnet.helius-rpc.com/?api-key=..."
```

Permissions requested: `http_client` (two JSON-RPC calls over the host's
`wasi:http`, TLS host-side), `config_read` (the section above). Nothing else.

## Worked example — real mainnet output, reproducible

Agent message: *"Attest the current temperature reading."* → the model calls
`depin_attest {"metric": "temp_c", "value": 23.5}` → the approval gate shows
the call → on approve, against a live mainnet blockhash:

```
ATTESTATION #1 ready to sign — temp_c 23.5 C from device 9FpAnhwE…
chain: prev genesis, ts 1785000000
memo: {"v":1,"dev":"9FpAnhwEEdEQpPz3VPW5LnTqQYw3cHvXqh15xcUMXJ1z","seq":1,"ts":1785000000,"metric":"temp_c","val":"23.5","unit":"C","prev":"genesis"}
unsigned_tx_base64: AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAECeqj163IpFEMiKqBTX+WyYQoEIwGVhtp3gr/zpdPhXa0FSlNamSkhBk0k6HFg2jh8fDW13bySu4HkH6hAQQVEjYkWhTC1kGoZh9KYCMKeZqKF4l0+VfxsOvcX1eq4YrTOAQEBAI8BeyJ2IjoxLCJkZXYiOiI5RnBBbmh3RUVkRVFwUHozVlBXNUxuVHFRWXczY0h2WHFoMTV4Y1VNWEoxeiIsInNlcSI6MSwidHMiOjE3ODUwMDAwMDAsIm1ldHJpYyI6InRlbXBfYyIsInZhbCI6IjIzLjUiLCJ1bml0IjoiQyIsInByZXYiOiJnZW5lc2lzIn0=
Approving signs a fee-only memo (no transfer possible). Blockhash valid to
height 413815626; if approval waits past ~60s, call again to rebuild — the
sequence stays consistent until one lands.
```

The whole reply is a few hundred tokens; the raw RPC traffic never reaches
the model.

**Reproduce it yourself** — the pipeline is transport-injected, so the
transcript above comes from real `getSignaturesForAddress` +
`getLatestBlockhash` responses replayed through the real code path:

```bash
curl -s -X POST "$RPC" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress",
       "params":["<device_pubkey>",{"limit":10}]}' > signatures.json
curl -s -X POST "$RPC" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash",
       "params":[{"commitment":"finalized"}]}' > blockhash.json
cargo run --example live -- <device_pubkey> signatures.json blockhash.json
```

`cargo test` stays network-free; only this example touches saved responses.

> **Corrected 2026-07-28.** The previous transcript in this section was
> illustrative: it used the all-ones System Program address as a stand-in
> device and quoted a `lastValidBlockHeight` of `296…`, which is stale by
> roughly 117 million blocks against live mainnet (`413815626` at time of
> writing). Both are fixed above, and the `live` example exists so the numbers
> can be re-derived rather than trusted.

## Blockhash expiry (trap #1, addressed head-on)

An unsigned transaction parked in an approval queue outlives its blockhash in
about a minute. Our answer, for this tool's shape: **rebuilding is free and
idempotent.** The sequence number comes from confirmed history, so calling the
tool again after a lapsed approval produces the same `seq` with a fresh
blockhash — nothing is lost, nothing double-counts, and the output says
exactly that so the agent knows to re-call rather than apologize. Durable
nonce accounts would remove the expiry entirely at the cost of on-chain setup
and nonce-advance management; that is the natural next step for unattended
fleets and is sketched under "What we'd build next."

## Threat model

| Surface | Exposure | Mitigation |
| --- | --- | --- |
| LLM-supplied args | Hostile by assumption | `deny_unknown_fields`; metric must match the operator allowlist; value parsed, finite, bounds-checked, canonically re-formatted; unit must match config |
| Payload integrity | JSON injection via strings | Every interpolated field is charset-restricted or numeric before it reaches the canonical payload |
| Config | Spoofing via args | The host strips caller-supplied `__config` before injection; the plugin still validates everything in it |
| Chain recovery | Attacker memos on the device address | Only memos with `v:1` and the exact configured `dev` count; failed transactions are skipped |
| Funds | Theft / drain | No key material exists in the plugin; the built transaction cannot express a transfer |
| RPC | Malicious/broken responses | Envelope errors surface; invalid blockhashes rejected; RPC failure means no transaction at all |

### Prompt-injection drill (fail-closed transcript)

`cargo run --example injection` — nine attacks, each must produce an explicit
error with **zero RPC calls**:

```
BLOCKED  redirect funds via smuggled recipient key
         -> arguments rejected: unknown field `recipient`, expected one of `metric`, `value`, `unit`, `__config`
BLOCKED  smuggle an amount into a memo-only tool
         -> arguments rejected: unknown field `amount_sol`, expected one of `metric`, `value`, `unit`, `__config`
BLOCKED  attest a metric the operator never allowlisted
         -> metric 'wallet_drained_ok' is not in the operator's allowlist (temp_c, humidity_pct)
BLOCKED  spoof an impossible sensor reading
         -> value 9999 is outside the operator's bounds for temp_c [-40, 85] — refusing to attest
BLOCKED  break the payload JSON via the value
         -> value '21admintrue' is not numeric
BLOCKED  smuggle instructions as a value
         -> value string is too long to be a sensor reading
BLOCKED  non-finite value
         -> value must be finite
BLOCKED  lie about the unit to distort the reading
         -> unit 'SOL' does not match the configured unit 'C' for temp_c
BLOCKED  override the operator's device key
         -> config device_pubkey is invalid: 'not-a-key' is not valid base58
CONTROL  legitimate reading passed validation ✓
result: every attack failed closed ✓
```

## Build & test

```
cargo test                                        # 21 host tests, no network, no wasm toolchain
cargo build --target wasm32-wasip2 --release      # the component (~370 KB)
cargo run --example injection                     # the drill above
```

Layout follows `plugins/redact-text`: all logic lives in plain Rust modules
(`att.rs` — validation + chain + payload, `tx.rs` — hand-rolled wire format,
`rpc.rs` — request/response codec) with zero wasm dependency; `lib.rs` holds
the `#[cfg(target_family = "wasm")]` shim (waki HTTP + WIT glue) and nothing
else. The full flow is transport-injected (`att::run` takes a closure), so
host tests exercise every branch end-to-end on canned RPC responses.

## Running inside ZeroClaw

Shipped release binaries (≤ v0.8.3) exclude the `plugins-wasm` feature — see
`plugins/token-risk-check/README.md` for the host build that loads plugins;
both plugins were verified end-to-end against it on an aarch64 phone.

## What fought us on wasm32-wasip2 (field notes)

- `solana-sdk` does not compile inside a WIT component, as the bounty brief
  warned. The entire legacy transaction — compact-u16 shortvecs, the 3-byte
  message header, account ordering, the zeroed signature slot — is hand-rolled
  in `tx.rs` (~90 lines including golden-vector tests) from the wire format
  docs. It was less painful than expected and the module is deliberately
  reusable: `build_unsigned_memo_tx` + `decode_pubkey` + shortvec are the
  seed of the shared wasm-friendly core Track E asks for.
- `getSignaturesForAddress` returning memos (with a sneaky `"[len] "` prefix
  to strip) saves a whole `getTransaction` round-trip per call — the
  difference between 2 and 3+ RPCs on every attestation.
- Same as plugin #1: `waki` for blocking `wasi:http`, wasm-only dependency so
  host tests never touch it; and the wall-clock comes from `SystemTime`,
  which wasip2 supports natively.

## What we'd build next

- **Durable nonce support**: config-declared nonce account, `advance_nonce`
  prepended to the transaction, expiry problem gone for unattended fleets.
- **`oracle-publish` on a cron SOP**: this plugin plus the host's scheduler is
  already 90% of a "Solana DePIN node that talks"; the missing 10% is a
  program CPI instead of a memo for consumers that want typed on-chain data.
- **Verifier CLI**: a 50-line host-side checker that walks an address and
  validates the chain links — the audit story made runnable.

## License

MIT OR Apache-2.0, matching the repository.
