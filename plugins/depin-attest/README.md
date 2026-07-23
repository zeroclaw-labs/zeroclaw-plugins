# depin-attest

**Custody tier: T1** — builds an unsigned Solana transaction. It never holds,
receives, or uses a private key, and it never calls `sendTransaction`.

A ZeroClaw **WIT tool** plugin implementing the `tool-plugin` world from
`wit/v0`, laid out identically to [`redact-text`](../redact-text), the
canonical reference plugin. Copy `redact-text` for a config-driven starting
point; copy this one if your tool also needs to talk to a chain.

## What it does

Exposes a single tool, `depin_attest`, that turns any ZeroClaw host device
(a Raspberry Pi with a sensor, most concretely) into a Solana-reporting DePIN
node:

1. Takes a sensor reading (`device_id`, `sensor_type`, `value`, `unit`) as
   tool arguments — the sensor read itself happens upstream, outside this
   plugin, via whatever hardware-facing tool the host exposes.
2. Fetches the current slot and a recent blockhash from a Solana RPC endpoint
   (`getLatestBlockhash`) over the host's `wasi:http` — no chain SDK, no
   `solana-sdk`, just a JSON-RPC POST and a hand-rolled base58 decoder.
3. Derives a **replay-guard nonce**: `sha256(device_id || "|" || slot_le)`.
   The same device attesting at the same slot always gets the same nonce,
   so a resubmission is trivially detectable downstream.
4. Builds a Memo-program instruction committing
   `zc-depin|<device>|<sensor>|<value><unit>|slot:<slot>|nonce:<hex>` and
   wraps it in a **v0 message with zero signatures** — a hand-rolled
   `compact-u16`/`MessageV0` serializer, no `solana-sdk`.
5. Returns the unsigned transaction as base64, plus the attestation hash,
   memo text, and nonce, in a JSON blob sized to stay well under 300 tokens.

## Why this design

- **No solana-sdk.** The Memo instruction needs no accounts and no complex
  account-resolution logic; a full SDK would pull in a keypair type, ed25519
  signing, and a dependency tree far larger than this tool's actual surface.
  Everything on the wire — shortvec, `MessageHeader`, `MessageV0`, base58,
  base64 — is ~150 lines of hand-rolled, host-testable code (`src/tx.rs`,
  `src/memo.rs`).
- **Pure core / thin shim.** `src/attest.rs`, `src/memo.rs`, and `src/tx.rs`
  have zero wasm dependency and compile with a plain `cargo test`. Only
  `src/lib.rs`'s `#[cfg(target_family = "wasm")] mod component` touches
  `wit-bindgen` or `waki` (the blocking `wasi:http` client), mirroring the
  pattern used by every HTTP-calling plugin in this repo (`notion`, `slack`,
  `telegram`, …).
- **T1 by construction, not by convention.** There is no signing code
  anywhere in this crate, and no submit path. An LLM cannot prompt-inject its
  way into a `sendTransaction` call that does not exist in the binary.

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `rpc_url` | `https://api.mainnet-beta.solana.com` | Solana RPC endpoint used for `getLatestBlockhash`. Point this at your own RPC provider to avoid public-endpoint rate limits. |
| `fee_payer` | *(none)* | Base58 pubkey to use as fee-payer in the unsigned transaction. If omitted, a zero-byte placeholder is used — you **must** replace it before signing. |

Requires the `config_read` permission to read `rpc_url` from this plugin's
own jailed config section; without it, the plugin falls back to the public
mainnet-beta endpoint.

## Tool arguments

```json
{
  "device_id": "pi-node-001",
  "sensor_type": "temperature",
  "value": 23.4,
  "unit": "celsius"
}
```

`sensor_type` is one of `temperature | humidity | uptime | energy_kwh |
custom`. The schema sets `additionalProperties: false`; unknown fields are
rejected by both the JSON Schema handed to the LLM and, independently, by
`#[serde(deny_unknown_fields)]` on the Rust side — see the threat model
below.

## Wiring diagram

```
[DHT22 sensor] ── GPIO 4 ──▶ [Raspberry Pi]
                                   │
                          ZeroClaw daemon
                                   │
                          depin-attest plugin
                       (device_id, sensor_type,
                          value, unit  ──▶
                       fetch slot + blockhash
                            over wasi:http  ──▶
                       build Memo instruction
                       build unsigned v0 tx)
                                   │
                    unsigned Memo tx, base64 (T1)
                                   │
                       human approves in wallet
                        (Phantom / CLI / multisig)
                                   │
                        Solana mainnet (Memo program)
```

## Threat model

- **The plugin cannot move funds or sign anything.** It has no key material
  and no code path that produces a signature. Compromising this plugin's
  logic (or the LLM calling it) can, at worst, produce a malformed or
  misleading unsigned transaction for a human to reject at the signing step.
- **The RPC call is read-only and unauthenticated.** `getLatestBlockhash`
  reveals no secrets; a malicious or MITM'd RPC endpoint can at most feed a
  stale/wrong blockhash or slot, which either makes the resulting tx
  unsubmittable (bad blockhash) or shifts the replay nonce — it cannot forge
  a signature or exfiltrate anything, since nothing secret is ever sent.
- **Prompt injection via tool arguments** is the main attack surface this
  plugin's own tests target. Two guards:
  1. `additionalProperties: false` in the JSON Schema plus
     `#[serde(deny_unknown_fields)]` on `AttestArgs` — an attacker cannot
     smuggle an extra field (e.g. a fake `private_key` or `submit: true`)
     into the arguments; parsing fails closed instead of ignoring or
     silently accepting it.
  2. No submit/sign path exists in the crate at all, so no injected
     instruction text can talk this tool into becoming a T2 (auto-submit)
     plugin — see `prompt_injection_sign_and_submit_ignored`.
- **Replay guard is advisory, not consensus-enforced.** The nonce lets a
  downstream system (indexer, dashboard, submission queue) detect and drop a
  duplicate attestation for the same `(device_id, slot)`; it is not a Solana
  program constraint, since the Memo program has no on-chain state to check
  against. A determined operator could still submit the same unsigned tx
  twice through their wallet — this plugin's job is only to make that
  detectable, not to make it impossible.

## Prompt-injection transcript

`prompt_injection_unknown_field_rejected` — an attacker-controlled tool call
tries to smuggle a `private_key` field past the parser:

```rust
let malicious = r#"{
    "device_id": "pi-node-001",
    "sensor_type": "temperature",
    "value": 23.4,
    "unit": "celsius",
    "private_key": "EXFILTRATE_THIS"
}"#;
let result: Result<AttestArgs, _> = serde_json::from_str(malicious);
assert!(result.is_err(), "unknown field should be rejected");
```

```
Error("unknown field `private_key`, expected one of `device_id`, `sensor_type`, `value`, `unit`", ...)
test prompt_injection_unknown_field_rejected ... ok
```

Fails closed: the extra field is rejected outright rather than silently
dropped or accepted, and `execute` in `src/lib.rs` returns
`ToolResult { success: false, error: Some("invalid arguments: ...") }`
without ever reaching the RPC call or building a transaction.

## What fought us on wasm32-wasip2

- **`solana-sdk` does not target `wasm32-wasip2`** (it pulls in native
  ed25519/curve25519 code and assumes a POSIX-ish environment). Rather than
  patch around that, this plugin never depends on it — the Memo instruction
  and v0 message format are simple enough to hand-roll (~150 lines total),
  which also keeps the binary small and fully host-testable.
- **`waki` must stay wasm-only.** It's gated behind
  `[target.'cfg(target_family = "wasm")'.dependencies]` in `Cargo.toml` so
  `cargo test` on the host never tries to compile a `wasi:http` client that
  doesn't exist outside the component runtime — the same pattern as
  `notion`, `slack`, and every other HTTP-calling plugin here.
- **`flatten` + `deny_unknown_fields` don't compose reliably in serde.**
  The obvious `#[serde(flatten)] attest: AttestArgs` alongside a `__config`
  field defeats `deny_unknown_fields`'s guarantee in edge cases. `lib.rs`
  instead splits the raw JSON manually (`split_execute_args`), popping
  `__config` out of the `serde_json::Value` before deserializing the rest
  into `AttestArgs`, so the fail-closed guarantee holds unconditionally.

## What to build next

- A companion sensor-read tool (or host WIT interface) so the full pipeline
  — physical read → attest → sign → submit — can be demonstrated end to end
  on real Raspberry Pi hardware.
- Optional multi-reading batching (one memo per N readings) to amortize
  transaction fees for high-frequency sensors.
- A T2 companion plugin, gated behind an explicit approval-queue permission,
  that takes an already-signed transaction from this plugin's output and
  submits it — kept strictly separate so this plugin's T1 guarantee never
  has to change.

## Test table

| Test | What it proves | Result |
|---|---|---|
| `nonce_is_deterministic` | Same device + slot → same nonce | PASS |
| `nonce_differs_by_slot` | Replay guard changes across slots | PASS |
| `nonce_differs_by_device` | Replay guard is per-device | PASS |
| `memo_format_includes_all_fields` | On-chain memo carries device/sensor/value/slot/nonce and stays compact | PASS |
| `attestation_hash_is_deterministic_and_matches_memo` | Hash is stable and hex-encoded correctly | PASS |
| `tx_serializes_without_panic` | v0 message has the correct `0x80` version prefix and zero signatures | PASS |
| `tx_base64_roundtrips_expected_length` | Base64 output is well-formed | PASS |
| `prompt_injection_unknown_field_rejected` | Fails closed on an attacker-added field | PASS |
| `prompt_injection_sign_and_submit_ignored` | No T2 (sign/submit) path exists in the produced data | PASS |
| `summary_stays_compact` | Tool output summary fits a small context budget | PASS |

```
running 10 tests
..........
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Layout

```
src/attest.rs   # pure logic: nonce derivation, memo/attestation hash — no wasm deps
src/memo.rs     # Memo program instruction builder — no wasm deps
src/tx.rs       # v0 transaction serializer + base64 — no wasm deps
src/lib.rs      # thin #[cfg(target_family = "wasm")] component shim + RPC fetch
tests/          # host tests exercising the pure core
```

Build:

```bash
rustup target add wasm32-wasip2
cargo test                                    # pure core, no wasm toolchain needed
cargo build --target wasm32-wasip2 --release
```
