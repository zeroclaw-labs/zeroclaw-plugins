# ProofKiosk — a pay-to-actuate, self-attesting kiosk on Solana

[![proofkiosk-ci](https://github.com/Sushant6095/zeroclaw-plugins/actions/workflows/proofkiosk-ci.yml/badge.svg?branch=feat/proofkiosk)](https://github.com/Sushant6095/zeroclaw-plugins/actions/workflows/proofkiosk-ci.yml)

ProofKiosk is a ZeroClaw agent that **sells a physical item for USDC, delivers it only
after the payment is verified on-chain, and writes tamper-evident attestations of what
it did** — while the agent never holds a spendable key.

Every plugin is **channel-agnostic** (works on any ZeroClaw channel — Telegram,
Discord, Matrix, WhatsApp, email; demoed on Telegram) and **useful standalone from a
laptop**: `kiosk-watch` alone answers "is invoice X paid?", `kiosk-attest` alone
notarizes arbitrary readings/events, `kiosk-charge` alone issues Solana Pay requests.
See each plugin's README.

It is a *system*, not a single plugin. Three small WIT tool plugins, one shared pure
crate:

| Component | Tier | Question it answers | Network | Status |
|---|---|---|---|---|
| [`plugins/kiosk-charge`](plugins/kiosk-charge) | T1 | "What should the customer pay?" → a Solana Pay `solana:` URL | **none** | shipped |
| [`plugins/kiosk-watch`](plugins/kiosk-watch) | T0 | "Did the money actually arrive?" → verified/pending/mismatch | read-only RPC | shipped |
| [`plugins/kiosk-attest`](plugins/kiosk-attest) | T1 | "Prove what happened." → hash-chained, durable-nonce memo tx (unsigned) | read-only RPC | shipped |
| [`crates/kiosk-core`](crates/kiosk-core) | — | shared pure substrate (base58/base64, Solana Pay, memo/nonce/message, JSON-RPC seam, shaping) | — | shipped |

### Tests & artifacts (all green, no network in tests)

| Component | Tests | Clippy `-D warnings` | wasm32-wasip2 |
|---|---|---|---|
| kiosk-core | 55 (incl. property + fuzz) | clean | — (rlib) |
| kiosk-charge | 12 | clean | 208 KB ✔ <250 KB |
| kiosk-watch | 24 | clean | 347 KB (bundles HTTP/TLS client) |
| kiosk-attest | 16 | clean | 383 KB (bundles HTTP/TLS client) |
| **total** | **107** | **clean** | `scripts/wasm-size.sh` |

The two safety primitives that make the whole thing interesting:

1. **The agent never holds a spendable key.** Money flows customer wallet → merchant
   wallet directly; the agent only prints the invoice. Jailbreaking the chatbot yields
   no till to raid — the recipient is fixed by operator config, never model input.
2. **The relay fires only on a verified on-chain payment**, not on what the agent
   *believes*. `kiosk-watch` returns `success == true` **iff** the exact USDC amount
   reached the merchant at the configured finality; the actuation SOP gates on that one
   boolean. RPC failure, pending, or mismatch all fail closed.

---

## The three-rung ladder — start with zero hardware

You do not need a Raspberry Pi, a sensor, or a relay to reproduce the core of
ProofKiosk. Each rung is independently runnable; **rung 1 is an evening on a laptop.**

### Rung 1 — laptop only (no hardware)

Prove the payment rail end to end against localnet or devnet:

1. `scripts/devnet-setup.sh` — spins up a validator (or targets devnet), mints a test
   USDC-like SPL token, and prints the config to paste.
2. Call `kiosk_charge` → get a `solana:` URL → pay it from any devnet wallet.
3. Call `kiosk_watch` with the returned `reference` → watch it flip from `PENDING` to
   `PAID` once the transfer confirms.

No GPIO, no sensor. This is the full "ask for money → confirm money" loop.

### Rung 2 — + a sensor (attestation)

Add a BME280 (temp/humidity) or any sensor tool. `kiosk-attest` writes each reading as
a hash-chained, durable-nonce memo transaction, so the environmental record is
tamper-evident on-chain. See `sops/sensor-loop/`.

### Rung 3 — + a relay (physical delivery)

Add a GPIO relay on a Raspberry Pi. The payment-loop SOP (`sops/payment-loop/`) fires
the relay for exactly one condition: `kiosk_watch` returned `success == true`. The drink
drops only after the chain says paid.

---

## 5-minute quickstart (rung 1, laptop)

```bash
rustup target add wasm32-wasip2
./scripts/devnet-setup.sh                 # localnet + test mint; prints config to paste
# paste the printed [plugins.*.config] blocks into your ZeroClaw config
cd plugins/kiosk-charge && cargo test && cargo build --target wasm32-wasip2 --release
cd ../kiosk-watch      && cargo test && cargo build --target wasm32-wasip2 --release
# build the host with the plugin runtime, then in chat:
#   "sell a cold drink"   -> kiosk_charge returns a solana: URL (scan/tap, pay)
#   "is it paid?"         -> kiosk_watch flips PENDING -> PAID once it confirms
./scripts/verify-no-network.sh            # proves kiosk-charge imports no wasi:http
```

## Minimal config

Defaults keep the required config tiny:

```toml
# kiosk-charge — the ONLY required key:
[plugins.kiosk-charge.config]
merchant_address = "YOUR_MERCHANT_PUBKEY"   # usdc_mint, cap, label all default

# kiosk-watch — TWO required keys:
[plugins.kiosk-watch.config]
rpc_url          = "https://api.devnet.solana.com"
merchant_address = "YOUR_MERCHANT_PUBKEY"   # usdc_mint defaults to USDC, finality to "confirmed"
```

## Copy-paste config (full)

ZeroClaw injects each plugin's `[plugins.<name>.config]` block into `execute` as the
flat `__config` map. The model never sees or sets these — recipient, mint, and RPC are
operator-owned.

```toml
# kiosk-charge (T1) — builds the Solana Pay charge. Zero network, zero secrets.
[plugins.kiosk-charge.config]
merchant_address = "YOUR_MERCHANT_PUBKEY"          # base58, 32 bytes — where funds land
usdc_mint        = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # mainnet USDC; use your devnet mint when testing
price_list       = "cold_drink:1.5, snack:0.75"    # item id -> USDC amount
max_amount_usdc  = "10"                            # cap for free-amount charges
label            = "Kiosk 01"                      # shown in the customer's wallet

# kiosk-watch (T0) — verifies the payment on-chain before actuation.
[plugins.kiosk-watch.config]
rpc_url          = "https://api.devnet.solana.com" # your RPC endpoint
merchant_address = "YOUR_MERCHANT_PUBKEY"          # must match the charge recipient
usdc_mint        = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # expected mint
finality         = "confirmed"                     # processed | confirmed | finalized
```

Run `scripts/devnet-setup.sh` to generate real values for `merchant_address`,
`usdc_mint`, and `rpc_url`.

---

## Building

Each plugin is a standalone `wasm32-wasip2` WIT component (see each plugin's README):

```bash
rustup target add wasm32-wasip2
cd plugins/kiosk-charge && cargo test && cargo build --target wasm32-wasip2 --release
cd plugins/kiosk-watch  && cargo test && cargo build --target wasm32-wasip2 --release
```

The stock ZeroClaw binary has no plugin host — build the runtime from source with the
plugin host enabled:

```bash
# Laptop (rungs 1–2): host the wasm plugins
cargo build --release --features plugins-wasm,plugins-wasm-cranelift

# Raspberry Pi (rung 3): add the GPIO/peripheral tools for the relay
cargo build --release --features plugins-wasm,plugins-wasm-cranelift,hardware,peripheral-rpi
```

---

## Proving the claims, not just asserting them

- `scripts/verify-no-network.sh` builds `kiosk-charge` for `wasm32-wasip2` and asserts
  its component imports **zero** `wasi:http` interfaces — the T1 "no network" claim is
  checked against the binary, not taken on faith. (`kiosk-watch`, by contrast, does
  import `wasi:http` — as a read-only RPC client should.)
- Every fail-closed behavior in each plugin is a host test (`cargo test`, no network):
  53 tests across the suite today.

## SOP examples

Ready-to-adapt Standard Operating Procedures live in `sops/`:

- `sops/payment-loop/` — cron → `kiosk_watch` → branch on `paid == true` → relay pulse.
- `sops/sensor-loop/` — cron → read sensor → `kiosk_attest` (attestation).
- `sops/heartbeat/`    — cron → `kiosk_watch` heartbeat → alert operator if stale.
