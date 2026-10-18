# Sensor loop

Turn a physical sensor into a tamper-evident on-chain record.

## Flow

```
cron (every 5 min)
   │
   ▼
bme280_read  →  { temp_c, humidity, ... }
   │
   ▼
kiosk_attest(kind="reading", metric="temp_c", value=…)
   │
   ▼
unsigned durable-nonce memo tx  →  signed & submitted by the operator signer
   │
   ▼
memo on-chain: {v, dev, seq, ts, metric, val, prev}  (seq/prev link the chain)
```

## Why it is trustworthy

- Each attestation memo carries `seq` and `prev` (the previous attestation's landed
  signature), so the readings form an ordered chain anchored on-chain. A missing or
  re-ordered reading is detectable by walking the chain.
- The transaction uses a **durable nonce** instead of a recent blockhash, so an
  attestation built now stays valid to submit later without a fresh blockhash — the Pi
  can attest even across brief connectivity gaps.
- `kiosk_attest` emits the transaction **unsigned** (zero signatures). The agent never
  signs; a separate operator signer does. The agent cannot forge or move anything.
- The attestation transaction contains **only** the Memo and System (advance-nonce)
  programs. A transfer is not expressible — this is enforced by a structural test in the
  plugin.

## Status

`kiosk_attest` is the next component in this PR series. This SOP is published now so the
end-to-end wiring (sensor → attestation) is reviewable alongside the payment loop.
