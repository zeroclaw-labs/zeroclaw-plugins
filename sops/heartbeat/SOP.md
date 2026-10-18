# Heartbeat

A liveness watchdog for the kiosk's attestation stream — the inverse gate of the
payment loop.

## Flow

```
cron (every 10 min)
   │
   ▼
kiosk_watch(mode="heartbeat", device_address, max_silence_s=1800)
   │
   ├── success == true   → LIVE (newest attestation is fresh) → do nothing
   │
   └── success == false  → STALE or MISSING → notify_operator(...)
```

## What it catches

- **STALE** — the device is still on-chain but hasn't attested within
  `max_silence_s` (here, 30 min): sensor hung, connectivity lost, or the attestation
  loop crashed.
- **MISSING** — no attestations found at all for the device address: never provisioned,
  or wrong address configured.

Both are operational failures the operator wants to know about immediately, so the
alert step fires on `success == false` — the mirror image of the payment loop, which
acts on `success == true`.

## Adapting it

- Point `device_address` at the same address `kiosk_attest` writes its chain to.
- Tune `max_silence_s` to a small multiple of your sensor-loop cadence (e.g. 6× a 5-min
  loop = 30 min) so one missed reading doesn't page you, but a dead device does.
- `notify_operator` stands in for whatever channel plugin you use (Telegram, email, …).
