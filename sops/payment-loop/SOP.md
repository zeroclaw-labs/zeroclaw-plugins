# Payment loop

The core ProofKiosk safety loop: **money must be verified on-chain before anything
physical happens.**

## Flow

```
cron (every 10s)
   │
   ▼
kiosk_watch(reference, expected_amount, window_s)
   │
   ├── success == false  → PENDING / EXPIRED / MISMATCH / RPC error → do nothing, poll again
   │
   └── success == true   → relay_pulse(pin_ms=400) → 🥤 item dispensed
```

## Why it is safe

- The relay step's `when` gates on `$.steps.1.success == true`. `kiosk_watch` sets
  `success = true` **only** for a transaction that credits the exact `expected_amount`
  of the operator's USDC mint to the operator's address, referencing this charge, at the
  configured finality. Pending, expired, mismatch, and **RPC failure** all yield
  `success = false`, so the relay never fires on a guess.
- `requires_confirmation = false` is deliberate: the on-chain verification *is* the
  confirmation. There is no human in the actuation path, and there does not need to be.
- The agent holds no key. It cannot move funds; it can only read the chain and pulse a
  GPIO pin after the chain says paid.

## Adapting it

- `reference` / `expected_amount` come from the preceding `kiosk_charge` call for this
  sale. In a full deployment the charge step writes them into the SOP context.
- Raise `finality` to `finalized` in `[plugins.kiosk-watch.config]` if you want economic
  irreversibility before dispensing (adds ~13s).
- `pin_ms` and the relay tool name depend on your hardware wiring (see the Pi build:
  `--features hardware,peripheral-rpi`).

## Open item

The exact `when:` field path (`$.steps.1.success`) is pending confirmation of how the
host exposes a prior step's `ToolResult` fields to `when:` expressions — the one
maintainer question on this PR. The intent is unambiguous: gate on the single boolean.
