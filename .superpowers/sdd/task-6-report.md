# Task 6 Report: depin-attest pure policy + memo payload

## Status

Implemented `plugins/depin-attest/` as a standalone Rust plugin crate matching the
`redact-text` layout: `[workspace]`, `cdylib` + `rlib`, MIT license, manifest,
stub README, empty wasm component module, host-testable pure policy module, and
vendored `solana_core` source under `src/vendor/solana_core/`.

No Task 7 RPC execution or wasm execution shim was implemented.

## Behavior Covered

- Default metric allowlist when `allowed_metrics` is absent:
  `temperature,humidity,uptime,pressure,air_quality`.
- Present-but-empty `allowed_metrics` refuses with `allowed_metrics is empty`.
- `period_bucket(unix_secs)` uses `floor(unix_secs / 300)`.
- Readings render with up to 6 decimal places and trimmed trailing zeros.
- Attestation hash is SHA-256 hex of
  `{device_id}|{metric}|{reading_str}|{unit}|{period}`.
- Memo format is
  `{prefix}|{device_id}|{metric}|{reading_str}|{unit}|{period}|{hash12}`.
- Memo UTF-8 payloads over 566 bytes refuse.
- Unknown JSON arg fields refuse.
- Prompt-injection fields `payer`, `nonce_account`, and `private_key` in args refuse.
- `max_abs_reading` defaults to `1_000_000.0` and rejects values outside the cap.

## TDD Evidence

RED:

```text
cargo test --manifest-path plugins/depin-attest/Cargo.toml
error[E0583]: file not found for module `attest`
```

GREEN:

```text
cargo test --manifest-path plugins/depin-attest/Cargo.toml
test result: ok. 8 passed; 0 failed
test result: ok. 2 passed; 0 failed
```

Final verification was clean with no warnings.

## Concerns

The vendored `solana_core` currently uses crate-root paths internally. Task 6
keeps the requested `#[path = "vendor/solana_core/lib.rs"] mod solana_core;`
wiring and adds crate-root path aliases for the vendored modules so the copied
tree compiles without editing generated vendor files.
