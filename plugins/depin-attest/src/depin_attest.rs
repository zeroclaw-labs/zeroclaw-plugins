//! Pure attestation core. No wit-bindgen or wasm dependency so it compiles and
//! tests on the host with a plain `cargo test`, while the wasm component reuses
//! the exact same logic through `lib.rs`.
//!
//! This module contains the full Palinurus depin-attest logic:
//! - `AttestConfig` — plugin config (RPC endpoint, SAS PDAs, custody mode, nonce account).
//! - `SensorReading` — the schema-encoded attestation payload + nonce derivation.
//! - `build_attest_ix` / `build_memo_ix` — Solana instruction construction.
//! - `execute_t1` / `execute_t2` — the two custody flows (T1 unsigned, T2 signed+submitted).
//! - Custody guards (T2) — program allowlist, session-key identity, lamport cap, daily cap.
//!
//! All logic lands here slice by slice (PLAN-2: slices B–G). The shim in `lib.rs`
//! wires it to the WIT `tool-plugin` world + `log-record` + `waki` RPC.