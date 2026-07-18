//! Lending health tool plugin for ZeroClaw: read-only Solana lending position health.
//!
//! v0.1: Kamino positions via public HTTP API.
//! v0.2: Kamino positions via on-chain reads with hand-rolled borsh (planned).
//!
//! The pure parsing and policy core lives in [`lending_health`] with zero wasm
//! or HTTP dependency, so it compiles and tests on the host with plain
//! `cargo test`. The wasm component under `#[cfg(target_family = "wasm")]`
//! (added later) reuses that logic through a thin shim.

pub mod lending_health;
