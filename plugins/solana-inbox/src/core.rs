//! Re-export of the pure core, which now lives in its own crates.io crate
//! (`solana-inbox-core`) so any other ZeroClaw plugin can reuse the same
//! Solana JSON-RPC response parser without importing this component's
//! wit-bindgen + waki stack.
//!
//! The re-export preserves the existing `solana_inbox::core::*` import
//! path used throughout the tests and the WASM shim in `lib.rs`.

pub use solana_inbox_core::*;
