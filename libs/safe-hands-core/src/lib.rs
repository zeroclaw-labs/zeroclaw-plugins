//! Safe Hands core: deterministic Solana transaction-authorization logic.
//!
//! Every Safe Hands plugin is a thin `#[cfg(target_family = "wasm")]` shim over
//! this crate. Nothing here depends on wasm, so the full engine compiles and
//! tests on the host with a plain `cargo test`.
//!
//! Design rules (non-negotiable):
//! - Deny by default. Any input the engine cannot fully explain is a failure.
//! - Policy comes from the operator's host-injected config, never from caller
//!   arguments.
//! - Amounts are raw smallest-unit integers. No floats, no fiat, no oracles in
//!   the decision path.
//!
//! Build (component, via a plugin): `cargo build --target wasm32-wasip2 --release`

#![forbid(unsafe_code)]

pub mod codec;
pub mod crypto;
pub mod policy;
pub mod rpc;
