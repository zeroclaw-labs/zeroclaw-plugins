//! depin-attest — a ZeroClaw T1 tool plugin: a sensor reading becomes an
//! UNSIGNED Solana Memo attestation transaction that a human (or a Squads
//! multisig) signs. No key ever exists in this plugin.
//!
//! Self-contained: the pure, wasm-free core (JSON-RPC over a mockable
//! `HttpClient`, encoding, instructions, attestation, shaping, sanitization)
//! lives here at the crate root and is exercised by plain `cargo test`; the
//! thin `#[cfg(target_family = "wasm")]` shim wires it to the `tool-plugin`
//! WIT world with `wit-bindgen` + the blocking `waki` client.

pub mod attest;
pub mod encode;
pub mod instructions;
pub mod rpc;
pub mod sanitize;
pub mod shape;

pub mod core;

#[cfg(target_family = "wasm")]
mod shim;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("http error: {0}")]
    Http(String),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("untrusted content rejected: {0}")]
    Injection(String),
    #[error("invalid input: {0}")]
    Input(String),
}

/// The seam that keeps the core testable. The wasm shim implements this with
/// `waki`; host tests implement it with canned JSON fixtures.
pub trait HttpClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String, CoreError>;
}
