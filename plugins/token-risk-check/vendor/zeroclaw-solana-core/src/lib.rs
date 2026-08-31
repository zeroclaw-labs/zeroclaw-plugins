//! Pure Rust Solana substrate: no `solana-sdk`, `solana-client`, or
//! `solana-program` dependency anywhere in this crate — only `borsh`,
//! `serde`/`serde_json`, `bs58`, and `base64`. Base58/Borsh primitives,
//! hand-rolled versioned-transaction wire format, durable-nonce transaction
//! building, JSON-RPC shaping over an injected `HttpTransport`, and
//! zero-copy Token-2022 mint parsing.
//!
//! This crate has no opinion about WIT, `wit-bindgen`, or any specific tool
//! plugin's `execute(args)`/config-injection contract — that orchestration
//! lives in each plugin's own pure core module (e.g.
//! `plugins/token-risk-check/src/token_risk.rs`), which imports this crate.
//! `zeroclaw-solana-core` itself builds and tests on a plain host target
//! with `cargo test`; it carries no wasm-only code, so nothing here requires
//! a wasm toolchain either.

pub mod crypto;
pub mod guardrails;
pub mod rpc;
pub mod transaction;

pub use crypto::{Blockhash, Pubkey, Signature};
pub use rpc::HttpTransport;
pub use transaction::VersionedTransaction;
