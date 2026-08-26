//! # solana-wasi-core
//!
//! Pure-Rust Solana primitives that compile anywhere Rust does — including
//! `wasm32-wasip2` WIT components, where `solana-sdk` / `solana-client` will
//! not follow you.
//!
//! Everything in this crate is a pure function or a plain struct:
//! no network, no wasm bindings, no global state. The plugins that sit on top
//! of it are thin shims; this crate is where the logic (and the tests) live.
//!
//! Modules:
//! - [`pubkey`] — 32-byte ed25519 public keys + base58.
//! - [`encoding`] — compact-u16 (shortvec) and base64 helpers.
//! - [`instruction`] — `AccountMeta`/`Instruction` + builders for the System,
//!   SPL-Token, ATA and Memo programs (hand-rolled byte layouts).
//! - [`message`] — legacy message compilation and unsigned-transaction
//!   serialization (base64), including durable-nonce-anchored messages.
//! - [`nonce`] — durable nonce account state parsing.
//! - [`rpc`] — JSON-RPC request builders and response parsers (pure: they
//!   take/return `serde_json::Value`, the caller does the I/O).
//! - [`policy`] — the fail-closed spend policy engine (allowlists, caps).
//! - [`shape`] — output shaping so tool results stay ~200 tokens, not 40KB.

pub mod encoding;
pub mod instruction;
pub mod message;
pub mod nonce;
pub mod policy;
pub mod pubkey;
pub mod rpc;
pub mod shape;
pub mod signing;
