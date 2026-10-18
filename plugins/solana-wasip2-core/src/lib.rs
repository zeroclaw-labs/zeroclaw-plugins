//! Solana wire-format primitives that actually compile for `wasm32-wasip2`.
//!
//! `solana-sdk` does not build inside a WIT component, so every ZeroClaw plugin
//! that touches Solana ends up hand-rolling the same base58 decoding, the same
//! compact-u16 encoder, the same JSON-RPC envelope handling — each with its own
//! private bounds-checking bugs. This crate is those primitives, written once.
//!
//! # What this crate will never do
//!
//! - **No signing.** No private keys, no keypairs, no signature generation.
//! - **No network I/O.** The host owns `wasi:http` and the permission gate.
//! - **No authority of any kind.** Parsing and serialization only.
//!
//! That boundary is the reason it is safe for plugins to share. A shared crate
//! that could sign or send would concentrate exactly the authority the
//! component model exists to keep split up. Transactions built here are
//! **unsigned by construction** — the signature slots are zeroed, so a host or
//! a human must approve before anything can happen.
//!
//! # Failure philosophy
//!
//! Every parser here fails **closed**. Malformed input is an `Err` with a
//! message naming what was wrong; it is never a best-effort guess, a silent
//! truncation, or an empty `Ok`. In a component whose output feeds a model that
//! may act on it, a confident wrong answer is worse than an error.

pub mod b64;
pub mod hash;
pub mod pubkey;
pub mod shortvec;
pub mod tx;

pub use pubkey::Pubkey;
