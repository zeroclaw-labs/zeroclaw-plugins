//! # aval-core
//!
//! Pure-Rust Solana substrate for the Aval suite of ZeroClaw tool plugins.
//!
//! Aval ("aval": the Brazilian Portuguese term for guaranteeing someone else's
//! obligation by co-signing it) is an approval rail for transacting agents:
//! the agent builds transactions anchored to durable nonce accounts so they
//! survive in a human approval queue indefinitely, and a read-only recheck
//! verifies them again at the moment of signature.
//!
//! Nothing in this crate touches wasm, HTTP, or the ZeroClaw WIT surface.
//! Network access is abstracted behind [`rpc::HttpPost`], which host tests
//! implement with fixtures and the wasm shims implement with `waki`.
//!
//! Deliberately not depended on: `solana-sdk`, `solana-client`, `borsh`,
//! `bs58`. The handful of byte layouts this suite needs (legacy messages,
//! five system-program instructions, SPL `TransferChecked`, the associated
//! token account program, nonce account state) are encoded by hand and pinned
//! by tests, which is what makes the wasm32-wasip2 build clean.

pub mod amount;
pub mod codec;
pub mod instruction;
pub mod message;
pub mod nonce;
pub mod pubkey;
pub mod rpc;
