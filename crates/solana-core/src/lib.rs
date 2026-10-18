//! # solana-core
//!
//! The shared substrate for ZeroClaw's Solana plugins. `solana-sdk` and
//! `solana-client` do not compile to a `wasm32-wasip2` WIT component, so this
//! crate hand-rolls the pieces a plugin actually needs and keeps them
//! **host-testable**:
//!
//! - [`base58`], [`base64`], [`shortvec`] — the encodings, dependency-free.
//! - [`pubkey`] — the 32-byte key type and the native program ids.
//! - [`rpc`] — a JSON-RPC client over a mockable [`rpc::RpcTransport`], so plugin
//!   logic is tested against [`rpc::MockTransport`] with no network.
//! - [`mint`] — SPL Token / Token-2022 mint decoding, including TLV extensions.
//! - [`instruction`], [`message`], [`programs`], [`nonce`] — unsigned
//!   (durable-nonce-capable) transaction construction.
//! - [`shape`] — compact output formatting, so a tool returns ~200 tokens, not
//!   40KB of raw JSON.
//!
//! ## The one wasm dependency
//!
//! Only [`transport::WakiTransport`] (behind `cfg(target_family = "wasm")`)
//! pulls in `waki` for `wasi:http`. Everything else is pure Rust. `cargo test`
//! on the host exercises the whole crate without a wasm toolchain and without
//! touching the network.

pub mod base58;
pub mod base64;
pub mod error;
pub mod instruction;
pub mod message;
pub mod mint;
pub mod nonce;
pub mod programs;
pub mod pubkey;
pub mod rpc;
pub mod shape;
pub mod shortvec;

#[cfg(all(target_family = "wasm", feature = "http"))]
pub mod transport;

pub use error::{CoreError, Result};
pub use pubkey::Pubkey;
