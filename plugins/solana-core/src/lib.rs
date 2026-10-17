//! solana-core — thin Solana toolkit for wasm32-wasip2 components.
//!
//! Pure core (no wasm dependency): JSON-RPC shapes, base58, borsh helpers,
//! versioned-transaction construction, blockhash/durable-nonce handling.
//! The `rpc` module uses `waki` (blocking wasi:http) when compiled for wasm,
//! or `ureq` on the host for `cargo test`.
//!
//! # Design
//!
//! - Zero `solana-sdk` dependency — avoids the wasm compilation pain
//!   described in the ZeroClaw bounty traps. Every struct is hand-rolled
//!   serde-compatible with the Solana JSON-RPC wire format.
//! - Every function returns the ~200 tokens a model needs, not the 40KB
//!   the RPC sent. Response shaping is built-in.
//! - Blockhash expiry is handled via durable-nonce accounts (see `nonce`).

pub mod rpc;
pub mod types;
pub mod tx;
pub mod nonce;

// Re-export key types
pub use types::*;
pub use rpc::SolanaRpc;
pub use tx::{
    build_transfer_tx,
    build_solana_pay_url,
    TxBuilder,
};
pub use nonce::DurableNonceManager;