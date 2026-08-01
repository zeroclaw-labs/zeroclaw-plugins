//! Pure Solana primitives used by the guard — no WASM / WIT deps.
//! Host-testable with a plain `cargo test`.

pub mod base58;
pub mod base64;
pub mod narrate;
pub mod programs;
pub mod pubkey;
pub mod risk;
pub mod tx;

pub use narrate::narrate_transaction;
pub use risk::{assess, Finding, Severity};
pub use tx::{DecodeError, DecodedTransaction};
