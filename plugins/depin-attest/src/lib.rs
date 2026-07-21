//! A ZeroClaw WIT tool plugin for DePIN attestation memo payloads.

pub mod attest;

#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/lib.rs"]
mod solana_core;

#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/error.rs"]
pub mod error;
#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/ix.rs"]
pub mod ix;
#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/keys.rs"]
pub mod keys;
#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/nonce.rs"]
pub mod nonce;
#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/rpc.rs"]
pub mod rpc;
#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/shape.rs"]
pub mod shape;
#[allow(dead_code, unused_imports)]
#[path = "vendor/solana_core/tx.rs"]
pub mod tx;

pub use error::{CoreError, CoreResult};

#[cfg(target_family = "wasm")]
mod component {}
