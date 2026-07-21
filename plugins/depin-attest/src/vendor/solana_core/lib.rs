//! Pure Solana substrate for ZeroClaw wasm tool plugins.
//! No wit-bindgen, waki, or solana-sdk.

pub mod error;
pub mod ix;
pub mod keys;
pub mod nonce;
pub mod rpc;
pub mod shape;
pub mod tx;

pub use error::{CoreError, CoreResult};
