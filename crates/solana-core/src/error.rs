//! One error type for the whole core. Plugins map it to a `tool-result`
//! (`success: false`) rather than an `Err`, so a bad mint or a flaky RPC reads
//! back to the model as a normal, recoverable tool response.

use std::fmt;

/// Everything that can go wrong inside the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A base58 string was not valid base58, or decoded to the wrong length.
    Base58(String),
    /// A base64 payload (e.g. account data from the RPC) failed to decode.
    Base64(String),
    /// A value that must be a 32-byte pubkey was the wrong length.
    BadPubkey(String),
    /// Account/mint bytes were shorter than the layout requires.
    Layout(String),
    /// The transport (HTTP) failed before we got a JSON body back.
    Transport(String),
    /// The RPC returned a JSON-RPC `error` object.
    Rpc { code: i64, message: String },
    /// The RPC response was valid JSON but not the shape we expected.
    UnexpectedResponse(String),
    /// A caller-supplied argument was invalid (amount, decimals, etc.).
    Invalid(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Base58(m) => write!(f, "invalid base58: {m}"),
            CoreError::Base64(m) => write!(f, "invalid base64: {m}"),
            CoreError::BadPubkey(m) => write!(f, "invalid pubkey: {m}"),
            CoreError::Layout(m) => write!(f, "account layout error: {m}"),
            CoreError::Transport(m) => write!(f, "rpc transport error: {m}"),
            CoreError::Rpc { code, message } => write!(f, "rpc error {code}: {message}"),
            CoreError::UnexpectedResponse(m) => write!(f, "unexpected rpc response: {m}"),
            CoreError::Invalid(m) => write!(f, "invalid argument: {m}"),
        }
    }
}

impl std::error::Error for CoreError {}

pub type Result<T> = std::result::Result<T, CoreError>;
