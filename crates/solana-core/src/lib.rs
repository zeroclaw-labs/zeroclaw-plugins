//! # solana-core
//!
//! The pure Solana substrate the ZeroClaw Solana plugins are built on. It is the
//! answer to the bounty's trap #2: `solana-sdk` / `solana-client` do not compile
//! clean for `wasm32-wasip2` inside a WIT component, so this crate hand-rolls the
//! small subset a read-only agent tool actually needs:
//!
//! - [`base58`] address encode/decode over `bs58`,
//! - [`rpc`] JSON-RPC request construction and response-envelope parsing,
//! - [`mint`] SPL Token / Token-2022 mint account decoding, including the
//!   Token-2022 TLV extension walker used for risk analysis,
//! - [`token_account`] SPL token account (balance) decoding,
//! - [`shape`] output-shaping helpers so a plugin returns the ~200 tokens the
//!   model needs, not the 40 KB the RPC sent (trap #3).
//!
//! Every decoder is **bounds-checked and panic-free**: malformed on-chain data
//! yields an `Err`, never a trap. That is a safety property a plugin relies on to
//! "fail closed" rather than crash the agent loop.
//!
//! The crate has no wasm or host dependency of its own, so the exact same code is
//! exercised by `cargo test` on the host and compiled into each plugin component.

pub mod base58;
pub mod mint;
pub mod rpc;
pub mod shape;
pub mod token_account;

/// A 32-byte Solana public key (or program id).
pub type Pubkey = [u8; 32];

/// The all-zero pubkey. In Token-2022 extensions an "unset" optional pubkey is
/// encoded as all zeros rather than an explicit tag, so callers test against
/// this to mean "None".
pub const DEFAULT_PUBKEY: Pubkey = [0u8; 32];

/// Well-known program ids, base58-encoded, so plugins can classify an account's
/// owner without pulling in `solana-program`.
pub mod programs {
    /// The original SPL Token program.
    pub const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    /// The SPL Token-2022 (Token Extensions) program.
    pub const SPL_TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    /// The System program (owner of unallocated / burn accounts like `1111…`).
    pub const SYSTEM: &str = "11111111111111111111111111111111";
}
