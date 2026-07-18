//! wasm32-wasip2-friendly Solana substrate for ZeroClaw tool plugins.
//!
//! `solana-sdk` and `solana-client` do not compile inside a WIT component, so
//! this crate re-implements the small slice of Solana that agent tool plugins
//! actually need, with zero I/O and zero wasm dependencies:
//!
//! - [`pubkey`]  — base58 ed25519 public keys, PDA and ATA derivation
//! - [`encoding`] — compact-u16 (shortvec), base64 helpers
//! - [`instruction`] — `Instruction`/`AccountMeta` plus builders for the
//!   system program, SPL Token / Token-2022 `TransferChecked`, the associated
//!   token account program, the memo program, and durable-nonce advance
//! - [`message`] — v0 versioned-message compilation and unsigned-transaction
//!   wire serialization (zeroed signature placeholders, base64 output)
//! - [`rpc`] — JSON-RPC request construction and response shaping behind the
//!   [`rpc::HttpTransport`] trait, so host tests mock the wire and the wasm
//!   shim plugs in `waki`
//! - [`amount`] — exact decimal-string ↔ base-unit conversion (no floats)
//! - [`nonce`] — durable nonce account parsing (the blockhash-expiry fix)
//! - [`token`] — SPL / Token-2022 mint account parsing incl. TLV extensions
//!
//! Everything here is deterministic and host-testable with a plain
//! `cargo test`.

pub mod amount;
pub mod encoding;
pub mod instruction;
pub mod message;
pub mod nonce;
pub mod pubkey;
pub mod rpc;
pub mod token;
