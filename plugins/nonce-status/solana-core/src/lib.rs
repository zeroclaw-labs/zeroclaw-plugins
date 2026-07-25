//! # solana-core-wasi
//!
//! A minimal Solana substrate for ZeroClaw WIT tool plugins targeting
//! `wasm32-wasip2`. The standard `solana-sdk` / `solana-client` stack does not
//! compile inside a WIT component (tokio, sockets, ring), so this crate
//! provides the small slice of Solana that agent payment tools actually need,
//! hand-rolled against the wire formats and verified against devnet
//! `simulateTransaction` (see `tests/vectors.rs` for the receipts):
//!
//! - base58 pubkeys, PDA / associated-token-account derivation ([`pubkey`])
//! - compact-u16 ("short vec") and base64 primitives ([`encoding`])
//! - instruction builders: system transfer, SPL `TransferChecked`, ATA
//!   create-idempotent, memo, and the durable-nonce trio ([`instruction`])
//! - legacy + v0 message compilation and unsigned-transaction envelopes
//!   ([`message`])
//! - durable nonce account state parsing, the fix for blockhash expiry in
//!   approval-gated flows ([`nonce`])
//! - exact decimal amount arithmetic, no floats ever ([`amount`])
//! - Solana Pay transfer-request URLs ([`pay`])
//! - transport-agnostic JSON-RPC request/response shaping ([`rpc`]) — the
//!   wasm shim plugs in `waki`, host tests plug in mocks
//! - fail-closed operator policy: allowlists and caps that the model cannot
//!   talk its way past ([`policy`])
//!
//! Everything here is pure Rust with no wasm dependency: it compiles and
//! tests on the host with a plain `cargo test`, and identically inside a
//! `wasm32-wasip2` component.

pub mod amount;
pub mod encoding;
pub mod instruction;
pub mod message;
pub mod nonce;
pub mod pay;
pub mod policy;
pub mod pubkey;
pub mod rpc;
