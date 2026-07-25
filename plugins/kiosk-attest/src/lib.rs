//! A ZeroClaw WIT tool plugin: `kiosk_attest`.
//!
//! Builds an UNSIGNED, hash-chained, durable-nonce memo attestation transaction
//! for the ProofKiosk. Custody tier T1: holds no key, signs nothing. The
//! transaction contains only the Memo and System (advance-nonce) programs, so
//! it is structurally incapable of moving funds.
//!
//! The pure core lives in [`attest`] (host-tested with mocked RPC); the wasm
//! component shim is added on top of it.

pub mod attest;
