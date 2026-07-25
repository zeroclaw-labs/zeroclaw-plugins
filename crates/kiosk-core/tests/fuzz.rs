//! Untrusted-input hardening: every decoder that touches bytes we did not
//! produce (RPC bodies, account data, base58/base64 strings, shortvec buffers)
//! must NEVER panic on hostile input — only ever return `Err`/`None`. A panic in
//! a wasm component aborts the call; fail-closed means a clean error instead.

use kiosk_core::rpc::parse_response;
use kiosk_core::{b58, b64, nonce, shortvec};
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_response_never_panics(s in ".{0,2048}") {
        // Returns Ok or Err — the only requirement is it does not panic.
        let _ = parse_response(&s);
    }

    #[test]
    fn parse_response_rejects_non_jsonrpc(s in "[^{]{1,64}") {
        // A body that is not a JSON object cannot be a valid envelope.
        prop_assert!(parse_response(&s).is_err());
    }

    #[test]
    fn b64_decode_never_panics(s in ".{0,1024}") {
        let _ = b64::decode(&s);
    }

    #[test]
    fn b58_decode_never_panics(s in ".{0,1024}") {
        let _ = b58::decode(&s);
    }

    #[test]
    fn nonce_parse_never_panics_on_arbitrary_base64(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        // Feed arbitrary bytes as base64 account data; must be Some or None, never a panic.
        let _ = nonce::parse_nonce_account(&b64::encode(&bytes));
    }

    #[test]
    fn nonce_parse_never_panics_on_arbitrary_string(s in ".{0,512}") {
        let _ = nonce::parse_nonce_account(&s);
    }

    #[test]
    fn shortvec_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..8)) {
        let _ = shortvec::decode_len(&bytes);
    }
}

// A few explicit oversized / truncated / garbage cases, fail-closed.
#[test]
fn explicit_hostile_inputs_fail_closed() {
    // Truncated JSON-RPC envelope.
    assert!(parse_response(r#"{"jsonrpc":"2.0","result""#).is_err());
    // Oversized but structurally wrong.
    assert!(parse_response(&"[".repeat(100_000)).is_err());
    // Deeply-nested-but-no-result object.
    assert!(parse_response(r#"{"a":{"b":{"c":1}}}"#).is_err());
    // Base64 of a too-short "nonce account".
    assert!(nonce::parse_nonce_account(&b64::encode(&[0u8; 79])).is_none());
    // Non-base64 garbage as account data.
    assert!(nonce::parse_nonce_account("@@@@not-base64@@@@").is_none());
    // Oversized base58 input does not panic and is either Some or None.
    let _ = b58::decode(&"1".repeat(100_000));
}
