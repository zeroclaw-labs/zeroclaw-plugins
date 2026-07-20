//! Host-side integration tests for the AWS KMS backend stub.
//!
//! Coverage per the bean:
//!   - `SignerBackend::public_key` → `SignerError::NotImplemented`.
//!   - `SignerBackend::sign` → `SignerError::NotImplemented`.
//!   - Mock-HTTP path (request body shape): `build_sign_request_body` produces
//!     the exact JSON envelope a v1 SigV4 transport would ship —
//!     `KeyId`, `SigningAlgorithm=ED25519`, `MessageType=RAW`, base64
//!     `Message`.
//!   - Mock-HTTP path (response shape): `parse_sign_response` decodes a
//!     real-shape KMS response, including the 64-byte signature extraction
//!     and the `Error` envelope handling.
//!   - `Debug` does NOT leak `secret_access_key`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::json;

use solana_keychain_sign::backends::aws_kms::AwsKmsClient;
use solana_keychain_sign::backends::{SignerBackend, SignerError};

fn fixture_client() -> AwsKmsClient {
    AwsKmsClient::new(
        "us-east-1",
        "AKIAFAKEKEYIDEXAMPLE",
        "supersecretaccesskeythatmustnotleak",
        "mrk-abcdef0123456789abcdef0123456789",
    )
}

// ── SignerBackend: v0 stubs ──────────────────────────────────────────────────

#[test]
fn public_key_returns_not_implemented_with_identifying_message() {
    let c = fixture_client();
    let err = c.public_key().expect_err("v0 must stub");
    match err {
        SignerError::NotImplemented(msg) => {
            assert!(
                msg.contains("public_key"),
                "message should name the unimplemented method: {msg}"
            );
            assert!(
                msg.contains("SigV4") || msg.contains("GetPublicKey"),
                "message should hint at the missing piece: {msg}"
            );
        }
        other => panic!("expected NotImplemented, got {other:?}"),
    }
}

#[test]
fn sign_returns_not_implemented_with_identifying_message() {
    let c = fixture_client();
    let msg = b"some message bytes";
    let err = c.sign(msg).expect_err("v0 must stub");
    match err {
        SignerError::NotImplemented(s) => {
            assert!(
                s.contains("sign"),
                "message should name the unimplemented method: {s}"
            );
            assert!(
                s.contains("SigV4"),
                "message should hint at the missing piece: {s}"
            );
        }
        other => panic!("expected NotImplemented, got {other:?}"),
    }
}

// ── Mock-HTTP path: request body shape ───────────────────────────────────────

#[test]
fn build_sign_request_body_has_required_kms_fields() {
    let c = fixture_client();
    let msg = b"hello solana";
    let body = c.build_sign_request_body(msg);

    // Required fields per KMS Sign API.
    assert_eq!(body["KeyId"], "mrk-abcdef0123456789abcdef0123456789");
    assert_eq!(body["SigningAlgorithm"], "ED25519");
    assert_eq!(body["MessageType"], "RAW");

    // Message must be base64 of the raw bytes.
    let b64 = body["Message"].as_str().expect("Message must be string");
    let decoded = B64.decode(b64).expect("Message must be valid base64");
    assert_eq!(decoded, msg);
}

#[test]
fn build_sign_request_body_base64_round_trips_arbitrary_message_bytes() {
    let c = fixture_client();
    // 0 bytes — boundary case.
    let body0 = c.build_sign_request_body(&[]);
    assert_eq!(body0["Message"].as_str().unwrap(), "");

    // A binary message with non-ASCII bytes — proves base64 encoding handles
    // what JSON serialization cannot.
    let bin: Vec<u8> = (0..=255).collect();
    let body_bin = c.build_sign_request_body(&bin);
    let b64 = body_bin["Message"].as_str().unwrap();
    let decoded = B64.decode(b64).unwrap();
    assert_eq!(decoded, bin);
}

// ── Mock-HTTP path: response parsing ─────────────────────────────────────────

#[test]
fn parse_sign_response_extracts_64_byte_signature() {
    // Construct a fake-but-well-shaped 64-byte signature.
    let sig_bytes: Vec<u8> = (0..64).collect();
    let sig_b64 = B64.encode(&sig_bytes);
    let resp = json!({ "Signature": sig_b64 });
    let out = AwsKmsClient::parse_sign_response(&resp).expect("must parse");
    assert_eq!(out.to_vec(), sig_bytes);
}

#[test]
fn parse_sign_response_rejects_kms_error_envelope() {
    let resp = json!({
        "__type": "NotFoundException",
        "Message": "Key arn:aws:kms:us-east-1:... not found"
    });
    // The parser looks for an `Error` key for KMS error envelopes. AWS SDKs
    // wrap the response body in `{ "Error": { ... } }` at the HTTP layer; the
    // bare `__type` top-level form is what KMS returns in the JSON body for
    // some error paths. We exercise BOTH to be defensive for v1.
    let bare = AwsKmsClient::parse_sign_response(&resp).unwrap_err();
    // Bare __type at top level is NOT caught by our current parser (we look
    // for `Error`). That's documented behavior; v1's transport layer should
    // normalize. For now, the missing Signature yields BadSignature.
    assert!(
        matches!(bare, SignerError::BadSignature(_)),
        "bare __type should fall through to BadSignature (missing Signature): {bare:?}"
    );

    // The wrapped form IS caught.
    let wrapped = json!({
        "Error": {
            "__type": "NotFoundException",
            "Message": "Key arn:aws:kms:us-east-1:... not found"
        }
    });
    let err = AwsKmsClient::parse_sign_response(&wrapped).unwrap_err();
    match err {
        SignerError::Backend(msg) => {
            assert!(msg.contains("NotFoundException"), "msg: {msg}");
            assert!(msg.contains("not found"), "msg: {msg}");
        }
        other => panic!("expected Backend, got {other:?}"),
    }
}

#[test]
fn parse_sign_response_rejects_missing_signature() {
    let resp = json!({ "OtherField": "nope" });
    let err = AwsKmsClient::parse_sign_response(&resp).unwrap_err();
    assert!(matches!(err, SignerError::BadSignature(_)));
}

#[test]
fn parse_sign_response_rejects_malformed_base64() {
    let resp = json!({ "Signature": "this is not valid base64 !@#$" });
    let err = AwsKmsClient::parse_sign_response(&resp).unwrap_err();
    match err {
        SignerError::BadSignature(msg) => assert!(msg.contains("base64 decode"), "msg: {msg}"),
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn parse_sign_response_rejects_wrong_length_signature() {
    // 32 bytes (half — looks like a pubkey).
    let too_short = B64.encode(vec![0u8; 32]);
    let err = AwsKmsClient::parse_sign_response(&json!({ "Signature": too_short })).unwrap_err();
    match err {
        SignerError::BadSignature(msg) => assert!(msg.contains("expected 64 bytes"), "msg: {msg}"),
        other => panic!("expected BadSignature, got {other:?}"),
    }

    // 128 bytes (twice as long).
    let too_long = B64.encode(vec![0u8; 128]);
    let err = AwsKmsClient::parse_sign_response(&json!({ "Signature": too_long })).unwrap_err();
    match err {
        SignerError::BadSignature(msg) => assert!(msg.contains("expected 64 bytes"), "msg: {msg}"),
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

// ── Secret hygiene ────────────────────────────────────────────────────────────

#[test]
fn debug_redacts_secret_access_key() {
    let c = fixture_client();
    let s = format!("{c:?}");
    assert!(
        !s.contains("supersecretaccesskeythatmustnotleak"),
        "Debug leaked the secret: {s}"
    );
    assert!(
        s.contains("<redacted>"),
        "Debug should show <redacted>: {s}"
    );
    // Non-secret fields are still visible.
    assert!(s.contains("us-east-1"));
    assert!(s.contains("AKIAFAKEKEYIDEXAMPLE"));
}

// ── Endpoint ─────────────────────────────────────────────────────────────────

#[test]
fn endpoint_includes_region() {
    let c = fixture_client();
    assert_eq!(c.endpoint(), "https://kms.us-east-1.amazonaws.com/");
}
