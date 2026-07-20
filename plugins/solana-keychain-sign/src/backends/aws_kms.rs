//! AWS KMS [`SignerBackend`] (v0 STUB).
//!
//! Returns [`SignerError::NotImplemented`] on every [`SignerBackend`] method.
//! The request/response shape helpers ([`AwsKmsClient::build_sign_request_body`],
//! [`AwsKmsClient::parse_sign_response`]) ARE implemented and unit-tested so
//! v1's SigV4 hand-roll is a pure addition — wire up the transport, no shape
//! surprises.
//!
//! ## v1 SigV4 hand-roll plan (~300 LOC pure Rust)
//!
//! AWS KMS requires SigV4-signed requests. The chain when v1 lands:
//!
//! 1. **Canonical request** (per AWS spec, joined with `\n`):
//!    - HTTP method (`POST`)
//!    - Canonical URI (`/`)
//!    - Canonical query string (empty)
//!    - Canonical headers — `host: kms.<region>.amazonaws.com\n` +
//!      `x-amz-date: <timestamp>\n` — lowercased keys, sorted, LF-joined,
//!      trailing LF
//!    - Signed headers list (`host;x-amz-date`)
//!    - Hashed payload — `hex(sha256(body))`
//!    - Hash the whole canonical request with SHA-256.
//!
//! 2. **String to sign** (joined with `\n`):
//!    - Algorithm: `AWS4-HMAC-SHA256`
//!    - Timestamp (`YYYYMMDDTHHMMSSZ`)
//!    - Credential scope (`<date>/<region>/kms/aws4_request`)
//!    - `hex(sha256(canonical_request))`
//!
//! 3. **Signing key chain** (HMAC-SHA256 nested):
//!    - `k_date    = HMAC-SHA256(b"AWS4" + secret_access_key, date)`
//!    - `k_region  = HMAC-SHA256(k_date,    region)`
//!    - `k_service = HMAC-SHA256(k_region,  "kms")`
//!    - `k_signing = HMAC-SHA256(k_service, "aws4_request")`
//!
//! 4. **Signature**: `hex(HMAC-SHA256(k_signing, string_to_sign))`
//!
//! 5. **Authorization header**:
//!    `AWS4-HMAC-SHA256 Credential=<access_key_id>/<scope>, SignedHeaders=host;x-amz-date, Signature=<sig>`
//!
//! All up ~300 LOC using `sha2` (already a sibling dep) + a small HMAC-SHA256
//! (~50 LOC, or pull the `hmac` crate). The shape helpers in this module are
//! SigV4-agnostic; v1 wires SigV4 into the transport layer only.
//!
//! ## The Ed25519-vs-KMS gap (v1+ research)
//!
//! AWS KMS asymmetric keys natively support RSA-PSS, RSA-PKCS1v15, and ECDSA
//! on NIST curves (P-256, P-384, P-521, etc.). **Ed25519 is NOT supported by
//! KMS as of 2026.** Solana's signature scheme requires Ed25519. The realistic
//! deployment paths for an AWS-backed Solana signer are:
//!
//!   1. **Secrets Manager**: store the Ed25519 seed as a secret; load it into
//!      a memory-locked signer at startup. Loses HSM protection but works
//!      with Solana today.
//!   2. **KMS + ECDSA + transform**: KMS signs with ECDSA-P-256, then a
//!      verifier translates to an Ed25519-compatible representation —
//!      non-trivial, may be impossible without protocol-level changes.
//!   3. **CloudHSM**: AWS CloudHSM supports Ed25519 via PKCS#11. Higher
//!      operational cost but matches the security model.
//!
//! v0 stubs this backend with `NotImplemented` so operators don't configure
//! it expecting it to work. The SigV4 plan above is for the transport layer;
//! making KMS produce a valid Solana signature is a separate research item
//! tracked in the README.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};

use super::{SignerBackend, SignerError};

/// AWS KMS asymmetric-signing backend (v0 STUB).
///
/// Holds the operator config (region, credentials, key id) but performs no
/// signing operations in v0. The struct's `secret_access_key` field is held
/// by value and is never copied into logs, error messages, or
/// [`SignerError`] variants — see [`Self::new`] and the `Debug` impl.
#[derive(Clone)]
pub struct AwsKmsClient {
    /// AWS region hosting the KMS key, e.g. `"us-east-1"`.
    pub region: String,
    /// AWS access key id (not secret on its own — appears in SigV4
    /// Authorization headers in v1).
    pub access_key_id: String,
    /// AWS secret access key (the secret half). Held by value; redacted from
    /// `Debug`. Never appears in errors.
    pub secret_access_key: String,
    /// KMS key id or ARN identifying the asymmetric signing key.
    pub key_id: String,
}

impl std::fmt::Debug for AwsKmsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsClient")
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl AwsKmsClient {
    /// Construct from operator config. `secret_access_key` is held by value
    /// and never surfaces in logs, errors, or `Debug` output.
    pub fn new(
        region: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            region: region.into(),
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            key_id: key_id.into(),
        }
    }

    /// KMS service endpoint for this client's region:
    /// `https://kms.<region>.amazonaws.com/`. Used by the v1 transport layer.
    pub fn endpoint(&self) -> String {
        format!("https://kms.{}.amazonaws.com/", self.region)
    }

    /// Build the JSON body for a KMS `Sign` API call. Pure and tested — when
    /// v1 wires SigV4 + waki, this exact body ships over the wire.
    ///
    /// `SigningAlgorithm: "ED25519"` per the bounty contract. **Note**: as of
    /// 2026 AWS KMS does not support Ed25519 signing — see module docs. v1
    /// must reconcile this before this backend becomes functional.
    pub fn build_sign_request_body(&self, message: &[u8]) -> Value {
        json!({
            "KeyId": self.key_id,
            "SigningAlgorithm": "ED25519",
            "MessageType": "RAW",
            "Message": B64.encode(message),
        })
    }

    /// Parse a KMS `Sign` response body and extract the raw 64-byte Ed25519
    /// signature. Pure and tested. Returns:
    ///   - `Ok([u8; 64])` on a well-formed response with a 64-byte signature.
    ///   - `Err(SignerError::Backend)` when KMS returned an `Error` envelope.
    ///   - `Err(SignerError::BadSignature)` when `Signature` is missing, not
    ///     valid base64, or not exactly 64 bytes after decoding.
    pub fn parse_sign_response(body: &Value) -> Result<[u8; 64], SignerError> {
        if let Some(err) = body.get("Error") {
            let code = err
                .get("__type")
                .and_then(Value::as_str)
                .unwrap_or("Unknown")
                .to_string();
            let message = err
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(SignerError::Backend(format!("KMS {code}: {message}")));
        }
        let sig_b64 = body
            .get("Signature")
            .and_then(Value::as_str)
            .ok_or_else(|| SignerError::BadSignature("missing Signature field".to_string()))?;
        let sig = B64
            .decode(sig_b64)
            .map_err(|e| SignerError::BadSignature(format!("base64 decode failed: {e}")))?;
        let len = sig.len();
        let arr: [u8; 64] = sig
            .try_into()
            .map_err(|_| SignerError::BadSignature(format!("expected 64 bytes, got {len}")))?;
        Ok(arr)
    }
}

impl SignerBackend for AwsKmsClient {
    fn name(&self) -> &'static str {
        super::AWS_KMS_BACKEND
    }

    fn public_key(&self) -> Result<Vec<u8>, SignerError> {
        // v1 needs GetPublicKey + SigV4 + (for ECDSA keys) ASN.1 SEQUENCE
        // decode. See module docs for the Ed25519 gap.
        Err(SignerError::NotImplemented(
            "AwsKmsClient::public_key — needs GetPublicKey + SigV4 (see module docs)",
        ))
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SignerError> {
        // v1 wires: SigV4 chain → waki POST → parse_sign_response. See
        // module docs for the ~300 LOC SigV4 hand-roll plan.
        Err(SignerError::NotImplemented(
            "AwsKmsClient::sign — needs SigV4 hand-roll (~300 LOC, see module docs)",
        ))
    }
}
