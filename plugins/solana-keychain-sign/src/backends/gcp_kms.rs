//! GCP Cloud KMS [`SignerBackend`] (v0 STUB).
//!
//! Returns [`SignerError::NotImplemented`] on every [`SignerBackend`] method
//! in v0. The request/response shape helpers
//! ([`GcpKmsClient::build_sign_request_body`],
//! [`GcpKmsClient::parse_sign_response`]) ARE implemented and unit-tested so
//! v1's OAuth2 transport layer is a pure addition — wire up `Authorization:
//! Bearer <token>` + waki POST, no shape surprises.
//!
//! ## Request shape (Ed25519)
//!
//! Cloud KMS Ed25519 signing takes the **raw message bytes** under the `data`
//! key (unlike RSA / ECDSA which take a pre-hashed `digest`). The body the
//! transport layer ships:
//!
//! ```json
//! {
//!   "data":     "<base64(message)>",
//!   "dataCrc32c": "<crc32c(message) as int64>"
//! }
//! ```
//!
//! [`GcpKmsClient::build_sign_request_body`] produces exactly this envelope.
//! The CRC32C field is included because Cloud KMS verifies it server-side
//! when present; v1's transport layer computes it from `sha2` + crc32c (a
//! ~30 LOC addition; crc32c is a small table-driven algorithm).
//!
//! ## Response shape
//!
//! Cloud KMS returns:
//!
//! ```json
//! {
//!   "name":          "projects/.../cryptoKeyVersions/1",
//!   "signature":     "<base64 64-byte Ed25519 sig>",
//!   "signatureCrc32c": "<int64>",
//!   "verified":      true
//! }
//! ```
//!
//! On error Cloud KMS wraps the body as `{ "error": { "code": <int>,
//! "message": "...", "status": "INVALID_ARGUMENT" } }`.
//! [`GcpKmsClient::parse_sign_response`] handles both shapes.
//!
//! ## v1 auth options (plan only — out of scope for v0)
//!
//! GCP Cloud KMS needs a Bearer `access_token`. Two realistic paths:
//!
//! 1. **Operator-pasted short-lived token (works today, 1hr rotation).**
//!    Operator runs `gcloud auth print-access-token` locally, pastes the
//!    result into config as `gcp_access_token`. The plugin ships it as
//!    `Authorization: Bearer <token>` on every sign call. Simple, but the
//!    token expires hourly — operator must rotate it manually. Zero
//!    network-side changes from the v0 stub: the transport layer literally
//!    adds one header.
//!
//! 2. **Service-account JSON + RSA JWT (heavier, future).**
//!    Operator supplies a service-account JSON key file; the plugin:
//!    a. Reads the `private_key` (PKCS#8 RSA-2048).
//!    b. Builds a JWT header `{ "alg": "RS256", "typ": "JWT", "kid": <sa_key_id> }`.
//!    c. Builds a JWT claim set with `iss`, `scope`, `aud`, `iat`, `exp`.
//!    d. Base64url-encodes both, signs `<header>.<claims>` with RSA-SHA256.
//!    e. POSTs to `https://oauth2.googleapis.com/token?grant_type=
//!       urn:ietf:params:oauth:grant-type:jwt-bearer`.
//!    f. Caches the resulting `access_token` until `exp - 60s`.
//!
//!    ~200 LOC + an RSA signer (the `rsa` crate + `sha2` + base64
//!    url-safe-no-pad). Tracked as a v2 item — the OAuth2 token endpoint
//!    + JWT signing is a generic Google API concern, not KMS-specific.
//!
//! ## The Ed25519-vs-CloudKMS gap (research)
//!
//! Like AWS KMS, Cloud KMS's HSM-backed keys support RSA-PSS / ECDSA on NIST
//! curves but **not Ed25519** as of 2026 (software-only key versions do).
//! Same caveat as `aws_kms.rs`: production deployments likely need
//! Cloud HSM (PKCS#11 with Ed25519) or Secret Manager + in-process signing.
//! The v0 stub keeps the slot open without promising something the
//! underlying service cannot deliver.
//!
//! ## v0 scaffold scope (this bean, `88iq`)
//!
//! [`GcpKmsClient`] already ships with: redacted Debug, operator-config
//! constructor, [`GcpKmsClient::sign_url`] shape helper, and
//! `NotImplemented` [`SignerBackend`] impl — all from `67ip`. This bean
//! (`88iq`) fills in the two shape helpers
//! ([`GcpKmsClient::build_sign_request_body`],
//! [`GcpKmsClient::parse_sign_response`]) and their host tests so v1's
//! transport layer is a pure addition.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};

use super::{SignerBackend, SignerError};

/// GCP Cloud KMS asymmetric-signing backend (v0 STUB).
///
/// Holds operator config (project / location / keyRing / cryptoKey / version)
/// but performs no signing operations in v0. The struct's `access_token`
/// field is held by value and is never copied into logs, error messages, or
/// [`SignerError`] variants — see [`Self::new`] and the `Debug` impl.
#[derive(Clone)]
pub struct GcpKmsClient {
    /// GCP project id hosting the KMS key ring.
    pub project: String,
    /// Location, e.g. `"us-central1"` (KMS regions are crammed into the URL).
    pub location: String,
    /// Key ring name.
    pub key_ring: String,
    /// Crypto key name (the asymmetric signing key).
    pub crypto_key: String,
    /// Crypto key version, e.g. `"1"`.
    pub version: String,
    /// Short-lived OAuth2 access token (`gcloud auth print-access-token`).
    /// Held by value; redacted from `Debug`; never in errors.
    pub access_token: String,
}

impl std::fmt::Debug for GcpKmsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsClient")
            .field("project", &self.project)
            .field("location", &self.location)
            .field("key_ring", &self.key_ring)
            .field("crypto_key", &self.crypto_key)
            .field("version", &self.version)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

impl GcpKmsClient {
    /// Construct from operator config. `access_token` is held by value and
    /// never surfaces in logs, errors, or `Debug` output.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: impl Into<String>,
        location: impl Into<String>,
        key_ring: impl Into<String>,
        crypto_key: impl Into<String>,
        version: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Self {
        Self {
            project: project.into(),
            location: location.into(),
            key_ring: key_ring.into(),
            crypto_key: crypto_key.into(),
            version: version.into(),
            access_token: access_token.into(),
        }
    }

    /// Full Cloud KMS sign endpoint for this client's key version. Pure —
    /// tested here so v1's transport layer can rely on it.
    pub fn sign_url(&self) -> String {
        format!(
            "https://cloudkms.googleapis.com/v1/projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}:sign",
            self.project, self.location, self.key_ring, self.crypto_key, self.version,
        )
    }

    /// Build the JSON body for a Cloud KMS Ed25519 `sign` API call. Pure and
    /// tested — when v1 wires OAuth2 + waki, this exact body ships over the
    /// wire.
    ///
    /// Cloud KMS Ed25519 signing takes the **raw message** (not a pre-hashed
    /// digest — RSA / ECDSA variants take `digest`, Ed25519 takes `data`).
    /// The optional `dataCrc32c` is included because Cloud KMS verifies it
    /// server-side when present; v1's transport layer fills it in with the
    /// crc32c of the raw message (a ~30 LOC addition).
    pub fn build_sign_request_body(&self, message: &[u8]) -> Value {
        json!({
            "data": B64.encode(message),
            // v1 fills dataCrc32c from the raw message; v0 leaves it null so
            // Cloud KMS treats the field as absent (it skips verification).
            "dataCrc32c": null,
        })
    }

    /// Parse a Cloud KMS `sign` response body and extract the raw 64-byte
    /// Ed25519 signature. Pure and tested. Returns:
    ///   - `Ok([u8; 64])` on a well-formed response with a 64-byte signature.
    ///   - `Err(SignerError::Backend)` when Cloud KMS returned an
    ///     `{ "error": { "code", "message", "status" } }` envelope.
    ///   - `Err(SignerError::BadSignature)` when `signature` is missing, not
    ///     valid base64, or not exactly 64 bytes after decoding.
    pub fn parse_sign_response(body: &Value) -> Result<[u8; 64], SignerError> {
        // Cloud KMS error envelope is top-level `error` (lowercase).
        if let Some(err) = body.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let status = err
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN")
                .to_string();
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(SignerError::Backend(format!(
                "CloudKMS {status} (code {code}): {message}"
            )));
        }
        let sig_b64 = body
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| SignerError::BadSignature("missing signature field".to_string()))?;
        let sig = B64
            .decode(sig_b64)
            .map_err(|e| SignerError::BadSignature(format!("base64 decode failed: {e}")))?;
        let len = sig.len();
        let arr: [u8; 64] = sig
            .try_into()
            .map_err(|_| SignerError::BadSignature(format!("expected 64 bytes, got {len}")))?;
        Ok(arr)
    }

    /// `Authorization` header value the v1 transport layer will send.
    /// `Bearer <token>`. Tested here so v1 has no string-construction
    /// surprises; the token itself never appears in errors or logs.
    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }
}

impl SignerBackend for GcpKmsClient {
    fn name(&self) -> &'static str {
        super::GCP_KMS_BACKEND
    }

    fn public_key(&self) -> Result<Vec<u8>, SignerError> {
        // v1 wires: getPublicKey endpoint + X.509 SubjectPublicKeyInfo
        // parsing for the Ed25519 SPKI prefix (matches CryptoKeyVersion
        // algorithm = ELLIPTIC_CURVE_SIGNING + ED25519).
        Err(SignerError::NotImplemented(
            "GcpKmsClient::public_key — v1 wires getPublicKey + SPKI parse",
        ))
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SignerError> {
        // v1 wires: waki POST + JWT-bearing Authorization header + parse.
        Err(SignerError::NotImplemented(
            "GcpKmsClient::sign — v1 wires OAuth2 + waki POST to cloudkms.googleapis.com",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> GcpKmsClient {
        GcpKmsClient::new(
            "my-project",
            "us-central1",
            "solana-keyring",
            "solana-session-key",
            "1",
            "ya29.A_FAKE_OAUTH_TOKEN",
        )
    }

    // ── SignerBackend: v0 stubs ─────────────────────────────────────────────

    #[test]
    fn public_key_returns_not_implemented_naming_v1_wiring() {
        let c = fixture();
        let err = c.public_key().expect_err("v0 must stub");
        match err {
            SignerError::NotImplemented(msg) => {
                assert!(msg.contains("public_key"), "msg: {msg}");
                assert!(
                    msg.contains("getPublicKey"),
                    "msg should hint at the missing piece: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn sign_returns_not_implemented_naming_v1_wiring() {
        let c = fixture();
        let err = c.sign(b"msg").expect_err("v0 must stub");
        match err {
            SignerError::NotImplemented(msg) => {
                assert!(msg.contains("sign"), "msg: {msg}");
                assert!(
                    msg.contains("OAuth2") || msg.contains("waki"),
                    "msg should hint at the missing piece: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    // ── Mock-HTTP path: request body shape ───────────────────────────────────

    #[test]
    fn build_sign_request_body_uses_data_field_for_ed25519() {
        // Ed25519 takes the raw message under `data` (not `digest`, which
        // is what RSA/ECDSA variants use).
        let c = fixture();
        let msg = b"hello solana";
        let body = c.build_sign_request_body(msg);

        assert!(
            body.get("data").is_some(),
            "Ed25519 body must use `data`: {body}"
        );
        assert!(
            body.get("digest").is_none(),
            "Ed25519 body must NOT use `digest`: {body}"
        );

        let b64 = body["data"].as_str().expect("data must be string");
        let decoded = B64.decode(b64).expect("data must be valid base64");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn build_sign_request_body_base64_round_trips_arbitrary_message_bytes() {
        let c = fixture();
        // 0 bytes — boundary case.
        let body0 = c.build_sign_request_body(&[]);
        assert_eq!(body0["data"].as_str().unwrap(), "");

        // A binary message with non-ASCII bytes — proves base64 handles
        // what JSON serialization cannot.
        let bin: Vec<u8> = (0..=255).collect();
        let body_bin = c.build_sign_request_body(&bin);
        let b64 = body_bin["data"].as_str().unwrap();
        let decoded = B64.decode(b64).unwrap();
        assert_eq!(decoded, bin);
    }

    #[test]
    fn build_sign_request_body_includes_data_crc32c_field() {
        // The field is present even when null — Cloud KMS treats null as
        // "skip verification". v1 fills in the real crc32c value.
        let c = fixture();
        let body = c.build_sign_request_body(b"msg");
        assert!(
            body.get("dataCrc32c").is_some(),
            "dataCrc32c field must be present (v0 leaves it null): {body}"
        );
        assert!(
            body["dataCrc32c"].is_null(),
            "v0 must leave dataCrc32c null: {body}"
        );
    }

    // ── Mock-HTTP path: response parsing ─────────────────────────────────────

    #[test]
    fn parse_sign_response_extracts_64_byte_signature() {
        let sig_bytes: Vec<u8> = (0..64).collect();
        let sig_b64 = B64.encode(&sig_bytes);
        let resp = json!({
            "name": "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1",
            "signature": sig_b64,
            "signatureCrc32c": "999999",
            "verified": true,
        });
        let out = GcpKmsClient::parse_sign_response(&resp).expect("must parse");
        assert_eq!(out.to_vec(), sig_bytes);
    }

    #[test]
    fn parse_sign_response_rejects_cloud_kms_error_envelope() {
        let resp = json!({
            "error": {
                "code": 400,
                "message": "request failed: decryption failed: ed25519 signature size is invalid",
                "status": "INVALID_ARGUMENT"
            }
        });
        let err = GcpKmsClient::parse_sign_response(&resp).unwrap_err();
        match err {
            SignerError::Backend(msg) => {
                assert!(msg.contains("INVALID_ARGUMENT"), "msg: {msg}");
                assert!(msg.contains("400"), "msg should include code: {msg}");
                assert!(msg.contains("signature size"), "msg: {msg}");
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn parse_sign_response_rejects_missing_signature() {
        let resp = json!({ "name": "projects/..." });
        let err = GcpKmsClient::parse_sign_response(&resp).unwrap_err();
        assert!(matches!(err, SignerError::BadSignature(_)));
    }

    #[test]
    fn parse_sign_response_rejects_malformed_base64() {
        let resp = json!({ "signature": "not valid base64 !!!" });
        let err = GcpKmsClient::parse_sign_response(&resp).unwrap_err();
        match err {
            SignerError::BadSignature(msg) => assert!(msg.contains("base64 decode"), "msg: {msg}"),
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn parse_sign_response_rejects_wrong_length_signature() {
        // 32 bytes (half — looks like a pubkey).
        let too_short = B64.encode(vec![0u8; 32]);
        let err =
            GcpKmsClient::parse_sign_response(&json!({ "signature": too_short })).unwrap_err();
        match err {
            SignerError::BadSignature(msg) => {
                assert!(msg.contains("expected 64 bytes"), "msg: {msg}")
            }
            other => panic!("expected BadSignature, got {other:?}"),
        }

        // 128 bytes (twice as long).
        let too_long = B64.encode(vec![0u8; 128]);
        let err = GcpKmsClient::parse_sign_response(&json!({ "signature": too_long })).unwrap_err();
        match err {
            SignerError::BadSignature(msg) => {
                assert!(msg.contains("expected 64 bytes"), "msg: {msg}")
            }
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    // ── Auth header ──────────────────────────────────────────────────────────

    #[test]
    fn authorization_header_is_bearer_format() {
        let c = fixture();
        let h = c.authorization_header();
        assert!(h.starts_with("Bearer "), "must be Bearer-prefixed: {h}");
        assert!(
            h.contains("ya29.A_FAKE_OAUTH_TOKEN"),
            "must contain the token after the prefix: {h}"
        );
    }

    // ── Secret hygiene ───────────────────────────────────────────────────────

    #[test]
    fn debug_redacts_access_token() {
        let c = fixture();
        let s = format!("{c:?}");
        assert!(!s.contains("ya29.A_FAKE_OAUTH_TOKEN"), "leaked: {s}");
        assert!(s.contains("<redacted>"), "should show <redacted>: {s}");
        assert!(
            s.contains("my-project"),
            "non-secret fields still visible: {s}"
        );
    }

    // ── URL shape ────────────────────────────────────────────────────────────

    #[test]
    fn sign_url_matches_cloud_kms_shape() {
        let c = fixture();
        assert_eq!(
            c.sign_url(),
            "https://cloudkms.googleapis.com/v1/projects/my-project/locations/us-central1/keyRings/solana-keyring/cryptoKeys/solana-session-key/cryptoKeyVersions/1:sign"
        );
    }

    #[test]
    fn name_returns_gcp_kms_backend_constant() {
        let c = fixture();
        assert_eq!(c.name(), super::super::GCP_KMS_BACKEND);
        assert_eq!(c.name(), "gcp_kms");
    }
}
