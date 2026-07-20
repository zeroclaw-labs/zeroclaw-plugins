//! HashiCorp Vault transit [`SignerBackend`] (v0 — fully working under wasm).
//!
//! POSTs message bytes to `{vault_addr}/v1/transit/sign/{key_name}` with
//! header `X-Vault-Token: {vault_token}` and body
//! `{ "input": "<base64(message)>" }`. Vault returns
//! `{ "data": { "signature": "vault:v1:<base64-sig>" } }`; we strip the
//! `vault:v{N}:` prefix, base64-decode the 64-byte Ed25519 signature, and
//! verify it against the operator-supplied `pubkey` before returning. If the
//! signature does not verify, the response is treated as corrupt / malicious
//! and rejected with [`SignerError::BadSignature`] — never returned to the
//! caller.
//!
//! ## Pure core + thin shim
//!
//! The trait seam is [`VaultTransport`] — a single `post_with_token` method.
//! [`VaultClient::sign_with`] is fully host-testable against a mock
//! transport; the wasm-only [`WakiVaultTransport`] impl lives under
//! `cfg(target_family = "wasm")` so the host test build never pulls in
//! `waki` or `wasi:http`.
//!
//! ## Why verification lives here
//!
//! Vault transit signs **whatever bytes it is asked to sign**. The plugin
//! trusts the operator's `pubkey` config to be the pubkey matching the
//! transit key — but verifying the signature against that pubkey before
//! returning is a cheap defense-in-depth: a misconfigured transit key, a
//! rotated key the operator forgot to mirror into config, or a Vault replay
//! all surface as `BadSignature` here rather than landing a bad tx on-chain.
//!
//! The verification uses `ed25519-dalek` (already a dep). The 64-byte sig +
//! 32-byte pubkey + original message go straight into `VerifyingKey::verify`
//! — no extra SHA-256 hop (Ed25519 does that internally).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};

use super::{SignerBackend, SignerError};

/// Low-level HTTP transport for the Vault transit client. Abstracted so host
/// tests supply a mock and the wasm component supplies [`WakiVaultTransport`].
/// Implementations are responsible for adding the `X-Vault-Token` header —
/// the token is passed per-call so it never has to outlive the request.
pub trait VaultTransport {
    /// POST `body` to `url` with `X-Vault-Token: <vault_token>` and
    /// `Content-Type: application/json`, return the parsed JSON response.
    /// Errors are operator-facing strings (no secrets in the URL).
    fn post_with_token(&self, url: &str, body: &Value, vault_token: &str) -> Result<Value, String>;
}

/// Vault transit signing client.
///
/// `pubkey` is supplied by the operator (the result of
/// `vault read -field=public_key transit/keys/<key_name>` against a
/// dev-mode Vault with the ed25519 key type). The plugin never fetches it
/// itself — operator-configured keys match the operator-configured
/// `signer_pubkey` envelope guard by construction.
///
/// `vault_token` is held by value; redacted from `Debug`; never appears in
/// errors or logs. [`SignerBackend::sign`] dispatches to
/// [`Self::sign_with`] with a [`WakiVaultTransport`] under
/// `cfg(target_family = "wasm")` and returns [`SignerError::NotImplemented`]
/// on host (host tests drive `sign_with` directly with a mock transport).
#[derive(Clone)]
pub struct VaultClient {
    /// Vault base address, e.g. `https://vault.example:8200`. No trailing slash.
    pub vault_addr: String,
    /// Vault token with `update` on `transit/sign/<key_name>`. Held by value;
    /// redacted from `Debug`; never appears in errors or logs.
    pub vault_token: String,
    /// Transit key name, e.g. `solana-session`.
    pub key_name: String,
    /// 32-byte Ed25519 public key the operator extracted from Vault. The
    /// envelope guard (`signer_pubkey`) must match this — operator ensures
    /// both sides point at the same key.
    pub pubkey: Vec<u8>,
}

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("vault_addr", &self.vault_addr)
            .field("vault_token", &"<redacted>")
            .field("key_name", &self.key_name)
            .field("pubkey", &format!("<{} bytes>", self.pubkey.len()))
            .finish()
    }
}

impl VaultClient {
    /// Construct from operator config. `vault_token` is held by value and
    /// never surfaces in logs, errors, or `Debug` output.
    pub fn new(
        vault_addr: impl Into<String>,
        vault_token: impl Into<String>,
        key_name: impl Into<String>,
        pubkey: Vec<u8>,
    ) -> Self {
        Self {
            vault_addr: vault_addr.into(),
            vault_token: vault_token.into(),
            key_name: key_name.into(),
            pubkey,
        }
    }

    /// Full URL for a `transit/sign/{key_name}` POST. Pure — tested here so
    /// the wasm transport layer can rely on it without re-deriving.
    pub fn sign_url(&self) -> String {
        let base = self.vault_addr.trim_end_matches('/');
        format!("{base}/v1/transit/sign/{}", self.key_name)
    }

    /// Sign `message` via the supplied transport and return the verified
    /// 64-byte Ed25519 signature.
    ///
    /// Full chain:
    ///   1. Build the request body (`{ "input": "<base64(msg)>" }`).
    ///   2. POST to [`Self::sign_url`] with `X-Vault-Token`.
    ///   3. Parse the Vault response envelope, strip the `vault:v{N}:`
    ///      prefix, base64-decode to 64 bytes.
    ///   4. Verify the signature against `self.pubkey` using `ed25519-dalek`.
    ///   5. Return the verified signature bytes.
    ///
    /// Any failure (transport, Vault error envelope, malformed body, wrong
    /// length, prefix mismatch, verification failure) →
    /// [`SignerError::Backend`] / [`SignerError::BadSignature`] / etc.
    pub fn sign_with<T: VaultTransport>(
        &self,
        transport: &T,
        message: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let body = build_sign_request_body(message);
        let resp = transport
            .post_with_token(&self.sign_url(), &body, &self.vault_token)
            .map_err(SignerError::Transport)?;
        let sig = parse_sign_response(&resp)?;
        // Defense-in-depth: verify the signature against the operator-supplied
        // pubkey before returning. Vault transit should always produce a sig
        // that verifies against the key it claims — this catches misconfigured
        // keys, rotated keys, or replay attacks in one cheap check.
        verify_signature(&self.pubkey, message, &sig)?;
        Ok(sig.to_vec())
    }
}

impl SignerBackend for VaultClient {
    fn name(&self) -> &'static str {
        super::VAULT_BACKEND
    }

    fn public_key(&self) -> Result<Vec<u8>, SignerError> {
        // Operator-supplied; we hand back a clone so callers can compare
        // against the configured `signer_pubkey` envelope guard.
        if self.pubkey.len() == 32 {
            Ok(self.pubkey.clone())
        } else {
            // Misconfigured pubkey — surface as Config so operator notices.
            Err(SignerError::Config(format!(
                "vault pubkey has {} bytes, expected 32",
                self.pubkey.len()
            )))
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        // Default transport under wasm = WakiVaultTransport; host tests drive
        // sign_with directly with a mock and never reach this dispatch.
        #[cfg(target_family = "wasm")]
        {
            self.sign_with(&WakiVaultTransport, message)
        }
        #[cfg(not(target_family = "wasm"))]
        {
            let _ = message;
            Err(SignerError::NotImplemented(
                "VaultClient::sign — host builds have no transport; use sign_with(&mock, ...) in tests",
            ))
        }
    }
}

// ── pure helpers — usable without a VaultTransport ───────────────────────────

/// Build the JSON body for a Vault transit `sign/{key}` POST. Pure and
/// tested — when the wasm transport ships, this exact body ships over the
/// wire. Vault expects `{ "input": "<base64(raw_message)>" }`.
pub fn build_sign_request_body(message: &[u8]) -> Value {
    json!({ "input": B64.encode(message) })
}

/// Strip the `vault:v{N}:` prefix Vault prepends to transit signatures.
///
/// Vault returns signatures as `"vault:v1:<base64>"` (the version matches
/// the key's `latest_version`). The plugin accepts any version prefix —
/// `vault:v1:` through `vault:v999:` — because key rotation bumps the
/// version and the operator's pubkey may trail. Returns the inner base64
/// string slice on success.
///
/// Returns [`SignerError::BadSignature`] when the field is missing the
/// prefix entirely (Vault always emits it for transit signatures — its
/// absence signals a corrupt or non-transit response).
pub fn strip_vault_prefix(sig_field: &str) -> Result<&str, SignerError> {
    // Find "vault:v" then skip past the version number and trailing colon.
    let rest = sig_field.strip_prefix("vault:v").ok_or_else(|| {
        SignerError::BadSignature(format!("missing 'vault:vN:' prefix (got {sig_field:?})"))
    })?;
    let colon = rest.find(':').ok_or_else(|| {
        SignerError::BadSignature(format!(
            "malformed 'vault:vN:' prefix — missing version terminator (got {sig_field:?})"
        ))
    })?;
    Ok(&rest[colon + 1..])
}

/// Parse a Vault transit sign response body and extract the raw 64-byte
/// Ed25519 signature. Pure and tested. Returns:
///   - `Ok([u8; 64])` on a well-formed `data.signature` field with valid
///     base64 after the `vault:vN:` prefix.
///   - `Err(SignerError::Backend)` when Vault returned a top-level
///     `errors` array (4xx/5xx body).
///   - `Err(SignerError::BadSignature)` when `data.signature` is missing,
///     prefix-malformed, not valid base64, or not exactly 64 bytes.
pub fn parse_sign_response(body: &Value) -> Result<[u8; 64], SignerError> {
    // Vault surfaces errors as a top-level `errors` string array.
    if let Some(errors) = body.get("errors").and_then(Value::as_array) {
        if !errors.is_empty() {
            let joined = errors
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(SignerError::Backend(format!("vault: {joined}")));
        }
    }
    let sig_field = body
        .get("data")
        .and_then(|d| d.get("signature"))
        .and_then(Value::as_str)
        .ok_or_else(|| SignerError::BadSignature("missing data.signature field".to_string()))?;
    let b64_inner = strip_vault_prefix(sig_field)?;
    let sig = B64
        .decode(b64_inner)
        .map_err(|e| SignerError::BadSignature(format!("base64 decode failed: {e}")))?;
    let len = sig.len();
    let arr: [u8; 64] = sig
        .try_into()
        .map_err(|_| SignerError::BadSignature(format!("expected 64 bytes, got {len}")))?;
    Ok(arr)
}

/// Verify a 64-byte Ed25519 signature against a 32-byte pubkey over
/// `message`. Pure — tested directly. Returns `Ok(())` on success,
/// `Err(SignerError::BadSignature)` on any failure (wrong pubkey length,
/// bad signature encoding, cryptographic mismatch).
pub fn verify_signature(pubkey: &[u8], message: &[u8], sig: &[u8]) -> Result<(), SignerError> {
    let pubkey_arr: [u8; 32] = pubkey
        .try_into()
        .map_err(|_| SignerError::BadSignature(format!("pubkey len {} != 32", pubkey.len())))?;
    let sig_arr: [u8; 64] = sig
        .try_into()
        .map_err(|_| SignerError::BadSignature(format!("sig len {} != 64", sig.len())))?;
    let verifying = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|e| SignerError::BadSignature(format!("invalid pubkey: {e}")))?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying
        .verify(message, &signature)
        .map_err(|e| SignerError::BadSignature(format!("signature verification failed: {e}")))?;
    Ok(())
}

// ── wasm-only transport impl ────────────────────────────────────────────────

#[cfg(target_family = "wasm")]
mod waki_transport {
    use super::VaultTransport;
    use serde_json::Value;

    /// `waki`-backed [`VaultTransport`] for the wasm32-wasip2 component.
    /// Performs blocking `wasi:http` POSTs with `X-Vault-Token` — TLS
    /// termination happens host-side per the ZeroClaw jail model. The token
    /// never lands in URL/query (which would leak into server logs); it
    /// rides only in the header.
    #[derive(Debug, Clone, Default)]
    pub struct WakiVaultTransport;

    impl WakiVaultTransport {
        pub fn new() -> Self {
            Self
        }
    }

    impl VaultTransport for WakiVaultTransport {
        fn post_with_token(
            &self,
            url: &str,
            body: &Value,
            vault_token: &str,
        ) -> Result<Value, String> {
            let resp = waki::Client::new()
                .post(url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("X-Vault-Token", vault_token)
                .json(body)
                .send()
                .map_err(|e| format!("waki POST {url} failed: {e}"))?;
            let val = resp
                .json::<Value>()
                .map_err(|e| format!("waki decode JSON from {url} failed: {e}"))?;
            Ok(val)
        }
    }
}

#[cfg(target_family = "wasm")]
pub use waki_transport::WakiVaultTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // ── fixtures ────────────────────────────────────────────────────────────

    /// Deterministic ed25519 keypair for tests — same seed every run, so the
    /// signature outputs are reproducible. Seed is 32 zero bytes (a valid but
    /// weak key — fine for fixture use, never used in production).
    fn test_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let seed = [0u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }
    fn fixture_with_pubkey(pubkey: Vec<u8>) -> VaultClient {
        VaultClient::new(
            "https://vault.example:8200",
            "hvs.AFAKESESSIONTOKEN",
            "solana-session",
            pubkey,
        )
    }

    /// A mock transport that returns a queued response — or the request it
    /// captured for assertions. Captures the URL + token so we can assert
    /// the client wired them correctly.
    struct MockVaultTransport {
        response: Value,
        captured_url: Mutex<String>,
        captured_token: Mutex<String>,
        captured_body: Mutex<Value>,
        call_count: AtomicUsize,
    }

    impl MockVaultTransport {
        fn new(response: Value) -> Self {
            Self {
                response,
                captured_url: Mutex::new(String::new()),
                captured_token: Mutex::new(String::new()),
                captured_body: Mutex::new(Value::Null),
                call_count: AtomicUsize::new(0),
            }
        }
    }

    impl VaultTransport for MockVaultTransport {
        fn post_with_token(
            &self,
            url: &str,
            body: &Value,
            vault_token: &str,
        ) -> Result<Value, String> {
            *self.captured_url.lock().unwrap() = url.to_string();
            *self.captured_token.lock().unwrap() = vault_token.to_string();
            *self.captured_body.lock().unwrap() = body.clone();
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.response.clone())
        }
    }

    fn vault_ok_response(sig_bytes: &[u8]) -> Value {
        json!({
            "request_id": "abc-123",
            "data": {
                "signature": format!("vault:v1:{}", B64.encode(sig_bytes))
            }
        })
    }

    // ── VaultClient shape ───────────────────────────────────────────────────

    #[test]
    fn sign_url_has_no_double_slash_and_includes_key_name() {
        let c = VaultClient::new(
            "https://vault.example:8200/",
            "tok",
            "solana-session",
            vec![0u8; 32],
        );
        assert_eq!(
            c.sign_url(),
            "https://vault.example:8200/v1/transit/sign/solana-session"
        );
    }

    #[test]
    fn public_key_returns_operator_supplied_32_bytes() {
        let c = fixture_with_pubkey(vec![0u8; 32]);
        assert_eq!(c.public_key().unwrap(), vec![0u8; 32]);
    }

    #[test]
    fn public_key_rejects_wrong_length_with_config_error() {
        let c = VaultClient::new("https://v", "t", "k", vec![0u8; 31]);
        match c.public_key() {
            Err(SignerError::Config(msg)) => assert!(msg.contains("32"), "msg: {msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_vault_token() {
        let c = fixture_with_pubkey(vec![0u8; 32]);
        let s = format!("{c:?}");
        assert!(!s.contains("hvs.AFAKESESSIONTOKEN"), "leaked: {s}");
        assert!(s.contains("<redacted>"), "should show <redacted>: {s}");
        assert!(
            s.contains("vault.example"),
            "non-secret fields still visible: {s}"
        );
    }

    #[test]
    fn name_returns_vault_backend_constant() {
        let c = fixture_with_pubkey(vec![0u8; 32]);
        assert_eq!(c.name(), super::super::VAULT_BACKEND);
        assert_eq!(c.name(), "vault");
    }

    // ── build_sign_request_body ─────────────────────────────────────────────

    #[test]
    fn build_sign_request_body_base64_encodes_the_raw_message() {
        let body = build_sign_request_body(b"hello vault");
        let b64 = body["input"].as_str().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), b"hello vault");
    }

    #[test]
    fn build_sign_request_body_round_trips_arbitrary_bytes() {
        let bin: Vec<u8> = (0..=255).collect();
        let body = build_sign_request_body(&bin);
        let b64 = body["input"].as_str().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), bin);
    }

    // ── strip_vault_prefix ──────────────────────────────────────────────────

    #[test]
    fn strip_vault_prefix_handles_version_1() {
        assert_eq!(strip_vault_prefix("vault:v1:YWJj").unwrap(), "YWJj");
    }

    #[test]
    fn strip_vault_prefix_handles_any_version_number() {
        // Operator may have rotated the transit key; the prefix version bumps.
        assert_eq!(strip_vault_prefix("vault:v2:YWJj").unwrap(), "YWJj");
        assert_eq!(strip_vault_prefix("vault:v42:YWJj").unwrap(), "YWJj");
        assert_eq!(strip_vault_prefix("vault:v999:YWJj").unwrap(), "YWJj");
    }

    #[test]
    fn strip_vault_prefix_rejects_missing_prefix() {
        let err = strip_vault_prefix("just-a-base64-blob").unwrap_err();
        assert!(matches!(err, SignerError::BadSignature(_)));
        assert!(err.to_string().contains("prefix"));
    }

    #[test]
    fn strip_vault_prefix_rejects_missing_version_terminator() {
        let err = strip_vault_prefix("vault:v1-without-colon").unwrap_err();
        assert!(matches!(err, SignerError::BadSignature(_)));
        assert!(err.to_string().contains("version terminator"));
    }

    // ── parse_sign_response ─────────────────────────────────────────────────

    #[test]
    fn parse_sign_response_extracts_64_byte_signature() {
        let sig: Vec<u8> = (0..64).collect();
        let resp = vault_ok_response(&sig);
        let out = parse_sign_response(&resp).unwrap();
        assert_eq!(out.to_vec(), sig);
    }

    #[test]
    fn parse_sign_response_surfaces_vault_errors_array_as_backend() {
        let resp = json!({
            "errors": ["permission denied", "invalid token"]
        });
        let err = parse_sign_response(&resp).unwrap_err();
        match err {
            SignerError::Backend(msg) => {
                assert!(msg.contains("permission denied"), "msg: {msg}");
                assert!(msg.contains("invalid token"), "msg: {msg}");
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn parse_sign_response_treats_empty_errors_array_as_ok_path() {
        // Vault sometimes returns `"errors": []` on success — must not trip.
        let sig = B64.encode(vec![0u8; 64]);
        let resp = json!({
            "errors": [],
            "data": { "signature": format!("vault:v1:{sig}") }
        });
        assert!(parse_sign_response(&resp).is_ok());
    }

    #[test]
    fn parse_sign_response_rejects_missing_data_signature() {
        let resp = json!({ "data": {} });
        let err = parse_sign_response(&resp).unwrap_err();
        assert!(matches!(err, SignerError::BadSignature(_)));
    }

    #[test]
    fn parse_sign_response_rejects_signature_with_wrong_prefix() {
        let sig = B64.encode(vec![0u8; 64]);
        let resp = json!({ "data": { "signature": sig } });
        let err = parse_sign_response(&resp).unwrap_err();
        assert!(matches!(err, SignerError::BadSignature(_)));
    }

    #[test]
    fn parse_sign_response_rejects_malformed_base64() {
        let resp = json!({ "data": { "signature": "vault:v1:not!!!base64" } });
        let err = parse_sign_response(&resp).unwrap_err();
        assert!(matches!(err, SignerError::BadSignature(_)));
        assert!(err.to_string().contains("base64"));
    }

    #[test]
    fn parse_sign_response_rejects_wrong_length_signature() {
        let too_short = B64.encode(vec![0u8; 32]);
        let resp = json!({ "data": { "signature": format!("vault:v1:{too_short}") } });
        let err = parse_sign_response(&resp).unwrap_err();
        assert!(err.to_string().contains("expected 64 bytes"));
    }

    // ── verify_signature ───────────────────────────────────────────────────

    #[test]
    fn verify_signature_accepts_a_known_good_signature() {
        let (signing, verifying) = test_keypair();
        let message = b"a test message that is signed";
        let sig = signing.sign(message);
        let pubkey = verifying.to_bytes();
        verify_signature(&pubkey, message, &sig.to_bytes()).expect("must verify");
    }

    #[test]
    fn verify_signature_rejects_a_tampered_message() {
        let (signing, verifying) = test_keypair();
        let sig = signing.sign(b"original message");
        // Verify against a DIFFERENT message — must fail.
        let err = verify_signature(&verifying.to_bytes(), b"tampered message", &sig.to_bytes())
            .expect_err("must reject");
        assert!(matches!(err, SignerError::BadSignature(_)));
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn verify_signature_rejects_a_wrong_pubkey() {
        let (signing, _) = test_keypair();
        let (_, other_verifying) = other_keypair();
        let message = b"some message";
        let sig = signing.sign(message);
        let err = verify_signature(&other_verifying.to_bytes(), message, &sig.to_bytes())
            .expect_err("must reject");
        assert!(err.to_string().contains("verification failed"));
    }

    fn other_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let seed = [1u8; 32]; // different seed
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn verify_signature_rejects_wrong_pubkey_length() {
        let err = verify_signature(&[0u8; 31], b"msg", &[0u8; 64]).expect_err("must reject");
        assert!(err.to_string().contains("pubkey len"));
    }

    #[test]
    fn verify_signature_rejects_wrong_sig_length() {
        let err = verify_signature(&[0u8; 32], b"msg", &[0u8; 63]).expect_err("must reject");
        assert!(err.to_string().contains("sig len"));
    }

    // ── VaultClient::sign_with — end-to-end (mocked transport) ──────────────

    #[test]
    fn sign_with_returns_verified_signature_on_happy_path() {
        let (signing, verifying) = test_keypair();
        let message = b"the message we want Vault to sign";
        let sig = signing.sign(message);

        let transport = MockVaultTransport::new(vault_ok_response(&sig.to_bytes()));
        let client = fixture_with_pubkey(verifying.to_bytes().to_vec());

        let out = client.sign_with(&transport, message).expect("must succeed");
        assert_eq!(out, sig.to_bytes());
        assert_eq!(transport.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sign_with_propagates_vault_error_envelope_as_backend() {
        let transport = MockVaultTransport::new(json!({
            "errors": ["1 error occurred:\n\t* permission denied\n\n"]
        }));
        let client = fixture_with_pubkey(vec![0u8; 32]);
        let err = client.sign_with(&transport, b"msg").expect_err("must fail");
        match err {
            SignerError::Backend(msg) => assert!(msg.contains("permission denied"), "msg: {msg}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn sign_with_rejects_vault_response_with_wrong_pubkey_with_badsig() {
        // Vault returned a signature that does NOT verify against the
        // operator-configured pubkey — defense-in-depth check fires.
        let (signing, _) = test_keypair(); // signs with seed=0
        let (_, verifying) = other_keypair(); // pubkey from seed=1
        let message = b"msg";
        let sig = signing.sign(message);
        let transport = MockVaultTransport::new(vault_ok_response(&sig.to_bytes()));
        let client = fixture_with_pubkey(verifying.to_bytes().to_vec());
        let err = client
            .sign_with(&transport, message)
            .expect_err("must fail");
        assert!(matches!(err, SignerError::BadSignature(_)));
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn sign_with_sends_x_vault_token_header_and_correct_url() {
        // The mock captures what the client actually sent. Verifying the
        // wiring (URL, token) here means the wasm transport layer does not
        // have to.
        let (signing, verifying) = test_keypair();
        let message = b"audit the request shape";
        let sig = signing.sign(message);
        let transport = MockVaultTransport::new(vault_ok_response(&sig.to_bytes()));
        let client = fixture_with_pubkey(verifying.to_bytes().to_vec());

        let _ = client.sign_with(&transport, message).unwrap();

        assert_eq!(
            *transport.captured_url.lock().unwrap(),
            "https://vault.example:8200/v1/transit/sign/solana-session"
        );
        assert_eq!(
            *transport.captured_token.lock().unwrap(),
            "hvs.AFAKESESSIONTOKEN"
        );
        let body = transport.captured_body.lock().unwrap().clone();
        let b64 = body["input"].as_str().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), message);
    }

    #[test]
    fn sign_with_propagates_transport_errors() {
        struct FailingTransport;
        impl VaultTransport for FailingTransport {
            fn post_with_token(
                &self,
                _url: &str,
                _body: &Value,
                _vault_token: &str,
            ) -> Result<Value, String> {
                Err("connection refused".to_string())
            }
        }
        let client = fixture_with_pubkey(vec![0u8; 32]);
        let err = client
            .sign_with(&FailingTransport, b"msg")
            .expect_err("must fail");
        match err {
            SignerError::Transport(msg) => {
                assert!(msg.contains("connection refused"), "msg: {msg}")
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn signer_backend_sign_returns_not_implemented_on_host() {
        // On host, the default SignerBackend::sign dispatch has no transport
        // — host tests drive sign_with(&mock, ...) directly.
        let c = fixture_with_pubkey(vec![0u8; 32]);
        let err = SignerBackend::sign(&c, b"msg").expect_err("host must stub");
        assert!(matches!(err, SignerError::NotImplemented(_)));
        assert!(err.to_string().contains("sign_with"));
    }
}
