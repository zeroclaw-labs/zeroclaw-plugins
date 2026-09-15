//! Multi-backend signer trait + factory.
//!
//! Each backend (Vault transit v0, AWS KMS v1, GCP KMS v1) implements
//! [`SignerBackend`]. The plugin picks one at runtime via
//! [`from_config`], which resolves the `backend` discriminator (`"vault"` |
//! `"aws_kms"` | `"gcp_kms"`) to a boxed trait object.
//!
//! All backends return signature bytes (`Vec<u8>`) for a given message — the
//! Solana signing primitive is Ed25519 (64-byte sig, 32-byte pubkey), but the
//! trait stays shape-agnostic so v1+ backends with different key types can
//! still plug in. The plugin's caller is responsible for asserting the
//! returned lengths match Solana's expectations.
//!
//! Secrets (`vault_token`, `aws_secret_access_key`, `gcp_access_token`) never
//! appear in [`SignerError`] payloads, log-record attrs, or `Debug` output —
//! every backend struct redacts its secret field.

use std::collections::HashMap;
use std::fmt;

pub mod aws_kms;
pub mod gcp_kms;
pub mod vault;

/// Discriminator values [`from_config`] accepts. The operator picks one per
/// session under `[plugins.entries.solana-keychain-sign.config] backend = ...`.
pub const VAULT_BACKEND: &str = "vault";
pub const AWS_KMS_BACKEND: &str = "aws_kms";
pub const GCP_KMS_BACKEND: &str = "gcp_kms";

/// Backend-agnostic signer error. Variants are operator-facing — secrets
/// (`vault_token`, `secret_access_key`, etc.) never appear in any variant's
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// Backend is shipped as a stub for v0. The string names which method +
    /// the reason (e.g. `"AwsKmsClient::sign — needs SigV4 hand-roll"`).
    NotImplemented(&'static str),
    /// Transport-layer failure (HTTP timeout, TLS error, network unreachable).
    Transport(String),
    /// Backend returned an error response (KMS error envelope, Vault 4xx/5xx,
    /// etc.). Free-form since each backend has its own error shape.
    Backend(String),
    /// Signature decoding failure — response was structurally OK but the
    /// signature bytes were missing, malformed, or wrong length.
    BadSignature(String),
    /// Operator config is incomplete or contradictory (missing key id, empty
    /// token, malformed URL, unknown backend discriminator).
    Config(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
            Self::Backend(msg) => write!(f, "backend error: {msg}"),
            Self::BadSignature(msg) => write!(f, "bad signature: {msg}"),
            Self::Config(msg) => write!(f, "config error: {msg}"),
        }
    }
}

impl std::error::Error for SignerError {}

/// Signing backend abstraction. v0 ships Vault transit (fully working); AWS
/// KMS + GCP KMS return [`SignerError::NotImplemented`] with a documented
/// hand-roll plan.
///
/// Methods are `&self` — backends are stateless post-construction. Each
/// method returns owned bytes so backends that fetch the pubkey lazily can
/// allocate without borrowing constraints.
///
/// [`SignerBackend::name`] is the short identifier that goes into `log-record`
/// `attrs` so the operator can audit which backend handled each call without
/// inspecting source. It must be `&'static str` so trait-object dispatch can
/// return it without allocating.
///
/// Requires [`fmt::Debug`] as a supertrait so `Box<dyn SignerBackend>` is
/// `Debug` — every concrete backend struct already implements `Debug`
/// (with manual redaction of its secret field).
pub trait SignerBackend: fmt::Debug {
    /// Short stable identifier (`"vault"`, `"aws_kms"`, `"gcp_kms"`). Used in
    /// structured log output; never user-facing free text.
    fn name(&self) -> &'static str;

    /// Return the backend's Ed25519 public key (32 bytes). This is the
    /// Solana fee-payer / signing key — the signer plugin asserts this
    /// matches the operator-configured `signer_pubkey` envelope guard.
    fn public_key(&self) -> Result<Vec<u8>, SignerError>;

    /// Sign `message` and return the 64-byte Ed25519 signature. The caller
    /// is responsible for assembling the signed transaction from the
    /// returned bytes; this method does NOT submit to the network.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// Operator config for backend construction.
///
/// Holds every field any backend needs as plain owned strings — the host
/// injects config as a flat `String -> String` map (same model as
/// `redact-text`), and [`BackendConfig::from_section`] parses that into this
/// struct. Fields not relevant to the selected backend default to empty
/// strings and are simply ignored. This keeps the schema flat and operator-
/// editable; the factory ([`from_config`]) reads only the slice it needs.
///
/// Secret fields (`vault_token`, `aws_secret_access_key`, `gcp_access_token`)
/// are held by value; the per-backend clients redact them from `Debug` and
/// they never appear in [`SignerError`] variants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendConfig {
    /// Discriminator: one of [`VAULT_BACKEND`], [`AWS_KMS_BACKEND`],
    /// [`GCP_KMS_BACKEND`]. Anything else →
    /// [`SignerError::Config`] from [`from_config`].
    pub backend: String,

    // ── Vault transit ───────────────────────────────────────────────────
    pub vault_addr: String,
    pub vault_token: String,
    pub vault_key_name: String,
    /// Base58-encoded 32-byte Ed25519 public key (operator-extracted via
    /// `vault read transit/keys/<name>`). Decoded to bytes at factory time.
    pub vault_pubkey: String,

    // ── AWS KMS ─────────────────────────────────────────────────────────
    pub aws_region: String,
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_key_id: String,

    // ── GCP Cloud KMS ───────────────────────────────────────────────────
    pub gcp_project: String,
    pub gcp_location: String,
    pub gcp_key_ring: String,
    pub gcp_crypto_key: String,
    pub gcp_version: String,
    /// Short-lived OAuth2 access token (`gcloud auth print-access-token`).
    pub gcp_access_token: String,
}

impl BackendConfig {
    /// Parse the host-injected flat config map into a typed
    /// [`BackendConfig`]. Unknown keys are ignored (forward-compat for new
    /// operator-side knobs); missing keys default to empty string and are
    /// enforced later by [`from_config`].
    ///
    /// Errors only on a present-but-empty `backend` discriminator — every
    /// other field's "missing" state is legal until the factory looks at it.
    pub fn from_section(map: &HashMap<String, String>) -> Result<Self, SignerError> {
        let get = |k: &str| map.get(k).cloned().unwrap_or_default();
        let cfg = Self {
            backend: get("backend"),
            vault_addr: get("vault_addr"),
            vault_token: get("vault_token"),
            vault_key_name: get("vault_key_name"),
            vault_pubkey: get("vault_pubkey"),
            aws_region: get("aws_region"),
            aws_access_key_id: get("aws_access_key_id"),
            aws_secret_access_key: get("aws_secret_access_key"),
            aws_key_id: get("aws_key_id"),
            gcp_project: get("gcp_project"),
            gcp_location: get("gcp_location"),
            gcp_key_ring: get("gcp_key_ring"),
            gcp_crypto_key: get("gcp_crypto_key"),
            gcp_version: get("gcp_version"),
            gcp_access_token: get("gcp_access_token"),
        };
        // Only the discriminator itself is fatal at parse time. Everything
        // else surfaces from from_config() with a precise Config error
        // (e.g. "vault backend requires vault_addr").
        if cfg.backend.is_empty() {
            return Err(SignerError::Config(
                "missing `backend` discriminator (expected 'vault' | 'aws_kms' | 'gcp_kms')".into(),
            ));
        }
        Ok(cfg)
    }
}

/// Construct a [`SignerBackend`] from operator config.
///
/// `backend_name` overrides `cfg.backend` when non-empty — supports callers
/// (tests, SOP triggers) that want to force a specific backend without
/// mutating the parsed config. Pass `""` to use `cfg.backend` as-is.
///
/// Returns `Err(SignerError::Config)` for:
///   - unknown `backend` discriminator
///   - missing required fields for the chosen backend (non-empty URL, token,
///     key id, etc.)
///   - malformed `vault_pubkey` (not valid base58 / not 32 bytes)
pub fn from_config(
    backend_name: &str,
    cfg: &BackendConfig,
) -> Result<Box<dyn SignerBackend>, SignerError> {
    let kind = if backend_name.is_empty() {
        cfg.backend.as_str()
    } else {
        backend_name
    };
    match kind {
        VAULT_BACKEND => {
            require(&cfg.vault_addr, "vault backend requires vault_addr")?;
            require(&cfg.vault_token, "vault backend requires vault_token")?;
            require(&cfg.vault_key_name, "vault backend requires vault_key_name")?;
            require(&cfg.vault_pubkey, "vault backend requires vault_pubkey")?;
            let pubkey = bs58::decode(&cfg.vault_pubkey)
                .into_vec()
                .map_err(|e| SignerError::Config(format!("vault_pubkey not base58: {e}")))?;
            if pubkey.len() != 32 {
                return Err(SignerError::Config(format!(
                    "vault_pubkey decoded to {} bytes, expected 32",
                    pubkey.len()
                )));
            }
            Ok(Box::new(vault::VaultClient::new(
                cfg.vault_addr.clone(),
                cfg.vault_token.clone(),
                cfg.vault_key_name.clone(),
                pubkey,
            )))
        }
        AWS_KMS_BACKEND => {
            require(&cfg.aws_region, "aws_kms backend requires aws_region")?;
            require(
                &cfg.aws_access_key_id,
                "aws_kms backend requires aws_access_key_id",
            )?;
            require(
                &cfg.aws_secret_access_key,
                "aws_kms backend requires aws_secret_access_key",
            )?;
            require(&cfg.aws_key_id, "aws_kms backend requires aws_key_id")?;
            Ok(Box::new(aws_kms::AwsKmsClient::new(
                cfg.aws_region.clone(),
                cfg.aws_access_key_id.clone(),
                cfg.aws_secret_access_key.clone(),
                cfg.aws_key_id.clone(),
            )))
        }
        GCP_KMS_BACKEND => {
            require(&cfg.gcp_project, "gcp_kms backend requires gcp_project")?;
            require(&cfg.gcp_location, "gcp_kms backend requires gcp_location")?;
            require(&cfg.gcp_key_ring, "gcp_kms backend requires gcp_key_ring")?;
            require(
                &cfg.gcp_crypto_key,
                "gcp_kms backend requires gcp_crypto_key",
            )?;
            require(&cfg.gcp_version, "gcp_kms backend requires gcp_version")?;
            require(
                &cfg.gcp_access_token,
                "gcp_kms backend requires gcp_access_token",
            )?;
            Ok(Box::new(gcp_kms::GcpKmsClient::new(
                cfg.gcp_project.clone(),
                cfg.gcp_location.clone(),
                cfg.gcp_key_ring.clone(),
                cfg.gcp_crypto_key.clone(),
                cfg.gcp_version.clone(),
                cfg.gcp_access_token.clone(),
            )))
        }
        other => Err(SignerError::Config(format!(
            "unknown backend '{other}' (expected 'vault' | 'aws_kms' | 'gcp_kms')"
        ))),
    }
}

/// Internal: reject empty-string required fields with a precise Config error.
fn require(value: &str, reason: &'static str) -> Result<(), SignerError> {
    if value.is_empty() {
        Err(SignerError::Config(reason.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── BackendConfig::from_section ────────────────────────────────────────────

    #[test]
    fn from_section_returns_empty_discriminator_error() {
        let map = HashMap::new();
        let err = BackendConfig::from_section(&map).expect_err("no backend key");
        assert!(matches!(err, SignerError::Config(_)));
        assert!(err.to_string().contains("backend"), "msg: {err}");
    }

    #[test]
    fn from_section_reads_discriminator_and_known_fields() {
        let mut map = HashMap::new();
        map.insert("backend".into(), "vault".into());
        map.insert("vault_addr".into(), "https://vault.example".into());
        map.insert("vault_token".into(), "hvs.TOKEN".into());
        map.insert("vault_key_name".into(), "solana-session".into());
        map.insert(
            "vault_pubkey".into(),
            "11111111111111111111111111111111".into(),
        );
        // Unknown keys ignored — forward-compat for new config knobs.
        map.insert("unknown_future_key".into(), "ignored".into());

        let cfg = BackendConfig::from_section(&map).unwrap();
        assert_eq!(cfg.backend, "vault");
        assert_eq!(cfg.vault_addr, "https://vault.example");
        assert_eq!(cfg.vault_pubkey, "11111111111111111111111111111111");
    }

    #[test]
    fn from_section_defaults_missing_fields_to_empty_string() {
        let mut map = HashMap::new();
        map.insert("backend".into(), "aws_kms".into());
        let cfg = BackendConfig::from_section(&map).unwrap();
        assert_eq!(cfg.backend, "aws_kms");
        assert!(cfg.aws_region.is_empty(), "missing fields default empty");
        assert!(cfg.vault_addr.is_empty(), "non-applicable fields empty");
    }

    // ── from_config — happy paths ─────────────────────────────────────────────

    fn vault_cfg() -> BackendConfig {
        let mut map = HashMap::new();
        map.insert("backend".into(), "vault".into());
        map.insert("vault_addr".into(), "https://vault.example".into());
        map.insert("vault_token".into(), "hvs.TOKEN".into());
        map.insert("vault_key_name".into(), "solana-session".into());
        // 32 zero bytes as base58.
        map.insert(
            "vault_pubkey".into(),
            bs58::encode(vec![0u8; 32]).into_string(),
        );
        BackendConfig::from_section(&map).unwrap()
    }

    fn aws_cfg() -> BackendConfig {
        let mut map = HashMap::new();
        map.insert("backend".into(), "aws_kms".into());
        map.insert("aws_region".into(), "us-east-1".into());
        map.insert("aws_access_key_id".into(), "AKIAFAKE".into());
        map.insert("aws_secret_access_key".into(), "secret".into());
        map.insert("aws_key_id".into(), "mrk-key".into());
        BackendConfig::from_section(&map).unwrap()
    }

    fn gcp_cfg() -> BackendConfig {
        let mut map = HashMap::new();
        map.insert("backend".to_string(), "gcp_kms".to_string());
        map.insert("gcp_project".to_string(), "p".to_string());
        map.insert("gcp_location".to_string(), "l".to_string());
        map.insert("gcp_key_ring".to_string(), "kr".to_string());
        map.insert("gcp_crypto_key".to_string(), "ck".to_string());
        map.insert("gcp_version".to_string(), "1".to_string());
        map.insert("gcp_access_token".to_string(), "tok".to_string());
        BackendConfig::from_section(&map).unwrap()
    }

    #[test]
    fn from_config_resolves_vault_and_reports_correct_name() {
        let cfg = vault_cfg();
        let b = from_config("", &cfg).unwrap();
        assert_eq!(b.name(), VAULT_BACKEND);
        assert_eq!(b.public_key().unwrap(), vec![0u8; 32]);
        // sign() returns NotImplemented naming the owner bean.
        assert!(matches!(
            b.sign(b"msg"),
            Err(SignerError::NotImplemented(_))
        ));
    }

    #[test]
    fn from_config_resolves_aws_kms_and_reports_correct_name() {
        let cfg = aws_cfg();
        let b = from_config("", &cfg).unwrap();
        assert_eq!(b.name(), AWS_KMS_BACKEND);
        assert!(b.public_key().is_err(), "AWS public_key is stubbed");
        assert!(b.sign(b"msg").is_err());
    }

    #[test]
    fn from_config_resolves_gcp_kms_and_reports_correct_name() {
        let cfg = gcp_cfg();
        let b = from_config("", &cfg).unwrap();
        assert_eq!(b.name(), GCP_KMS_BACKEND);
        assert!(b.public_key().is_err());
        assert!(b.sign(b"msg").is_err());
    }

    #[test]
    fn from_config_backend_name_override_wins_over_cfg_backend() {
        // A config that has BOTH vault + aws_kms fields populated; the
        // cfg.backend discriminator says "vault" but the caller forces
        // aws_kms. The override takes effect — useful for SOP triggers
        // that want to test a specific backend without mutating config.
        let mut map = HashMap::new();
        map.insert("backend".to_string(), "vault".to_string());
        map.insert("vault_addr".to_string(), "https://v".to_string());
        map.insert("vault_token".to_string(), "t".to_string());
        map.insert("vault_key_name".to_string(), "k".to_string());
        map.insert(
            "vault_pubkey".to_string(),
            bs58::encode(vec![0u8; 32]).into_string(),
        );
        map.insert("aws_region".to_string(), "us-east-1".to_string());
        map.insert("aws_access_key_id".to_string(), "AKIA".to_string());
        map.insert("aws_secret_access_key".to_string(), "secret".to_string());
        map.insert("aws_key_id".to_string(), "mrk-key".to_string());

        let cfg = BackendConfig::from_section(&map).unwrap();
        assert_eq!(cfg.backend, "vault", "config still says vault");

        // Default: vault wins.
        assert_eq!(from_config("", &cfg).unwrap().name(), VAULT_BACKEND);
        // Override: aws_kms wins.
        assert_eq!(
            from_config(AWS_KMS_BACKEND, &cfg).unwrap().name(),
            AWS_KMS_BACKEND
        );
    }

    // ── from_config — error paths ─────────────────────────────────────────────

    #[test]
    fn from_config_rejects_unknown_backend_discriminator() {
        let mut map = HashMap::new();
        map.insert("backend".into(), "azure_key_vault".into());
        let cfg = BackendConfig::from_section(&map).unwrap();
        let err = from_config("", &cfg).expect_err("unknown backend");
        match err {
            SignerError::Config(msg) => {
                assert!(msg.contains("azure_key_vault"), "msg: {msg}");
                assert!(msg.contains("vault"), "msg should hint valid set: {msg}");
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn from_config_vault_requires_every_field() {
        let mut map = HashMap::new();
        map.insert("backend".into(), "vault".into());
        let cfg = BackendConfig::from_section(&map).unwrap();
        let err = from_config("", &cfg).expect_err("missing vault_addr");
        assert!(matches!(err, SignerError::Config(_)));
        assert!(err.to_string().contains("vault_addr"));
    }

    #[test]
    fn from_config_vault_rejects_malformed_pubkey() {
        let mut map = HashMap::new();
        map.insert("backend".into(), "vault".into());
        map.insert("vault_addr".into(), "https://v".into());
        map.insert("vault_token".into(), "t".into());
        map.insert("vault_key_name".into(), "k".into());
        map.insert("vault_pubkey".into(), "this is not base58!".into());
        let cfg = BackendConfig::from_section(&map).unwrap();
        let err = from_config("", &cfg).expect_err("not base58");
        assert!(matches!(err, SignerError::Config(_)));
        assert!(err.to_string().contains("base58"));
    }

    #[test]
    fn from_config_vault_rejects_wrong_length_pubkey() {
        let mut map = HashMap::new();
        map.insert("backend".into(), "vault".into());
        map.insert("vault_addr".into(), "https://v".into());
        map.insert("vault_token".into(), "t".into());
        map.insert("vault_key_name".into(), "k".into());
        // 31 bytes — base58-valid, wrong length.
        map.insert(
            "vault_pubkey".into(),
            bs58::encode(vec![0u8; 31]).into_string(),
        );
        let cfg = BackendConfig::from_section(&map).unwrap();
        let err = from_config("", &cfg).expect_err("wrong length");
        match err {
            SignerError::Config(msg) => assert!(msg.contains("32"), "msg: {msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn from_config_aws_kms_requires_every_field() {
        let mut map = HashMap::new();
        map.insert("backend".into(), "aws_kms".into());
        map.insert("aws_region".into(), "us-east-1".into());
        // Missing access_key_id, secret_access_key, key_id.
        let cfg = BackendConfig::from_section(&map).unwrap();
        let err = from_config("", &cfg).expect_err("missing fields");
        assert!(err.to_string().contains("aws_access_key_id"));
    }

    #[test]
    fn from_config_gcp_kms_requires_every_field() {
        let mut map = HashMap::new();
        map.insert("backend".to_string(), "gcp_kms".to_string());
        map.insert("gcp_project".to_string(), "p".to_string());
        // Missing location, key_ring, crypto_key, version, access_token.
        let cfg = BackendConfig::from_section(&map).unwrap();
        let err = from_config("", &cfg).expect_err("missing fields");
        assert!(err.to_string().contains("gcp_location"));
    }
}
