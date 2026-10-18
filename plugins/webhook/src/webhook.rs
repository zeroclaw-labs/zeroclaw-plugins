//! Pure generic-webhook channel logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin. It owns everything I/O-free and
//! therefore host-testable with a plain `cargo test`:
//!
//!   * parsing the plugin's `[channels.webhook.<alias>]` config section,
//!   * the optional `X-Webhook-Signature` HMAC-SHA256 authenticity check over the
//!     raw body (hex, `sha256=` prefix tolerated), matching the native channel,
//!   * decoding an inbound `{sender, content, thread_id?}` JSON body into an
//!     inbound message, and
//!   * building the outbound `{content, thread_id?, recipient?}` JSON body.
//!
//! The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O (blocking `waki` HTTP for the outbound POST/PUT) and reuses this logic.
//!
//! The generic webhook is the "universal adapter": any system that can POST JSON
//! to `/plugin/webhook` and (optionally) receive a reply POST/PUT at `send_url`
//! can talk to the agent.

use serde::Deserialize;
use serde_json::{json, Value};

/// The URL path segment the host mounts this channel's webhook under
/// (`/plugin/webhook`).
pub const WEBHOOK_PATH: &str = "webhook";

/// The plugin's config section, mirroring the native `[channels.webhook.<alias>]`
/// snake_case keys. `port` / `listen_path` are native-server concerns (the plugin
/// receives inbound over the host's `/plugin/webhook` route, not its own port);
/// they are accepted for deserialization but unused. serde ignores the rest.
///
/// The host has already validated the object against the manifest's closed
/// schema. The `secret` and `auth_header` properties are `x-secret`, so they
/// never appear here; the shim reads them with `secrets.get` at the point of
/// use.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WebhookConfig {
    /// Host-side enable gate; accepted so a native section deserializes.
    #[serde(default)]
    pub enabled: bool,
    /// URL to POST/PUT outbound replies to. When unset, outbound is a no-op
    /// (matching the native channel).
    #[serde(default)]
    pub send_url: Option<String>,
    /// HTTP method for outbound replies (`POST` or `PUT`). Default: `POST`.
    #[serde(default)]
    pub send_method: Option<String>,
}

impl WebhookConfig {
    /// Parse the public config object returned by `config.get`. Accepts
    /// everything the manifest schema accepts. An empty or malformed string
    /// yields defaults (inert rather than a hard failure).
    pub fn from_public_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// Back-compat alias: the legacy `configure(config)` path fed the whole
    /// section (secrets inline) here. Kept for the host `cargo test` suite;
    /// the wasm shim now uses [`WebhookConfig::from_public_json`] plus
    /// `secrets.get` at the point of use.
    pub fn from_json(config_json: &str) -> Self {
        let value: serde_json::Value = serde_json::from_str(config_json).unwrap_or_default();
        let public = value
            .as_object()
            .map(|object| {
                let mut filtered = serde_json::Map::new();
                for key in ["enabled", "send_url", "send_method"] {
                    if let Some(entry) = object.get(key) {
                        filtered.insert(key.to_string(), entry.clone());
                    }
                }
                serde_json::Value::Object(filtered).to_string()
            })
            .unwrap_or_default();
        Self::from_public_json(&public)
    }

    /// The trimmed outbound URL, or `None` when unset/blank.
    pub fn send_url(&self) -> Option<&str> {
        self.send_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// The upper-cased outbound method (`POST` unless configured `PUT`).
    pub fn send_method(&self) -> String {
        match self
            .send_method
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_uppercase()
        {
            m if m == "PUT" => "PUT".to_string(),
            _ => "POST".to_string(),
        }
    }

    /// The trimmed `Authorization` header value, or `None` when unset/blank.
    /// Read from `secrets.get("auth_header")` at the point of use — never
    /// from the public config object.
    pub fn auth_header_value(auth_header: Option<&str>) -> Option<&str> {
        auth_header.map(str::trim).filter(|s| !s.is_empty())
    }

    /// The trimmed signing secret, or `None` when unset/blank (→ no signature
    /// check). Read from `secrets.get("secret")` at the point of use — never
    /// from the public config object.
    pub fn secret_value(secret: Option<&str>) -> Option<&str> {
        secret.map(str::trim).filter(|s| !s.is_empty())
    }

    /// The trimmed `Authorization` header value, or `None` when unset/blank.
    /// Legacy helper over the struct field; the wasm shim now passes the
    /// `secrets.get` value to [`WebhookConfig::auth_header_value`].
    pub fn auth_header(&self) -> Option<&str> {
        Self::auth_header_value(None)
    }

    /// The trimmed signing secret, or `None` when unset/blank (→ no signature
    /// check). Legacy helper; the wasm shim now passes the `secrets.get`
    /// value to [`WebhookConfig::secret_value`].
    pub fn secret(&self) -> Option<&str> {
        Self::secret_value(None)
    }
}

/// An inbound webhook message, pre-WIT-lift. The `channel` is always
/// `"webhook"`, stamped by the host shim; `id` (`webhook_<seq>`) is assigned
/// there too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub thread_ts: Option<String>,
}

/// The inbound payload shape: `{sender, content, thread_id?}`.
#[derive(Debug, Deserialize)]
struct IncomingWebhook {
    #[serde(default)]
    sender: String,
    content: String,
    #[serde(default)]
    thread_id: Option<String>,
}

/// Verify an inbound request's signature. Returns `true` when no secret is
/// configured (accept all), `false` when a secret is set but the signature is
/// absent or does not match. The signature is
/// `hex(HMAC-SHA256(secret, body))` with an optional `sha256=` prefix (mirrors
/// the native channel).
pub fn verify_signature(secret: Option<&str>, body: &[u8], signature: Option<&str>) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let Some(secret) = secret else {
        return true; // no secret configured → accept
    };
    let Some(sig) = signature else {
        return false; // secret set but no signature provided
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    let hex_sig = sig.trim().strip_prefix("sha256=").unwrap_or(sig.trim());
    let Ok(expected) = hex::decode(hex_sig) else {
        return false;
    };
    mac.verify_slice(&expected).is_ok()
}

/// Decode an inbound webhook body into an [`Inbound`]. Returns `Err` on invalid
/// JSON or an empty `content` (the host maps these to `400`). `reply_target` is
/// the `thread_id` when present, else the `sender`.
pub fn parse_incoming(body: &[u8]) -> Result<Inbound, String> {
    let payload: IncomingWebhook =
        serde_json::from_slice(body).map_err(|e| format!("webhook: invalid JSON payload: {e}"))?;
    if payload.content.is_empty() {
        return Err("webhook: empty content".to_string());
    }
    let reply_target = payload
        .thread_id
        .clone()
        .unwrap_or_else(|| payload.sender.clone());
    Ok(Inbound {
        sender: payload.sender,
        reply_target,
        content: payload.content,
        thread_ts: payload.thread_id,
    })
}

/// Build the outbound reply body: `{content, thread_id?, recipient?}`. `None` /
/// empty `recipient` and absent `thread_ts` are omitted (mirrors the native
/// `OutgoingWebhook`).
pub fn build_outgoing(content: &str, thread_ts: Option<&str>, recipient: &str) -> Value {
    let mut obj = json!({ "content": content });
    if let Some(t) = thread_ts {
        obj["thread_id"] = json!(t);
    }
    if !recipient.is_empty() {
        obj["recipient"] = json!(recipient);
    }
    obj
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn config_parses_defaults_and_method() {
        let cfg = WebhookConfig::from_public_json(
            r#"{"enabled":true,"send_url":" https://x/cb ","send_method":"put"}"#,
        );
        assert!(cfg.enabled);
        assert_eq!(cfg.send_url(), Some("https://x/cb"));
        assert_eq!(cfg.send_method(), "PUT");
        // x-secret values arrive via secrets.get, never in the public object.
        assert_eq!(
            WebhookConfig::auth_header_value(Some(" Bearer k ")),
            Some("Bearer k")
        );
        assert_eq!(WebhookConfig::secret_value(Some(" s ")), Some("s"));

        let d = WebhookConfig::from_public_json("{}");
        assert_eq!(d.send_url(), None);
        assert_eq!(d.send_method(), "POST"); // default
        assert_eq!(WebhookConfig::secret_value(None), None);
        // malformed → defaults
        assert_eq!(
            WebhookConfig::from_public_json("nope").send_method(),
            "POST"
        );
        // legacy path strips secrets before parsing (back-compat).
        let legacy = WebhookConfig::from_json(
            r#"{"send_url":"https://x/cb","secret":"s","auth_header":"k"}"#,
        );
        assert_eq!(legacy.send_url(), Some("https://x/cb"));
    }

    #[test]
    fn config_ignores_native_only_fields() {
        // port / listen_path / retry_* exist in the native section; must not fail.
        let cfg = WebhookConfig::from_public_json(
            r#"{"port":8090,"listen_path":"/hooks","max_retries":5}"#,
        );
        assert_eq!(cfg.send_url(), None);
    }

    #[test]
    fn signature_no_secret_accepts_all() {
        assert!(verify_signature(None, b"anything", None));
        assert!(verify_signature(None, b"anything", Some("whatever")));
    }

    #[test]
    fn signature_secret_requires_valid_sig() {
        let secret = "mysecret";
        let body = b"test body";
        let good = sign(secret, body);
        assert!(verify_signature(Some(secret), body, Some(&good)));
        // sha256= prefix tolerated
        assert!(verify_signature(
            Some(secret),
            body,
            Some(&format!("sha256={good}"))
        ));
        // secret set, no signature → reject
        assert!(!verify_signature(Some(secret), body, None));
        // wrong signature / tampered body / non-hex
        assert!(!verify_signature(Some(secret), body, Some("deadbeef")));
        assert!(!verify_signature(Some(secret), b"other", Some(&good)));
        assert!(!verify_signature(Some(secret), body, Some("nothex")));
    }

    #[test]
    fn parse_incoming_full_and_minimal() {
        let full = parse_incoming(br#"{"sender":"u","content":"hi","thread_id":"t1"}"#).unwrap();
        assert_eq!(full.sender, "u");
        assert_eq!(full.content, "hi");
        assert_eq!(full.reply_target, "t1"); // thread_id wins
        assert_eq!(full.thread_ts.as_deref(), Some("t1"));

        let min = parse_incoming(br#"{"sender":"u","content":"hi"}"#).unwrap();
        assert_eq!(min.reply_target, "u"); // falls back to sender
        assert_eq!(min.thread_ts, None);
    }

    #[test]
    fn parse_incoming_rejects_empty_and_bad_json() {
        assert!(parse_incoming(br#"{"sender":"u","content":""}"#).is_err());
        assert!(parse_incoming(b"not json").is_err());
        // missing content field → error (content is required)
        assert!(parse_incoming(br#"{"sender":"u"}"#).is_err());
    }

    #[test]
    fn build_outgoing_omits_absent_fields() {
        let full = build_outgoing("resp", Some("t1"), "u");
        assert_eq!(full["content"], "resp");
        assert_eq!(full["thread_id"], "t1");
        assert_eq!(full["recipient"], "u");

        let bare = build_outgoing("resp", None, "");
        assert_eq!(bare["content"], "resp");
        assert!(bare.get("thread_id").is_none());
        assert!(bare.get("recipient").is_none());
    }
}
