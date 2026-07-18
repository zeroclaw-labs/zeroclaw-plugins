//! Pure WATI (WhatsApp Business API) webhook logic — no wasm, no HTTP, no host
//! deps.
//!
//! This is the `rlib` half of the plugin. It owns everything I/O-free and
//! therefore host-testable with a plain `cargo test`:
//!
//!   * parsing the plugin's `[channels.wati.<alias>]` config section,
//!   * the WATI/Meta-style verification handshake
//!     (`GET …?hub.challenge=…`, echoed verbatim — WATI does **not** send a
//!     `hub.verify_token`, matching the native gateway),
//!   * decoding a WATI event payload (variable field names) into inbound text
//!     messages, and
//!   * building the `POST /api/ext/v3/conversations/messages/text` send target +
//!     body.
//!
//! The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O (blocking `waki` HTTP calls) and reuses this logic verbatim.
//!
//! ## Security note
//!
//! WATI does not sign its inbound webhooks (there is no HMAC/signature header),
//! and the native gateway performs **no** authenticity check on the inbound
//! `POST /wati` body — it relies on the sender allowlist (`peer_groups`), which
//! the host applies to plugin-returned messages. This plugin therefore performs
//! no signature verification either; deploy the `/plugin/wati` route behind a
//! secret path or network ACL if you need transport authenticity.
//!
//! Scope: **text messages only** (send + receive). Media/voice transcription is
//! intentionally deferred (see README).

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Value};

/// WATI API base (default; overridable via `api_url` in config).
pub const DEFAULT_API_URL: &str = "https://live-mt-server.wati.io";

/// The URL path segment the host mounts this channel's webhook under
/// (`/plugin/wati`). Both the GET verification and the POST event webhook arrive
/// there.
pub const WEBHOOK_PATH: &str = "wati";

/// Reserved `channel` value for a challenge-echo reply. An `InboundMessage`
/// whose `channel` is this and whose `content` is the body to send makes the
/// host reply `200` with that body verbatim and enqueue nothing.
pub const WEBHOOK_REPLY_CHANNEL: &str = "__webhook_reply__";

/// The plugin's config section, mirroring the native `[channels.wati.<alias>]`
/// snake_case keys. serde ignores native fields this text-only v0.1.0 plugin
/// does not use (`proxy_url`, `excluded_tools`, …).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WatiConfig {
    /// Host-side enable gate; accepted so a native section deserializes.
    #[serde(default)]
    pub enabled: bool,
    /// WATI API token (Bearer auth) used to send messages.
    #[serde(default)]
    pub api_token: Option<String>,
    /// WATI API base URL. Defaults to [`DEFAULT_API_URL`].
    #[serde(default)]
    pub api_url: Option<String>,
    /// Tenant ID for multi-channel setups; prefixes the send `target`.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl WatiConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (inert rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// The trimmed API token (may be empty).
    pub fn api_token(&self) -> &str {
        self.api_token.as_deref().unwrap_or("").trim()
    }

    /// The API base with any trailing slash trimmed, falling back to
    /// [`DEFAULT_API_URL`] when unset or blank.
    pub fn api_url(&self) -> String {
        let v = self
            .api_url
            .as_deref()
            .unwrap_or("")
            .trim()
            .trim_end_matches('/');
        if v.is_empty() {
            DEFAULT_API_URL.to_string()
        } else {
            v.to_string()
        }
    }

    /// The trimmed tenant ID, or `None` when unset/blank.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

/// A WATI message mapped to the host inbound-message fields (the `channel` is
/// always `"wati"`, stamped by the host shim). WATI conversations are addressed
/// by the peer's MSISDN, so `sender` and `reply_target` are both the E.164
/// phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    /// Unix timestamp in **milliseconds** (the WIT contract). WATI reports
    /// seconds (or ISO); [`parse_webhook_payload`] normalizes to ms, or `0` when
    /// absent/unparseable.
    pub timestamp: u64,
}

/// The send endpoint: `POST <api_base>/api/ext/v3/conversations/messages/text`.
pub fn send_url(api_base: &str) -> String {
    format!(
        "{}/api/ext/v3/conversations/messages/text",
        api_base.trim_end_matches('/')
    )
}

/// Build the `target` field for the WATI API, prefixing with `tenant_id` when
/// set. Strips a leading `+` (WATI wants bare digits) and does not double an
/// already-present tenant prefix. Mirrors the native `build_target`.
pub fn build_target(tenant_id: Option<&str>, phone: &str) -> String {
    let bare = phone.trim().strip_prefix('+').unwrap_or(phone.trim());
    match tenant_id {
        Some(tid) if !tid.is_empty() => {
            if bare.starts_with(&format!("{tid}:")) {
                bare.to_string()
            } else {
                format!("{tid}:{bare}")
            }
        }
        _ => bare.to_string(),
    }
}

/// The send body: `{ "target": <target>, "text": <text> }`.
pub fn build_send_body(target: &str, text: &str) -> Value {
    json!({ "target": target, "text": text })
}

/// Decode a WATI webhook body into inbound text messages. WATI's field names
/// vary by API version, so multiple paths are tried for each field — mirroring
/// the native `parse_webhook_payload`. Outgoing (`fromMe`/`owner`) and
/// non-text/empty messages yield nothing. No allowlist is applied here (the host
/// gates senders via `peer_groups`).
pub fn parse_webhook_payload(payload: &Value) -> Vec<Inbound> {
    let mut out = Vec::new();

    // Text — top-level `text`, or nested `message.text` / `message.body`.
    let text = payload
        .get("text")
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("message")
                .and_then(|m| m.get("text").or_else(|| m.get("body")))
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .trim();
    if text.is_empty() {
        return out;
    }

    // Skip outgoing messages (`fromMe` / `from_me` / `owner`).
    let from_me = payload
        .get("fromMe")
        .or_else(|| payload.get("from_me"))
        .or_else(|| payload.get("owner"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if from_me {
        return out;
    }

    // Sender phone (`waId` / `wa_id` / `from`), normalized to E.164.
    let wa_id = payload
        .get("waId")
        .or_else(|| payload.get("wa_id"))
        .or_else(|| payload.get("from"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if wa_id.is_empty() {
        return out;
    }
    let phone = if wa_id.starts_with('+') {
        wa_id.to_string()
    } else {
        format!("+{wa_id}")
    };

    let timestamp = extract_timestamp_ms(payload);
    out.push(Inbound {
        id: format!("wati_{phone}_{timestamp}"),
        reply_target: phone.clone(),
        sender: phone,
        content: text.to_string(),
        timestamp,
    });
    out
}

/// Extract a timestamp and normalize to **milliseconds**. Handles unix seconds
/// and unix milliseconds (numeric or numeric-string). ISO 8601 strings and
/// absent values yield `0` (this pure core carries no date parser; the native
/// falls back to wall-clock, which the plugin does not have here).
fn extract_timestamp_ms(payload: &Value) -> u64 {
    let raw = payload.get("timestamp").or_else(|| payload.get("created"));
    let Some(raw) = raw else { return 0 };
    let secs_or_ms = raw
        .as_u64()
        .or_else(|| raw.as_str().and_then(|s| s.trim().parse::<u64>().ok()));
    match secs_or_ms {
        // Already milliseconds (heuristic threshold matches the native impl).
        Some(v) if v > 10_000_000_000 => v,
        // Seconds → milliseconds.
        Some(v) => v.saturating_mul(1000),
        None => 0,
    }
}

/// Extract the `hub.challenge` from a raw GET query string, percent-decoded.
/// WATI's verification handshake echoes this value with no token check (matching
/// the native gateway). Returns `Err` when absent so the component emits a
/// bad-request rejection.
pub fn extract_challenge(raw_query: &str) -> Result<String, String> {
    match parse_query(raw_query).get("hub.challenge") {
        Some(ch) if !ch.is_empty() => Ok(ch.clone()),
        _ => Err("wati: webhook verification missing hub.challenge".to_string()),
    }
}

/// Parse a raw `key=value&key=value` query string into a map, percent-decoding
/// both keys and values (`%XX` and `+` → space). Later duplicate keys win.
pub fn parse_query(raw: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

/// Percent-decode a query component: `%XX` → byte, `+` → space, everything else
/// verbatim. Malformed `%` escapes are passed through literally.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_and_defaults() {
        let cfg = WatiConfig::from_json(
            r#"{"enabled":true,"api_token":" tok ","api_url":"https://x.wati.io/","tenant_id":"t1"}"#,
        );
        assert!(cfg.enabled);
        assert_eq!(cfg.api_token(), "tok"); // trimmed
        assert_eq!(cfg.api_url(), "https://x.wati.io"); // trailing slash trimmed
        assert_eq!(cfg.tenant_id(), Some("t1"));
    }

    #[test]
    fn config_defaults_when_empty_or_malformed() {
        for s in ["{}", "", "not json", "[]"] {
            let cfg = WatiConfig::from_json(s);
            assert!(!cfg.enabled);
            assert_eq!(cfg.api_token(), "");
            assert_eq!(cfg.api_url(), DEFAULT_API_URL);
            assert_eq!(cfg.tenant_id(), None);
        }
    }

    #[test]
    fn config_ignores_unknown_native_fields() {
        let cfg = WatiConfig::from_json(
            r#"{"api_token":"t","proxy_url":"socks5://x","excluded_tools":["a"]}"#,
        );
        assert_eq!(cfg.api_token(), "t");
    }

    #[test]
    fn build_target_with_and_without_tenant() {
        assert_eq!(build_target(None, "+1234567890"), "1234567890");
        assert_eq!(build_target(Some("t1"), "+1234567890"), "t1:1234567890");
        // Already-prefixed is not doubled.
        assert_eq!(build_target(Some("t1"), "t1:1234567890"), "t1:1234567890");
    }

    #[test]
    fn send_url_and_body_shape() {
        assert_eq!(
            send_url("https://live-mt-server.wati.io"),
            "https://live-mt-server.wati.io/api/ext/v3/conversations/messages/text"
        );
        assert_eq!(
            build_send_body("1234567890", "hi"),
            json!({"target":"1234567890","text":"hi"})
        );
    }

    #[test]
    fn parse_valid_message_normalizes_phone_and_ms() {
        let payload = json!({
            "text": "Hello from WATI!",
            "waId": "1234567890",
            "fromMe": false,
            "timestamp": 1_705_320_000_u64
        });
        let msgs = parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "+1234567890");
        assert_eq!(msgs[0].reply_target, "+1234567890");
        assert_eq!(msgs[0].content, "Hello from WATI!");
        // seconds → milliseconds
        assert_eq!(msgs[0].timestamp, 1_705_320_000_000);
        assert_eq!(msgs[0].id, "wati_+1234567890_1705320000000");
    }

    #[test]
    fn parse_alternative_field_names() {
        // wa_id + message.body + from_me
        let payload = json!({
            "message": { "body": "Alt field test" },
            "wa_id": "1234567890",
            "from_me": false
        });
        let msgs = parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "Alt field test");
        assert_eq!(msgs[0].sender, "+1234567890");
        assert_eq!(msgs[0].timestamp, 0); // absent → 0
    }

    #[test]
    fn parse_from_fallback_and_message_text() {
        let payload = json!({
            "message": { "text": "Nested" },
            "from": "1234567890"
        });
        let msgs = parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "Nested");
        assert_eq!(msgs[0].sender, "+1234567890");
    }

    #[test]
    fn parse_skips_from_me_owner_empty_and_no_sender() {
        // fromMe
        assert!(parse_webhook_payload(&json!({"text":"x","waId":"1","fromMe":true})).is_empty());
        // owner=true
        assert!(parse_webhook_payload(&json!({"text":"x","waId":"1","owner":true})).is_empty());
        // no text
        assert!(parse_webhook_payload(&json!({"waId":"1"})).is_empty());
        // whitespace-only text
        assert!(parse_webhook_payload(&json!({"text":"   ","waId":"1"})).is_empty());
        // no sender
        assert!(parse_webhook_payload(&json!({"text":"x"})).is_empty());
        // empty object
        assert!(parse_webhook_payload(&json!({})).is_empty());
    }

    #[test]
    fn timestamp_milliseconds_kept() {
        let payload = json!({"text":"x","waId":"1","timestamp":1_705_320_000_000_u64});
        assert_eq!(
            parse_webhook_payload(&payload)[0].timestamp,
            1_705_320_000_000
        );
        // numeric string seconds
        let s = json!({"text":"x","waId":"1","timestamp":"1705320000"});
        assert_eq!(parse_webhook_payload(&s)[0].timestamp, 1_705_320_000_000);
        // ISO string → 0 (no date parser in pure core)
        let iso = json!({"text":"x","waId":"1","timestamp":"2025-01-15T12:00:00Z"});
        assert_eq!(parse_webhook_payload(&iso)[0].timestamp, 0);
    }

    #[test]
    fn challenge_extracted_and_percent_decoded() {
        assert_eq!(extract_challenge("hub.challenge=ABC123").unwrap(), "ABC123");
        assert_eq!(
            extract_challenge("foo=1&hub.challenge=1%2B2").unwrap(),
            "1+2"
        );
        assert!(extract_challenge("foo=bar").is_err());
        assert!(extract_challenge("hub.challenge=").is_err());
        assert!(extract_challenge("").is_err());
    }

    #[test]
    fn parse_query_edges() {
        let m = parse_query("a=1&b=&c&d=x%20y");
        assert_eq!(m.get("a").unwrap(), "1");
        assert_eq!(m.get("b").unwrap(), "");
        assert_eq!(m.get("c").unwrap(), "");
        assert_eq!(m.get("d").unwrap(), "x y");
        assert!(parse_query("").is_empty());
    }
}
