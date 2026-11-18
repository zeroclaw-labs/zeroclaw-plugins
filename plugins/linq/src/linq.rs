//! Pure Linq (Partner V3 API: iMessage/RCS/SMS) webhook logic — no wasm, no
//! HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin. It owns everything I/O-free and
//! therefore host-testable with a plain `cargo test`:
//!
//!   * parsing the plugin's `[channels.linq.<alias>]` config section,
//!   * the `X-Webhook-Signature` HMAC-SHA256 authenticity check over
//!     `"{timestamp}.{body}"` (with a 300 s replay window), matching the native
//!     `verify_linq_signature`,
//!   * decoding both Linq webhook payload shapes (legacy `2025-01-01` and current
//!     `2026-02-03`) into inbound text messages, and
//!   * building the send / create-chat request bodies.
//!
//! The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O (blocking `waki` HTTP calls, current-time lookup for the replay window)
//! and reuses this logic verbatim.
//!
//! Scope: **text messages only** (send + receive). Inbound images are surfaced as
//! an `[IMAGE:<url>]` marker (matching the native channel); no media is
//! downloaded.

use serde::Deserialize;
use serde_json::{json, Value};

/// Linq Partner V3 API base.
pub const LINQ_API_BASE: &str = "https://api.linqapp.com/api/partner/v3";

/// The URL path segment the host mounts this channel's webhook under
/// (`/plugin/linq`).
pub const WEBHOOK_PATH: &str = "linq";

/// Reject webhook timestamps more than this many seconds from now (replay
/// window). Mirrors the native `verify_linq_signature`.
pub const MAX_SIGNATURE_AGE_SECS: i64 = 300;

/// The plugin's config section, mirroring the native `[channels.linq.<alias>]`
/// snake_case keys. serde ignores native fields this text-only v0.1.0 plugin
/// does not use (`excluded_tools`, …).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LinqConfig {
    /// Host-side enable gate; accepted so a native section deserializes.
    #[serde(default)]
    pub enabled: bool,
    /// Linq Partner API token (Bearer auth) used to send messages.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Phone number to send from (E.164), used when creating a new chat.
    #[serde(default)]
    pub from_phone: Option<String>,
    /// Webhook signing secret. When set, `X-Webhook-Signature` is verified; when
    /// empty, inbound is accepted without a signature (mirrors the native
    /// gateway, which only verifies when `signing_secret` is configured).
    #[serde(default)]
    pub signing_secret: Option<String>,
}

impl LinqConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (inert rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// The trimmed API token (may be empty).
    pub fn api_token(&self) -> &str {
        self.api_token.as_deref().unwrap_or("").trim()
    }

    /// The trimmed from-phone (may be empty).
    pub fn from_phone(&self) -> &str {
        self.from_phone.as_deref().unwrap_or("").trim()
    }

    /// The trimmed signing secret, or `None` when unset/blank (→ no signature
    /// check).
    pub fn signing_secret(&self) -> Option<&str> {
        self.signing_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

/// A Linq message mapped to the host inbound-message fields (the `channel` is
/// always `"linq"`, stamped by the host shim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    /// Unix timestamp in **milliseconds**. Linq's `created_at` is RFC 3339; this
    /// pure core carries no date parser, so it is left `0` (deferred).
    pub timestamp: u64,
}

// ── Signature verification ────────────────────────────────────────────────

/// Verify a Linq `X-Webhook-Signature` against `"{timestamp}.{body}"`.
///
/// The signature is `hex(HMAC-SHA256(secret, "{timestamp}.{body}"))` (an optional
/// `sha256=` prefix and surrounding whitespace are tolerated; hex case is
/// ignored). `timestamp` must parse as an integer within
/// [`MAX_SIGNATURE_AGE_SECS`] of `now_secs` (the replay window). Returns `true`
/// only on a constant-time MAC match within the window. Mirrors the native
/// `verify_linq_signature`; `now_secs` is a parameter for host-testability (the
/// shim passes the wall clock).
pub fn verify_signature(
    secret: &str,
    body: &[u8],
    timestamp: &str,
    signature: &str,
    now_secs: i64,
) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Reject a non-integer or stale timestamp.
    let Ok(ts) = timestamp.trim().parse::<i64>() else {
        return false;
    };
    if (now_secs - ts).unsigned_abs() > MAX_SIGNATURE_AGE_SECS as u64 {
        return false;
    }

    let mut message = Vec::with_capacity(timestamp.trim().len() + 1 + body.len());
    message.extend_from_slice(timestamp.trim().as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);

    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(&message);

    let hex_sig = signature
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(signature);
    let Ok(provided) = hex::decode(hex_sig.trim()) else {
        return false;
    };
    mac.verify_slice(&provided).is_ok()
}

// ── Inbound decode ────────────────────────────────────────────────────────

fn sender_is_from_me(data: &Value) -> bool {
    // Legacy: data.is_from_me
    if let Some(v) = data.get("is_from_me").and_then(Value::as_bool) {
        return v;
    }
    // New: data.sender_handle.is_me OR data.direction == "outbound"
    let is_me = data
        .get("sender_handle")
        .and_then(|v| v.get("is_me"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_outbound = matches!(
        data.get("direction").and_then(Value::as_str),
        Some("outbound")
    );
    is_me || is_outbound
}

fn sender_handle(data: &Value) -> Option<&str> {
    data.get("from").and_then(Value::as_str).or_else(|| {
        data.get("sender_handle")
            .and_then(|v| v.get("handle"))
            .and_then(Value::as_str)
    })
}

fn chat_id(data: &Value) -> Option<&str> {
    data.get("chat_id").and_then(Value::as_str).or_else(|| {
        data.get("chat")
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
    })
}

fn message_parts(data: &Value) -> Option<&Vec<Value>> {
    data.get("message")
        .and_then(|v| v.get("parts"))
        .and_then(Value::as_array)
        .or_else(|| data.get("parts").and_then(Value::as_array))
}

/// An image `media`/`image` part → `[IMAGE:<url>]` marker; `None` for non-image
/// media. Mirrors the native `media_part_to_image_marker`.
fn media_part_to_image_marker(part: &Value) -> Option<String> {
    let source = part
        .get("url")
        .or_else(|| part.get("value"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())?;
    let mime = part
        .get("mime_type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !mime.starts_with("image/") {
        return None;
    }
    Some(format!("[IMAGE:{source}]"))
}

/// Decode a Linq webhook payload into inbound text messages. Only
/// `message.received` events are considered; outgoing (`is_from_me` / `is_me` /
/// `direction == "outbound"`) messages are skipped. Both the legacy `chat_id` /
/// `from` / `message.parts` shape and the current `chat.id` / `sender_handle` /
/// `parts` shape are accepted. No allowlist is applied here (the host gates
/// senders via `peer_groups`).
pub fn parse_webhook_payload(payload: &Value) -> Vec<Inbound> {
    let mut out = Vec::new();

    if payload.get("event_type").and_then(Value::as_str) != Some("message.received") {
        return out;
    }
    let Some(data) = payload.get("data") else {
        return out;
    };
    if sender_is_from_me(data) {
        return out;
    }
    let Some(from) = sender_handle(data) else {
        return out;
    };
    let normalized_from = if from.starts_with('+') {
        from.to_string()
    } else {
        format!("+{from}")
    };

    let chat = chat_id(data).unwrap_or("").to_string();

    let Some(parts) = message_parts(data) else {
        return out;
    };
    let content_parts: Vec<String> = parts
        .iter()
        .filter_map(|part| match part.get("type").and_then(Value::as_str)? {
            "text" => part
                .get("value")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            "media" | "image" => media_part_to_image_marker(part),
            _ => None,
        })
        .collect();
    if content_parts.is_empty() {
        return out;
    }
    let content = content_parts.join("\n").trim().to_string();
    if content.is_empty() {
        return out;
    }

    let reply_target = if chat.is_empty() {
        normalized_from.clone()
    } else {
        chat
    };

    out.push(Inbound {
        id: format!("linq_{normalized_from}_{reply_target}"),
        reply_target,
        sender: normalized_from,
        content,
        timestamp: 0,
    });
    out
}

// ── Outbound send ─────────────────────────────────────────────────────────

/// The send-to-existing-chat endpoint: `POST <base>/chats/<recipient>/messages`.
pub fn send_message_url(recipient: &str) -> String {
    format!("{LINQ_API_BASE}/chats/{recipient}/messages")
}

/// The create-chat endpoint: `POST <base>/chats`.
pub fn create_chat_url() -> String {
    format!("{LINQ_API_BASE}/chats")
}

/// Body for sending a text into an existing chat.
pub fn build_send_body(text: &str) -> Value {
    json!({ "message": { "parts": [{ "type": "text", "value": text }] } })
}

/// Body for creating a new chat with `recipient` from `from_phone`.
pub fn build_create_chat_body(from_phone: &str, recipient: &str, text: &str) -> Value {
    json!({
        "from": from_phone,
        "to": [recipient],
        "message": { "parts": [{ "type": "text", "value": text }] }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn sign(secret: &str, ts: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        let mut msg = ts.as_bytes().to_vec();
        msg.push(b'.');
        msg.extend_from_slice(body);
        mac.update(&msg);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn config_parses_and_defaults() {
        let cfg = LinqConfig::from_json(
            r#"{"enabled":true,"api_token":" tok ","from_phone":"+15551234567","signing_secret":" s "}"#,
        );
        assert!(cfg.enabled);
        assert_eq!(cfg.api_token(), "tok");
        assert_eq!(cfg.from_phone(), "+15551234567");
        assert_eq!(cfg.signing_secret(), Some("s"));

        let empty = LinqConfig::from_json("{}");
        assert_eq!(empty.api_token(), "");
        assert_eq!(empty.signing_secret(), None);
        // blank secret → None
        assert_eq!(
            LinqConfig::from_json(r#"{"signing_secret":"  "}"#).signing_secret(),
            None
        );
    }

    #[test]
    fn config_defaults_when_malformed_and_ignores_unknown() {
        for s in ["", "not json", "[]"] {
            assert_eq!(LinqConfig::from_json(s).api_token(), "");
        }
        let cfg = LinqConfig::from_json(r#"{"api_token":"t","excluded_tools":["x"]}"#);
        assert_eq!(cfg.api_token(), "t");
    }

    #[test]
    fn signature_valid_within_window() {
        let secret = "webhook_secret";
        let body = br#"{"event_type":"message.received"}"#;
        let now = 1_700_000_000_i64;
        let ts = now.to_string();
        let good = sign(secret, &ts, body);
        assert!(verify_signature(secret, body, &ts, &good, now));
        // sha256= prefix + uppercase hex tolerated
        let prefixed = format!("sha256={}", good.to_ascii_uppercase());
        assert!(verify_signature(secret, body, &ts, &prefixed, now));
    }

    #[test]
    fn signature_rejects_bad_secret_body_stale_and_garbage() {
        let secret = "webhook_secret";
        let body = br#"{"event_type":"message.received"}"#;
        let now = 1_700_000_000_i64;
        let ts = now.to_string();
        let good = sign(secret, &ts, body);

        // wrong secret
        assert!(!verify_signature("other", body, &ts, &good, now));
        // tampered body
        assert!(!verify_signature(secret, b"{}", &ts, &good, now));
        // stale timestamp (>300s), even with a correct signature for that ts
        let stale = (now - 600).to_string();
        let stale_sig = sign(secret, &stale, body);
        assert!(!verify_signature(secret, body, &stale, &stale_sig, now));
        // non-integer timestamp
        assert!(!verify_signature(secret, body, "not-a-ts", &good, now));
        // non-hex signature
        assert!(!verify_signature(secret, body, &ts, "zz", now));
        // future timestamp within window is OK; outside is not
        let future_ok = (now + 200).to_string();
        assert!(verify_signature(
            secret,
            body,
            &future_ok,
            &sign(secret, &future_ok, body),
            now
        ));
        let future_bad = (now + 600).to_string();
        assert!(!verify_signature(
            secret,
            body,
            &future_bad,
            &sign(secret, &future_bad, body),
            now
        ));
    }

    #[test]
    fn parse_legacy_text_message() {
        let payload = json!({
            "event_type": "message.received",
            "data": {
                "chat_id": "chat-789",
                "from": "+1234567890",
                "is_from_me": false,
                "message": { "id": "m", "parts": [{ "type": "text", "value": "Hello ZeroClaw!" }] }
            }
        });
        let msgs = parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "+1234567890");
        assert_eq!(msgs[0].content, "Hello ZeroClaw!");
        assert_eq!(msgs[0].reply_target, "chat-789");
    }

    #[test]
    fn parse_new_format_text_message_normalizes_phone() {
        let payload = json!({
            "event_type": "message.received",
            "webhook_version": "2026-02-03",
            "data": {
                "id": "m",
                "direction": "inbound",
                "sender_handle": { "handle": "1234567890", "is_me": false },
                "chat": { "id": "chat-2026" },
                "parts": [{ "type": "text", "value": "hi" }]
            }
        });
        let msgs = parse_webhook_payload(&payload);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "+1234567890"); // + prepended
        assert_eq!(msgs[0].reply_target, "chat-2026");
        assert_eq!(msgs[0].content, "hi");
    }

    #[test]
    fn parse_skips_outgoing_and_non_message_events() {
        // legacy is_from_me
        assert!(parse_webhook_payload(&json!({
            "event_type":"message.received",
            "data":{"from":"+1","is_from_me":true,"message":{"parts":[{"type":"text","value":"x"}]}}
        }))
        .is_empty());
        // new is_me
        assert!(parse_webhook_payload(&json!({
            "event_type":"message.received",
            "data":{"sender_handle":{"handle":"+1","is_me":true},"parts":[{"type":"text","value":"x"}]}
        }))
        .is_empty());
        // direction outbound
        assert!(parse_webhook_payload(&json!({
            "event_type":"message.received",
            "data":{"sender_handle":{"handle":"+1","is_me":false},"direction":"outbound","parts":[{"type":"text","value":"x"}]}
        }))
        .is_empty());
        // wrong event type
        assert!(
            parse_webhook_payload(&json!({"event_type":"message.delivered","data":{}})).is_empty()
        );
        // empty
        assert!(parse_webhook_payload(&json!({})).is_empty());
    }

    #[test]
    fn parse_media_image_marker_and_multiple_parts() {
        let img = json!({
            "event_type":"message.received",
            "data":{"chat_id":"c","from":"+1","is_from_me":false,
                "message":{"parts":[{"type":"media","url":"https://x/i.jpg","mime_type":"image/jpeg"}]}}
        });
        assert_eq!(
            parse_webhook_payload(&img)[0].content,
            "[IMAGE:https://x/i.jpg]"
        );
        // non-image media skipped → no content → no message
        let audio = json!({
            "event_type":"message.received",
            "data":{"chat_id":"c","from":"+1","is_from_me":false,
                "message":{"parts":[{"type":"media","url":"https://x/a.mp3","mime_type":"audio/mpeg"}]}}
        });
        assert!(parse_webhook_payload(&audio).is_empty());
        // text + image joined with newline
        let both = json!({
            "event_type":"message.received",
            "data":{"chat":{"id":"c"},"sender_handle":{"handle":"+1","is_me":false},
                "parts":[{"type":"text","value":"see"},{"type":"media","url":"https://x/i.jpg","mime_type":"image/jpeg"}]}
        });
        assert_eq!(
            parse_webhook_payload(&both)[0].content,
            "see\n[IMAGE:https://x/i.jpg]"
        );
    }

    #[test]
    fn parse_fallback_reply_target_and_empty_text() {
        // no chat id → reply_target is the sender
        let no_chat = json!({
            "event_type":"message.received",
            "data":{"from":"+1234567890","is_from_me":false,"message":{"parts":[{"type":"text","value":"hi"}]}}
        });
        assert_eq!(
            parse_webhook_payload(&no_chat)[0].reply_target,
            "+1234567890"
        );
        // empty text value → skipped
        let empty = json!({
            "event_type":"message.received",
            "data":{"chat_id":"c","from":"+1","is_from_me":false,"message":{"parts":[{"type":"text","value":""}]}}
        });
        assert!(parse_webhook_payload(&empty).is_empty());
    }

    #[test]
    fn send_bodies_and_urls() {
        assert_eq!(
            send_message_url("chat-1"),
            "https://api.linqapp.com/api/partner/v3/chats/chat-1/messages"
        );
        assert_eq!(
            create_chat_url(),
            "https://api.linqapp.com/api/partner/v3/chats"
        );
        assert_eq!(
            build_send_body("hi"),
            json!({"message":{"parts":[{"type":"text","value":"hi"}]}})
        );
        assert_eq!(
            build_create_chat_body("+1555", "+1999", "yo"),
            json!({"from":"+1555","to":["+1999"],"message":{"parts":[{"type":"text","value":"yo"}]}})
        );
    }
}
