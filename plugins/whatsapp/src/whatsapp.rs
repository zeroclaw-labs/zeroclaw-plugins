//! Pure WhatsApp Cloud (Meta Graph) webhook logic — no wasm, no HTTP, no host
//! deps.
//!
//! This is the `rlib` half of the plugin. It owns everything the sandboxed
//! component needs but which is I/O-free and therefore host-testable with a
//! plain `cargo test`:
//!
//!   * parsing the plugin's `[channels.whatsapp.<alias>]` config section,
//!   * the Meta webhook **verification** handshake
//!     (`GET …?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…`),
//!   * the `X-Hub-Signature-256` HMAC-SHA256 authenticity check over the raw
//!     POST body,
//!   * decoding a Cloud API event payload
//!     (`entry[].changes[].value.messages[]`) into inbound messages, and
//!   * building the Graph `POST /<phone_number_id>/messages` send body + URL.
//!
//! The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O (blocking `waki` HTTP calls) and reuses this logic verbatim, so the
//! interesting behavior is covered here.
//!
//! Scope: **text messages only** (send + receive). Media, reactions, and
//! threading are intentionally deferred — non-text inbound events are skipped
//! and outbound is always a `text` message.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Value};

/// Default Meta Graph API origin (versioned). The native channel hard-codes
/// `v18.0`; this plugin defaults to the newer `v20.0` and lets an operator
/// override it via `api_base_url` (see [`WhatsAppConfig`]).
pub const DEFAULT_API_BASE_URL: &str = "https://graph.facebook.com/v20.0";

/// Reported alongside the plugin/manifest version.
pub const CHANNEL_VERSION: &str = "0.1.0";

/// The URL path segment the host mounts this channel's webhook under
/// (`/plugin/whatsapp`). Both the GET verification and the POST event webhook
/// arrive there.
pub const WEBHOOK_PATH: &str = "whatsapp";

/// Reserved `channel` value for a challenge-echo reply. An `InboundMessage`
/// whose `channel` is this and whose `content` is the body to send makes the
/// host reply `200` with that body verbatim and enqueue nothing. Used for the
/// Meta GET verification handshake.
pub const WEBHOOK_REPLY_CHANNEL: &str = "__webhook_reply__";

/// The plugin's config section. When installed as a mirror of the built-in
/// `whatsapp` channel this is the same `[channels.whatsapp.<alias>]` block the
/// native reads, so the field names match the native `WhatsAppConfig`
/// snake_case keys. serde ignores the many native fields this text-only v0.1.0
/// plugin does not use (allowlists, mention patterns, Web-mode selectors, …).
///
/// `api_base_url` is the one field the native config does *not* carry (the
/// native channel hard-codes the Graph origin). It is an optional plugin-only
/// override; a native mirror section without it simply uses
/// [`DEFAULT_API_BASE_URL`].
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WhatsAppConfig {
    /// Whether this channel is active (host-side gate; accepted so a native
    /// section deserializes, but the plugin does not act on it).
    #[serde(default)]
    pub enabled: bool,
    /// Graph API access token (Bearer) used to send messages. Cloud API mode.
    #[serde(default)]
    pub access_token: Option<String>,
    /// App secret used to verify the `X-Hub-Signature-256` header on inbound
    /// POST webhooks. When empty, signature verification is skipped (mirrors the
    /// native channel, which treats `app_secret` as optional).
    #[serde(default)]
    pub app_secret: Option<String>,
    /// Operator-chosen token echoed back to Meta during the GET verification
    /// handshake. Must be non-empty for verification to ever succeed.
    #[serde(default)]
    pub verify_token: Option<String>,
    /// Meta phone-number ID the send endpoint is scoped to
    /// (`POST /<phone_number_id>/messages`).
    #[serde(default)]
    pub phone_number_id: Option<String>,
    /// Override the Graph API origin. Defaults to [`DEFAULT_API_BASE_URL`].
    #[serde(default)]
    pub api_base_url: Option<String>,
}

impl WhatsAppConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// The trimmed Graph access token (may be empty).
    pub fn access_token(&self) -> &str {
        self.access_token.as_deref().unwrap_or("").trim()
    }

    /// The trimmed app secret (may be empty → signature check skipped).
    pub fn app_secret(&self) -> &str {
        self.app_secret.as_deref().unwrap_or("").trim()
    }

    /// The trimmed verify token (may be empty → GET verification never passes).
    pub fn verify_token(&self) -> &str {
        self.verify_token.as_deref().unwrap_or("").trim()
    }

    /// The trimmed phone-number ID (may be empty).
    pub fn phone_number_id(&self) -> &str {
        self.phone_number_id.as_deref().unwrap_or("").trim()
    }

    /// The Graph API origin with any trailing slash trimmed, falling back to
    /// [`DEFAULT_API_BASE_URL`] when unset or blank.
    pub fn api_base(&self) -> String {
        resolve_base(self.api_base_url.as_deref(), DEFAULT_API_BASE_URL)
    }

    /// Whether the plugin has enough to send: an access token and a phone-number
    /// ID. The shim gates `send`/`health-check` on this.
    pub fn can_send(&self) -> bool {
        !self.access_token().is_empty() && !self.phone_number_id().is_empty()
    }
}

fn resolve_base(value: Option<&str>, default: &str) -> String {
    let v = value.unwrap_or("").trim().trim_end_matches('/');
    if v.is_empty() {
        default.to_string()
    } else {
        v.to_string()
    }
}

/// A WhatsApp message mapped to the host inbound-message fields (the `channel`
/// is always `"whatsapp"`, stamped by the host shim). WhatsApp Cloud
/// conversations are addressed by the peer's MSISDN, so `sender` and
/// `reply_target` are both the message's `from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub channel_alias: Option<String>,
    /// Unix timestamp in **milliseconds** (the WIT contract). WhatsApp reports
    /// seconds; [`decode_message`] multiplies by 1000.
    pub timestamp: u64,
    pub thread_ts: Option<String>,
}

// ── Signature verification ────────────────────────────────────────────────

/// Verify a Meta `X-Hub-Signature-256` header against the raw request body.
///
/// The header is `"sha256=" + hex(HMAC-SHA256(app_secret, body))`. Returns
/// `true` only when the header is well-formed and the MAC matches (constant-time
/// via `verify_slice`). Mirrors the native gateway's `verify_whatsapp_signature`.
pub fn verify_signature(app_secret: &str, body: &[u8], signature_header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let Some(hex_sig) = signature_header.trim().strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig.trim()) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Constant-time byte comparison for the verify-token check. Length is allowed
/// to leak (as in the native `constant_time_eq`); the token bytes are not.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── GET verification handshake ────────────────────────────────────────────

/// Handle a Meta webhook verification `GET`. On success returns the
/// `hub.challenge` string the host must echo back in the response body; on any
/// mismatch returns `Err(reason)` so the component emits an unauthorized
/// rejection and enqueues nothing.
///
/// Requires `hub.mode == "subscribe"`, a non-empty configured `verify_token`
/// that matches `hub.verify_token` (constant-time), and a present
/// `hub.challenge`.
pub fn verify_get_request(cfg: &WhatsAppConfig, raw_query: &str) -> Result<(), String> {
    let params = parse_query(raw_query);
    let mode = params.get("hub.mode").map(String::as_str).unwrap_or("");
    if mode != "subscribe" {
        return Err(format!(
            "whatsapp: webhook verification failed (unexpected hub.mode {mode:?})"
        ));
    }
    let want = cfg.verify_token();
    let got = params
        .get("hub.verify_token")
        .map(String::as_str)
        .unwrap_or("");
    if want.is_empty() || !constant_time_eq(got, want) {
        return Err(
            "whatsapp: webhook verification failed (hub.verify_token mismatch)".to_string(),
        );
    }
    Ok(())
}

/// Extract the non-empty challenge from an authenticated Meta verification
/// request. Keeping this separate lets the component distinguish a malformed
/// query (HTTP 400) from failed token verification (HTTP 401).
pub fn get_verification_challenge(raw_query: &str) -> Result<String, String> {
    let params = parse_query(raw_query);
    match params.get("hub.challenge") {
        Some(ch) if !ch.is_empty() => Ok(ch.clone()),
        _ => Err("whatsapp: webhook verification missing hub.challenge".to_string()),
    }
}

pub fn handle_get_verification(cfg: &WhatsAppConfig, raw_query: &str) -> Result<String, String> {
    verify_get_request(cfg, raw_query)?;
    get_verification_challenge(raw_query)
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

// ── Inbound decode ────────────────────────────────────────────────────────

/// Decode a Cloud API webhook payload into inbound messages, walking
/// `entry[].changes[].value.messages[]`. Non-text messages and status updates
/// are skipped. `channel_alias` is stamped on each result (the host shim knows
/// the bound alias; the pure core takes it as a parameter for testability).
pub fn decode_inbound(payload: &Value, channel_alias: Option<&str>) -> Vec<Inbound> {
    let mut out = Vec::new();
    let Some(entries) = payload.get("entry").and_then(Value::as_array) else {
        return out;
    };
    for entry in entries {
        let Some(changes) = entry.get("changes").and_then(Value::as_array) else {
            continue;
        };
        for change in changes {
            let Some(value) = change.get("value") else {
                continue;
            };
            let Some(msgs) = value.get("messages").and_then(Value::as_array) else {
                continue;
            };
            for msg in msgs {
                if let Some(inb) = decode_message(msg, channel_alias) {
                    out.push(inb);
                }
            }
        }
    }
    out
}

/// Map one Cloud API `messages[]` entry to an [`Inbound`]. Returns `None` unless
/// it is a text message with a non-empty `from` and `text.body` (this text-only
/// plugin skips media/reactions/etc.).
pub fn decode_message(msg: &Value, channel_alias: Option<&str>) -> Option<Inbound> {
    let from = msg
        .get("from")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?;

    // Text-only: a non-`text` type has no `text.body`, so this also drops it.
    let msg_type = msg.get("type").and_then(Value::as_str).unwrap_or("text");
    if msg_type != "text" {
        return None;
    }
    let content = msg
        .get("text")
        .and_then(|t| t.get("body"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if content.is_empty() {
        return None;
    }

    // WhatsApp timestamps are unix **seconds** as a string; the WIT contract is
    // milliseconds.
    let ts_secs = msg
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(0);
    let timestamp = ts_secs.saturating_mul(1000);

    let id = msg
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("whatsapp_{from}_{ts_secs}"));

    Some(Inbound {
        id,
        sender: from.to_string(),
        reply_target: from.to_string(),
        content: content.to_string(),
        channel_alias: channel_alias.map(str::to_string),
        timestamp,
        thread_ts: None,
    })
}

// ── Outbound send ─────────────────────────────────────────────────────────

/// Build the Graph `POST /<phone_number_id>/messages` JSON body for a single
/// text message. A leading `+` on the recipient MSISDN is stripped (the API
/// wants a bare number), mirroring the native channel.
pub fn build_send_body(to: &str, text: &str) -> Value {
    let to = to.trim();
    let to = to.strip_prefix('+').unwrap_or(to);
    json!({
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to,
        "type": "text",
        "text": { "preview_url": false, "body": text },
    })
}

/// The Graph send endpoint URL: `<api_base>/<phone_number_id>/messages`.
pub fn send_url(api_base: &str, phone_number_id: &str) -> String {
    format!(
        "{}/{}/messages",
        api_base.trim_end_matches('/'),
        phone_number_id
    )
}

/// The Graph health-probe URL: `<api_base>/<phone_number_id>` (a cheap
/// authenticated GET the native channel uses as a reachability check).
pub fn health_url(api_base: &str, phone_number_id: &str) -> String {
    format!("{}/{}", api_base.trim_end_matches('/'), phone_number_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use serde_json::json;
    use sha2::Sha256;

    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    fn text_event(from: &str, body: &str, id: &str, ts: &str) -> Value {
        json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "WABA_ID",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": { "phone_number_id": "PNID" },
                        "messages": [{
                            "from": from,
                            "id": id,
                            "timestamp": ts,
                            "type": "text",
                            "text": { "body": body }
                        }]
                    }
                }]
            }]
        })
    }

    #[test]
    fn config_parses_and_defaults() {
        let cfg = WhatsAppConfig::from_json(
            r#"{
                "enabled": true,
                "access_token": " tok-123 ",
                "app_secret": "sekret",
                "verify_token": "vt",
                "phone_number_id": "PNID",
                "api_base_url": "https://graph.example.com/v21.0/"
            }"#,
        );
        assert!(cfg.enabled);
        assert_eq!(cfg.access_token(), "tok-123"); // trimmed
        assert_eq!(cfg.app_secret(), "sekret");
        assert_eq!(cfg.verify_token(), "vt");
        assert_eq!(cfg.phone_number_id(), "PNID");
        // Trailing slash trimmed on override.
        assert_eq!(cfg.api_base(), "https://graph.example.com/v21.0");
        assert!(cfg.can_send());
    }

    #[test]
    fn config_defaults_when_empty_or_malformed() {
        for s in ["{}", "", "not json", "[]"] {
            let cfg = WhatsAppConfig::from_json(s);
            assert!(!cfg.enabled);
            assert_eq!(cfg.access_token(), "");
            assert_eq!(cfg.verify_token(), "");
            assert_eq!(cfg.api_base(), DEFAULT_API_BASE_URL);
            assert!(!cfg.can_send());
        }
    }

    #[test]
    fn config_ignores_unknown_native_fields() {
        // A verbatim native [channels.whatsapp.<alias>] section carries many
        // fields this plugin does not model; serde must ignore them.
        let cfg = WhatsAppConfig::from_json(
            r#"{
                "access_token": "t",
                "phone_number_id": "p",
                "verify_token": "v",
                "allowed_numbers": ["+123"],
                "dm_mention_patterns": ["@bot"],
                "mode": "personal",
                "session_path": "/x",
                "mention_only": true
            }"#,
        );
        assert_eq!(cfg.access_token(), "t");
        assert_eq!(cfg.phone_number_id(), "p");
        assert!(cfg.can_send());
    }

    #[test]
    fn signature_valid_and_invalid() {
        let secret = "app-secret";
        let body = br#"{"object":"whatsapp_business_account","entry":[]}"#;
        let good = sign(secret, body);

        assert!(verify_signature(secret, body, &good));
        // Wrong secret.
        assert!(!verify_signature("other", body, &good));
        // Tampered body.
        assert!(!verify_signature(secret, b"{}", &good));
        // Missing prefix.
        let bare = good.strip_prefix("sha256=").unwrap();
        assert!(!verify_signature(secret, body, bare));
        // Non-hex payload.
        assert!(!verify_signature(secret, body, "sha256=zzzz"));
        // Empty header.
        assert!(!verify_signature(secret, body, ""));
    }

    #[test]
    fn get_verification_echoes_challenge() {
        let cfg = WhatsAppConfig::from_json(r#"{"verify_token":"my-token"}"#);
        let q = "hub.mode=subscribe&hub.verify_token=my-token&hub.challenge=CHALLENGE_1234";
        assert_eq!(handle_get_verification(&cfg, q).unwrap(), "CHALLENGE_1234");
    }

    #[test]
    fn get_verification_percent_decodes_values() {
        let cfg = WhatsAppConfig::from_json(r#"{"verify_token":"a b+c"}"#);
        // token "a b+c" arrives as "a%20b%2Bc"; challenge is URL-encoded too.
        let q = "hub.mode=subscribe&hub.verify_token=a%20b%2Bc&hub.challenge=1%2B2%3D3";
        assert_eq!(handle_get_verification(&cfg, q).unwrap(), "1+2=3");
    }

    #[test]
    fn get_verification_rejects_bad_token_mode_and_missing() {
        let cfg = WhatsAppConfig::from_json(r#"{"verify_token":"good"}"#);
        // Wrong token.
        assert!(handle_get_verification(
            &cfg,
            "hub.mode=subscribe&hub.verify_token=bad&hub.challenge=X"
        )
        .is_err());
        // Wrong mode.
        assert!(handle_get_verification(
            &cfg,
            "hub.mode=unsubscribe&hub.verify_token=good&hub.challenge=X"
        )
        .is_err());
        // Missing challenge.
        assert!(handle_get_verification(&cfg, "hub.mode=subscribe&hub.verify_token=good").is_err());
        // Empty configured verify_token never passes, even on empty incoming.
        let no_token = WhatsAppConfig::from_json("{}");
        assert!(handle_get_verification(
            &no_token,
            "hub.mode=subscribe&hub.verify_token=&hub.challenge=X"
        )
        .is_err());
    }

    #[test]
    fn decode_inbound_text_message() {
        let payload = text_event("15551230000", "hello world", "wamid.ABC", "1700000000");
        let msgs = decode_inbound(&payload, Some("main"));
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(m.id, "wamid.ABC");
        assert_eq!(m.sender, "15551230000");
        assert_eq!(m.reply_target, "15551230000");
        assert_eq!(m.content, "hello world");
        assert_eq!(m.channel_alias.as_deref(), Some("main"));
        // seconds → milliseconds
        assert_eq!(m.timestamp, 1_700_000_000_000);
        assert_eq!(m.thread_ts, None);
    }

    #[test]
    fn decode_inbound_skips_non_text_and_statuses() {
        // Image message.
        let image = json!({
            "entry": [{ "changes": [{ "value": { "messages": [{
                "from": "15551230000", "id": "wamid.IMG", "timestamp": "1700000000",
                "type": "image", "image": { "id": "media-1" }
            }] } }] }]
        });
        assert!(decode_inbound(&image, None).is_empty());

        // A status-only change (no `messages` array) — must not panic or emit.
        let status = json!({
            "entry": [{ "changes": [{ "value": {
                "statuses": [{ "id": "wamid.S", "status": "delivered" }]
            } }] }]
        });
        assert!(decode_inbound(&status, None).is_empty());

        // Empty text body is dropped.
        let empty = text_event("15551230000", "", "wamid.E", "1700000000");
        assert!(decode_inbound(&empty, None).is_empty());
    }

    #[test]
    fn decode_inbound_multiple_messages_across_entries() {
        let payload = json!({
            "entry": [
                { "changes": [{ "value": { "messages": [
                    { "from": "111", "id": "a", "timestamp": "1", "type": "text", "text": {"body": "one"} },
                    { "from": "222", "id": "b", "timestamp": "2", "type": "text", "text": {"body": "two"} }
                ] } }] },
                { "changes": [{ "value": { "messages": [
                    { "from": "333", "id": "c", "timestamp": "3", "type": "text", "text": {"body": "three"} }
                ] } }] }
            ]
        });
        let msgs = decode_inbound(&payload, None);
        let contents: Vec<_> = msgs.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(contents, ["one", "two", "three"]);
    }

    #[test]
    fn decode_message_falls_back_to_synthetic_id() {
        let msg = json!({
            "from": "15551230000", "timestamp": "1700000000",
            "type": "text", "text": { "body": "hi" }
        });
        let inb = decode_message(&msg, None).unwrap();
        assert_eq!(inb.id, "whatsapp_15551230000_1700000000");
    }

    #[test]
    fn empty_payload_is_empty() {
        assert!(decode_inbound(&json!({}), None).is_empty());
        assert!(decode_inbound(&json!({"entry": []}), None).is_empty());
        assert!(decode_inbound(&json!({"entry": [{}]}), None).is_empty());
    }

    #[test]
    fn send_body_strips_plus_and_shapes_json() {
        let body = build_send_body("+15551230000", "reply text");
        assert_eq!(body["messaging_product"], "whatsapp");
        assert_eq!(body["recipient_type"], "individual");
        assert_eq!(body["to"], "15551230000");
        assert_eq!(body["type"], "text");
        assert_eq!(body["text"]["body"], "reply text");
        assert_eq!(body["text"]["preview_url"], false);

        // No leading plus is left as-is.
        let body2 = build_send_body("15551230000", "x");
        assert_eq!(body2["to"], "15551230000");
    }

    #[test]
    fn urls_are_versioned_and_scoped() {
        let cfg = WhatsAppConfig::from_json(r#"{"phone_number_id":"PNID"}"#);
        assert_eq!(
            send_url(&cfg.api_base(), cfg.phone_number_id()),
            "https://graph.facebook.com/v20.0/PNID/messages"
        );
        assert_eq!(
            health_url(&cfg.api_base(), cfg.phone_number_id()),
            "https://graph.facebook.com/v20.0/PNID"
        );
        // Override base, trailing slash trimmed.
        let cfg2 = WhatsAppConfig::from_json(
            r#"{"phone_number_id":"P","api_base_url":"https://x.test/v1/"}"#,
        );
        assert_eq!(
            send_url(&cfg2.api_base(), cfg2.phone_number_id()),
            "https://x.test/v1/P/messages"
        );
    }

    #[test]
    fn parse_query_handles_edges() {
        let m = parse_query("a=1&b=&c&d=x%20y");
        assert_eq!(m.get("a").unwrap(), "1");
        assert_eq!(m.get("b").unwrap(), "");
        assert_eq!(m.get("c").unwrap(), "");
        assert_eq!(m.get("d").unwrap(), "x y");
        assert!(parse_query("").is_empty());
    }
}
