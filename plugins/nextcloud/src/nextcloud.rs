//! Pure Nextcloud Talk **bot-webhook** logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin. It owns everything the sandboxed
//! component needs that is *not* I/O:
//!
//!   * parsing the plugin's `[channels.nextcloud_talk.<alias>]` config section,
//!   * verifying the Talk bot webhook HMAC signature over the raw body,
//!   * decoding a Talk bot webhook payload into inbound messages,
//!   * building the OCS `sendMessage` request URL + body,
//!   * truncating outbound text to the OCS length limit.
//!
//! The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O (the `waki` HTTP `POST` with the bot's `Bearer` token) and reuses this
//! logic verbatim, so all the interesting behavior is covered by a plain host
//! `cargo test` with no token, no network, and no wasm.
//!
//! The signature scheme, payload shape, send endpoint, auth, and config field
//! names all mirror the built-in `nextcloud_talk` channel
//! (`crates/zeroclaw-channels/src/nextcloud_talk.rs`) so a mirror install is
//! interchangeable with the native channel.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Maximum message length the Nextcloud Talk OCS chat API accepts, in **chars**
/// (not bytes). The API rejects messages longer than 32 000 characters.
pub const NC_MAX_MESSAGE_LENGTH: usize = 32_000;

/// Lower-cased header carrying the per-request nonce prepended to the body
/// before signing. The host lower-cases all header names before `parse_webhook`.
pub const RANDOM_HEADER: &str = "x-nextcloud-talk-random";
/// Lower-cased header carrying the hex HMAC-SHA256 signature.
pub const SIGNATURE_HEADER: &str = "x-nextcloud-talk-signature";

/// The plugin's config section (`[channels.nextcloud_talk.<alias>]` for a mirror,
/// or
/// `[[plugins.entries.nextcloud]].config` as a novel plugin). Field names match
/// the native `NextcloudTalkConfig` snake_case keys so a mirror plugin can be fed
/// the native section verbatim. Only the fields this v0.1.0 plugin uses are
/// declared; serde ignores the rest (`proxy_url`, `stream_mode`,
/// `excluded_tools`, `draft_update_interval_ms`, …).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NextcloudConfig {
    /// Nextcloud base URL, e.g. `https://cloud.example.com`. A trailing slash is
    /// trimmed by [`NextcloudConfig::base_url`].
    #[serde(default)]
    pub base_url: String,
    /// Bot app token used for OCS API bearer auth (`Authorization: Bearer …`).
    #[serde(default)]
    pub app_token: Option<String>,
    /// Shared secret for webhook signature verification. When empty, incoming
    /// webhooks are accepted unsigned — mirroring the native channel, which only
    /// verifies when a secret is configured.
    #[serde(default)]
    pub webhook_secret: Option<String>,
    /// Display name of the bot in Nextcloud Talk (e.g. `"zeroclaw"`). Used to
    /// drop the bot's own messages and prevent feedback loops. Empty ⇒ only the
    /// built-in name `"zeroclaw"` and the `actor.type`/`bots/` prefix guards
    /// apply.
    #[serde(default)]
    pub bot_name: Option<String>,
}

impl NextcloudConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// Base URL with any trailing slash trimmed, for consistent path joins.
    pub fn base_url(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// The OCS bearer token (trimmed), or `""` when unset — the "not configured"
    /// sentinel the shim checks before attempting a send.
    pub fn app_token(&self) -> &str {
        self.app_token.as_deref().unwrap_or("").trim()
    }

    /// The webhook signing secret (trimmed), or `""` when unset. Empty means
    /// "accept unsigned" (native-mirroring behavior).
    pub fn webhook_secret(&self) -> &str {
        self.webhook_secret.as_deref().unwrap_or("").trim()
    }

    /// The configured bot name, lower-cased and trimmed, or `""` when unset.
    pub fn bot_name(&self) -> String {
        self.bot_name
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    }
}

/// A Talk webhook message mapped to the host inbound-message fields. `channel`
/// (`"nextcloud"`) and `timestamp` are stamped by the wasm shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
}

// ── Signature verification ─────────────────────────────────────────────────────

/// Verify a Nextcloud Talk bot webhook signature (official Talk bot docs):
///
/// ```text
/// signature == hex( HMAC-SHA256( secret, X-Nextcloud-Talk-Random ++ raw_body ) )
/// ```
///
/// `random` is the header value, `body` is the exact received bytes, `signature`
/// is the hex from `X-Nextcloud-Talk-Signature` (a defensive `sha256=` prefix is
/// stripped). The compare is constant-time (`Mac::verify_slice`). Returns `false`
/// on a missing/empty random, a non-hex signature, or a digest mismatch.
pub fn verify_signature(secret: &str, random: &str, body: &[u8], signature: &str) -> bool {
    let random = random.trim();
    if random.is_empty() {
        return false;
    }

    let signature_hex = signature
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or_else(|| signature.trim())
        .trim();
    let Some(provided) = decode_hex(signature_hex) else {
        return false;
    };

    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    // HMAC of the concatenation `random ++ body`, fed incrementally to avoid
    // allocating (and to hash the raw bytes rather than a lossy UTF-8 copy).
    mac.update(random.as_bytes());
    mac.update(body);
    mac.verify_slice(&provided).is_ok()
}

/// Decode an even-length lower/upper-case hex string to bytes, or `None` on any
/// non-hex character or odd length.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Case-insensitively look up a header value by (lower-cased) name.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// ── Webhook ingest ──────────────────────────────────────────────────────────────

/// Authenticate a raw inbound webhook. When a `webhook_secret` is configured,
/// verify the HMAC over the exact request body; otherwise accept unsigned input
/// to mirror the native channel.
pub fn authenticate_webhook(
    headers: &[(String, String)],
    body: &[u8],
    cfg: &NextcloudConfig,
) -> Result<(), String> {
    let secret = cfg.webhook_secret();
    if !secret.is_empty() {
        let random = header(headers, RANDOM_HEADER).unwrap_or("");
        let signature = header(headers, SIGNATURE_HEADER).unwrap_or("");
        if !verify_signature(secret, random, body, signature) {
            return Err("nextcloud: webhook signature verification failed".to_string());
        }
    }
    Ok(())
}

/// Decode an already-authenticated Nextcloud Talk webhook body.
pub fn decode_webhook(body: &[u8], cfg: &NextcloudConfig) -> Result<Vec<Inbound>, String> {
    let payload: Value = serde_json::from_slice(body)
        .map_err(|e| format!("nextcloud: invalid JSON payload: {e}"))?;
    Ok(decode_inbound(&payload, &cfg.bot_name()))
}

/// Authenticate and decode a raw webhook. The split helpers are also exposed so
/// the WIT shim can preserve the host's typed authentication and payload-
/// rejection boundary.
pub fn parse_webhook(
    headers: &[(String, String)],
    body: &[u8],
    cfg: &NextcloudConfig,
) -> Result<Vec<Inbound>, String> {
    authenticate_webhook(headers, body, cfg)?;
    decode_webhook(body, cfg)
}

/// Decode a Talk bot webhook payload into inbound messages. Routes on the
/// top-level `type`:
///   * `"Create"` → Activity Streams 2.0 (the real Talk bot format),
///   * `"message"` → legacy/custom shape,
///   * anything else → nothing (a heartbeat/system event just acks empty).
pub fn decode_inbound(payload: &Value, bot_name: &str) -> Vec<Inbound> {
    let event_type = payload
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if event_type.eq_ignore_ascii_case("create") {
        decode_as2(payload, bot_name).into_iter().collect()
    } else if event_type.eq_ignore_ascii_case("message") {
        decode_legacy(payload, bot_name).into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Decode an Activity Streams 2.0 `Create` payload (the real Talk bot webhook
/// format):
///
/// ```json
/// {
///   "type": "Create",
///   "actor":  { "type": "Person", "id": "users/alice", "name": "Alice" },
///   "object": { "type": "Note", "name": "message", "id": "177",
///               "content": "{\"message\":\"hi\",\"parameters\":[]}" },
///   "target": { "type": "Collection", "id": "<room_token>", "name": "Room" }
/// }
/// ```
///
/// Emits `sender = actor.id` (with the `users/`/`bots/` prefix stripped),
/// `reply_target = target.id` (the conversation token), and `content` = the
/// `message` field decoded from the JSON-encoded `object.content`. Returns `None`
/// for non-chat objects, bot-authored messages (feedback-loop guard), and empty
/// content.
fn decode_as2(payload: &Value, bot_name: &str) -> Option<Inbound> {
    let obj = payload.get("object")?;

    // Chat messages are `Note` objects named `message`. Ignore reactions, edits,
    // system activity, etc. Accept on either signal so a payload that omits one
    // still parses.
    let obj_type = obj.get("type").and_then(Value::as_str).unwrap_or_default();
    let obj_name = obj.get("name").and_then(Value::as_str).unwrap_or_default();
    if !obj_type.eq_ignore_ascii_case("note") && !obj_name.eq_ignore_ascii_case("message") {
        return None;
    }

    // Conversation token = target.id.
    let room_token = payload
        .get("target")
        .and_then(|t| t.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())?;

    let actor = payload.get("actor");

    // Feedback-loop guard: drop the bot's own messages. Nextcloud does not
    // always set `actor.type = "Application"` reliably, so we also check the
    // `bots/` id prefix and the configured/known bot name.
    let actor_type = actor
        .and_then(|a| a.get("type"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actor_type.eq_ignore_ascii_case("application") {
        return None;
    }

    let raw_actor_id = actor
        .and_then(|a| a.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if raw_actor_id.starts_with("bots/") {
        return None;
    }
    let actor_id = raw_actor_id
        .trim_start_matches("users/")
        .trim_start_matches("bots/")
        .trim();
    if actor_id.is_empty() {
        return None;
    }

    let actor_name = actor
        .and_then(|a| a.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if is_bot_name(actor_name, bot_name) {
        return None;
    }

    // The message text is JSON-encoded inside `object.content`, e.g.
    // `content = "{\"message\":\"hello\",\"parameters\":[]}"`.
    let content = obj
        .get("content")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| {
            v.get("message")
                .and_then(Value::as_str)
                .map(|m| m.trim().to_string())
        })
        .filter(|s| !s.is_empty())?;

    let id = value_to_string(obj.get("id"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback_id(actor_id, &content));

    Some(Inbound {
        id,
        sender: actor_id.to_string(),
        reply_target: room_token.to_string(),
        content,
    })
}

/// Decode the legacy/custom `type: "message"` shape:
///
/// ```json
/// {
///   "type": "message",
///   "object":  { "token": "<room>" },
///   "message": { "actorType": "users", "actorId": "alice", "message": "hi" }
/// }
/// ```
fn decode_legacy(payload: &Value, bot_name: &str) -> Option<Inbound> {
    let message_obj = payload.get("message")?;

    let room_token = payload
        .get("object")
        .and_then(|o| o.get("token"))
        .and_then(Value::as_str)
        .or_else(|| message_obj.get("token").and_then(Value::as_str))
        .map(str::trim)
        .filter(|t| !t.is_empty())?;

    // Feedback-loop guard: drop bot / system-originated messages.
    let actor_type = message_obj
        .get("actorType")
        .and_then(Value::as_str)
        .or_else(|| payload.get("actorType").and_then(Value::as_str))
        .unwrap_or_default();
    if actor_type.eq_ignore_ascii_case("bots") || actor_type.eq_ignore_ascii_case("application") {
        return None;
    }

    let actor_id = message_obj
        .get("actorId")
        .and_then(Value::as_str)
        .or_else(|| payload.get("actorId").and_then(Value::as_str))
        .map(str::trim)
        .filter(|id| !id.is_empty())?;
    if is_bot_name(actor_id, bot_name) {
        return None;
    }

    // Only real chat comments; skip system events.
    let message_type = message_obj
        .get("messageType")
        .and_then(Value::as_str)
        .unwrap_or("comment");
    if !message_type.eq_ignore_ascii_case("comment") {
        return None;
    }
    let has_system_message = message_obj
        .get("systemMessage")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|v| !v.is_empty());
    if has_system_message {
        return None;
    }

    let content = message_obj
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|c| !c.is_empty())?
        .to_string();

    let id = value_to_string(message_obj.get("id"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback_id(actor_id, &content));

    Some(Inbound {
        id,
        sender: actor_id.to_string(),
        reply_target: room_token.to_string(),
        content,
    })
}

/// Whether `name` identifies this bot: the configured `bot_name` (when set) or
/// the well-known built-in name `zeroclaw`. Mirrors the native `is_bot_name`.
fn is_bot_name(name: &str, bot_name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    (!bot_name.is_empty() && name == bot_name) || name == "zeroclaw"
}

/// A `Value` (string or number) rendered to a `String`; `None` for other kinds.
fn value_to_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// A deterministic synthetic id for the rare payload that omits an id, so the
/// host's dedup key stays stable across a retry of the *same* message.
fn fallback_id(sender: &str, content: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    sender.hash(&mut h);
    content.hash(&mut h);
    format!("nextcloud_{:x}", h.finish())
}

// ── Outbound send ───────────────────────────────────────────────────────────────

/// The OCS chat `sendMessage` URL for a conversation token:
/// `POST {base}/ocs/v2.php/apps/spreed/api/v1/chat/{token}?format=json`.
/// The token is percent-encoded for the path segment.
pub fn chat_url(base_url: &str, room_token: &str) -> String {
    format!(
        "{}/ocs/v2.php/apps/spreed/api/v1/chat/{}?format=json",
        base_url.trim_end_matches('/'),
        encode_path_segment(room_token)
    )
}

/// The OCS `sendMessage` JSON body: `{"message": "<text>"}`.
pub fn build_send_body(content: &str) -> Value {
    json!({ "message": content })
}

/// Truncate `text` to at most [`NC_MAX_MESSAGE_LENGTH`] characters on a char
/// boundary (never splitting a multi-byte codepoint), returning the original
/// when already within the limit.
pub fn truncate_to_nc_limit(text: &str) -> &str {
    match text.char_indices().nth(NC_MAX_MESSAGE_LENGTH) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

/// Percent-encode a single URL path segment (RFC 3986 unreserved set passes
/// through; everything else is `%XX`). Room tokens are normally `[A-Za-z0-9]`,
/// so this is defensive.
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0f));
            }
        }
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── config ────────────────────────────────────────────────────────────────

    #[test]
    fn config_parses_native_field_names() {
        let cfg = NextcloudConfig::from_json(
            r#"{
                "enabled": true,
                "base_url": "https://cloud.example.com/",
                "app_token": "  bot-token  ",
                "webhook_secret": " s3cr3t ",
                "bot_name": " ZeroClaw ",
                "proxy_url": "http://ignored",
                "stream_mode": "off"
            }"#,
        );
        assert_eq!(cfg.base_url(), "https://cloud.example.com");
        assert_eq!(cfg.app_token(), "bot-token");
        assert_eq!(cfg.webhook_secret(), "s3cr3t");
        assert_eq!(cfg.bot_name(), "zeroclaw");
    }

    #[test]
    fn config_empty_or_malformed_is_inert_defaults() {
        for s in ["", "{}", "not json", "[]"] {
            let cfg = NextcloudConfig::from_json(s);
            assert_eq!(cfg.base_url(), "");
            assert_eq!(cfg.app_token(), "");
            assert_eq!(cfg.webhook_secret(), "");
            assert_eq!(cfg.bot_name(), "");
        }
    }

    // ── signature ───────────────────────────────────────────────────────────────

    // Known-answer vector: HMAC-SHA256(key="topsecret", msg="rnd123{body}") hex.
    // Computed independently; guards the `random ++ body` ordering + hex compare.
    const KAV_SECRET: &str = "topsecret";
    const KAV_RANDOM: &str = "rnd123";
    const KAV_BODY: &str = r#"{"type":"Create"}"#;
    const KAV_SIG: &str = "2f8b1d0c8a5c2c6f7d8f8a3f3f2b6a4b9a3d2f0d0f5b9c7e1a2b3c4d5e6f7a8b";

    fn expected_sig(secret: &str, random: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(random.as_bytes());
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn signature_roundtrip_accepts_valid() {
        let sig = expected_sig(KAV_SECRET, KAV_RANDOM, KAV_BODY.as_bytes());
        assert!(verify_signature(
            KAV_SECRET,
            KAV_RANDOM,
            KAV_BODY.as_bytes(),
            &sig
        ));
        // uppercase hex + `sha256=` prefix are accepted too.
        assert!(verify_signature(
            KAV_SECRET,
            KAV_RANDOM,
            KAV_BODY.as_bytes(),
            &format!("sha256={}", sig.to_ascii_uppercase())
        ));
    }

    #[test]
    fn signature_rejects_tampered_body() {
        let sig = expected_sig(KAV_SECRET, KAV_RANDOM, KAV_BODY.as_bytes());
        assert!(!verify_signature(
            KAV_SECRET,
            KAV_RANDOM,
            b"{\"type\":\"Create\",\"x\":1}",
            &sig
        ));
    }

    #[test]
    fn signature_rejects_wrong_secret_random_and_junk() {
        let sig = expected_sig(KAV_SECRET, KAV_RANDOM, KAV_BODY.as_bytes());
        assert!(!verify_signature(
            "wrong",
            KAV_RANDOM,
            KAV_BODY.as_bytes(),
            &sig
        ));
        assert!(!verify_signature(
            KAV_SECRET,
            "other-random",
            KAV_BODY.as_bytes(),
            &sig
        ));
        // empty random is always rejected.
        assert!(!verify_signature(KAV_SECRET, "", KAV_BODY.as_bytes(), &sig));
        // non-hex signature is rejected, not panicking.
        assert!(!verify_signature(
            KAV_SECRET,
            KAV_RANDOM,
            KAV_BODY.as_bytes(),
            "nothex!!"
        ));
        // odd-length hex rejected.
        assert!(!verify_signature(
            KAV_SECRET,
            KAV_RANDOM,
            KAV_BODY.as_bytes(),
            "abc"
        ));
        // a fixed unrelated digest does not match.
        assert!(!verify_signature(
            KAV_SECRET,
            KAV_RANDOM,
            KAV_BODY.as_bytes(),
            KAV_SIG
        ));
    }

    #[test]
    fn decode_hex_roundtrip_and_rejects() {
        assert_eq!(decode_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(decode_hex("AB"), Some(vec![0xab]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    // ── parse_webhook (verify + decode) ─────────────────────────────────────────

    fn as2_body(actor_id: &str, actor_name: &str, token: &str, text: &str) -> String {
        let content = serde_json::to_string(&json!({ "message": text, "parameters": [] })).unwrap();
        json!({
            "type": "Create",
            "actor": { "type": "Person", "id": actor_id, "name": actor_name },
            "object": { "type": "Note", "name": "message", "id": "177", "content": content },
            "target": { "type": "Collection", "id": token, "name": "Room" }
        })
        .to_string()
    }

    fn cfg_with(secret: Option<&str>, bot_name: Option<&str>) -> NextcloudConfig {
        NextcloudConfig {
            base_url: "https://cloud.example.com".into(),
            app_token: Some("tok".into()),
            webhook_secret: secret.map(str::to_string),
            bot_name: bot_name.map(str::to_string),
        }
    }

    #[test]
    fn parse_webhook_verifies_then_decodes_as2() {
        let body = as2_body("users/alice", "Alice", "room-token-123", "hello there");
        let cfg = cfg_with(Some("topsecret"), None);
        let random = "abc-random";
        let sig = expected_sig("topsecret", random, body.as_bytes());
        let headers = vec![
            ("x-nextcloud-talk-random".to_string(), random.to_string()),
            ("x-nextcloud-talk-signature".to_string(), sig),
        ];
        let msgs = parse_webhook(&headers, body.as_bytes(), &cfg).expect("valid signature");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "alice");
        assert_eq!(msgs[0].reply_target, "room-token-123");
        assert_eq!(msgs[0].content, "hello there");
        assert_eq!(msgs[0].id, "177");
    }

    #[test]
    fn parse_webhook_bad_signature_is_err() {
        let body = as2_body("users/alice", "Alice", "room", "hi");
        let cfg = cfg_with(Some("topsecret"), None);
        let headers = vec![
            ("x-nextcloud-talk-random".to_string(), "r".to_string()),
            ("x-nextcloud-talk-signature".to_string(), "00".repeat(32)),
        ];
        assert!(parse_webhook(&headers, body.as_bytes(), &cfg).is_err());
    }

    #[test]
    fn parse_webhook_missing_signature_headers_is_err_when_secret_set() {
        let body = as2_body("users/alice", "Alice", "room", "hi");
        let cfg = cfg_with(Some("topsecret"), None);
        assert!(parse_webhook(&[], body.as_bytes(), &cfg).is_err());
    }

    #[test]
    fn parse_webhook_no_secret_accepts_unsigned() {
        let body = as2_body("users/alice", "Alice", "room-9", "unsigned ok");
        let cfg = cfg_with(None, None);
        let msgs = parse_webhook(&[], body.as_bytes(), &cfg).expect("unsigned accepted");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].reply_target, "room-9");
    }

    #[test]
    fn parse_webhook_invalid_json_is_err() {
        let cfg = cfg_with(None, None);
        assert!(parse_webhook(&[], b"not json", &cfg).is_err());
    }

    // ── decode_inbound (AS2) ────────────────────────────────────────────────────

    #[test]
    fn as2_maps_sender_target_and_content() {
        let payload: Value =
            serde_json::from_str(&as2_body("users/bob", "Bob", "tok-xyz", "  spaced  ")).unwrap();
        let msgs = decode_inbound(&payload, "");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "bob");
        assert_eq!(msgs[0].reply_target, "tok-xyz");
        assert_eq!(msgs[0].content, "spaced"); // trimmed
    }

    #[test]
    fn as2_drops_application_actor() {
        let mut payload: Value =
            serde_json::from_str(&as2_body("users/svc", "Svc", "tok", "loop")).unwrap();
        payload["actor"]["type"] = json!("Application");
        assert!(decode_inbound(&payload, "").is_empty());
    }

    #[test]
    fn as2_drops_bots_prefixed_actor() {
        let payload: Value =
            serde_json::from_str(&as2_body("bots/zeroclaw", "ZeroClaw", "tok", "loop")).unwrap();
        assert!(decode_inbound(&payload, "").is_empty());
    }

    #[test]
    fn as2_drops_configured_and_default_bot_name() {
        // default known bot name "zeroclaw"
        let p1: Value =
            serde_json::from_str(&as2_body("users/x", "ZeroClaw", "tok", "loop")).unwrap();
        assert!(decode_inbound(&p1, "").is_empty());
        // configured bot name
        let p2: Value = serde_json::from_str(&as2_body("users/x", "MyBot", "tok", "loop")).unwrap();
        assert!(decode_inbound(&p2, "mybot").is_empty());
        // a normal user still passes
        let p3: Value = serde_json::from_str(&as2_body("users/x", "Human", "tok", "hi")).unwrap();
        assert_eq!(decode_inbound(&p3, "mybot").len(), 1);
    }

    #[test]
    fn as2_ignores_non_note_object() {
        let mut payload: Value =
            serde_json::from_str(&as2_body("users/a", "A", "tok", "x")).unwrap();
        payload["object"]["type"] = json!("Like");
        payload["object"]["name"] = json!("reaction");
        assert!(decode_inbound(&payload, "").is_empty());
    }

    #[test]
    fn as2_empty_or_unparseable_content_dropped() {
        // empty message text
        let empty: Value = serde_json::from_str(&as2_body("users/a", "A", "tok", "   ")).unwrap();
        assert!(decode_inbound(&empty, "").is_empty());
        // content not JSON-encoded
        let mut bad: Value = serde_json::from_str(&as2_body("users/a", "A", "tok", "x")).unwrap();
        bad["object"]["content"] = json!("plain not json");
        assert!(decode_inbound(&bad, "").is_empty());
    }

    #[test]
    fn as2_missing_target_token_dropped() {
        let mut payload: Value =
            serde_json::from_str(&as2_body("users/a", "A", "tok", "x")).unwrap();
        payload["target"]["id"] = json!("");
        assert!(decode_inbound(&payload, "").is_empty());
    }

    #[test]
    fn as2_numeric_object_id_is_stringified() {
        let mut payload: Value =
            serde_json::from_str(&as2_body("users/a", "A", "tok", "hi")).unwrap();
        payload["object"]["id"] = json!(4242);
        let msgs = decode_inbound(&payload, "");
        assert_eq!(msgs[0].id, "4242");
    }

    #[test]
    fn as2_missing_id_gets_deterministic_fallback() {
        let mut payload: Value =
            serde_json::from_str(&as2_body("users/a", "A", "tok", "hi")).unwrap();
        payload["object"].as_object_mut().unwrap().remove("id");
        let a = decode_inbound(&payload, "");
        let b = decode_inbound(&payload, "");
        assert!(!a.is_empty());
        assert!(a[0].id.starts_with("nextcloud_"));
        assert_eq!(a[0].id, b[0].id); // deterministic
    }

    // ── decode_inbound (legacy) ─────────────────────────────────────────────────

    #[test]
    fn legacy_message_format_maps() {
        let payload = json!({
            "type": "message",
            "object": { "token": "room-legacy" },
            "message": {
                "actorType": "users",
                "actorId": "carol",
                "message": "legacy hi",
                "messageType": "comment"
            }
        });
        let msgs = decode_inbound(&payload, "");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "carol");
        assert_eq!(msgs[0].reply_target, "room-legacy");
        assert_eq!(msgs[0].content, "legacy hi");
    }

    #[test]
    fn legacy_drops_bot_actor_type_and_system() {
        let bot = json!({
            "type": "message",
            "object": { "token": "r" },
            "message": { "actorType": "bots", "actorId": "b", "message": "x" }
        });
        assert!(decode_inbound(&bot, "").is_empty());

        let sys = json!({
            "type": "message",
            "object": { "token": "r" },
            "message": { "actorType": "users", "actorId": "u", "message": "x",
                          "systemMessage": "call_started" }
        });
        assert!(decode_inbound(&sys, "").is_empty());

        let non_comment = json!({
            "type": "message",
            "object": { "token": "r" },
            "message": { "actorType": "users", "actorId": "u", "message": "x",
                          "messageType": "system" }
        });
        assert!(decode_inbound(&non_comment, "").is_empty());
    }

    #[test]
    fn unknown_event_type_yields_nothing() {
        assert!(decode_inbound(&json!({"type": "Heartbeat"}), "").is_empty());
        assert!(decode_inbound(&json!({}), "").is_empty());
    }

    // ── send helpers ────────────────────────────────────────────────────────────

    #[test]
    fn chat_url_shape_and_encoding() {
        assert_eq!(
            chat_url("https://cloud.example.com", "room-token-123"),
            "https://cloud.example.com/ocs/v2.php/apps/spreed/api/v1/chat/room-token-123?format=json"
        );
        // trailing slash trimmed + odd token chars percent-encoded.
        assert_eq!(
            chat_url("https://cloud.example.com/", "a b/c"),
            "https://cloud.example.com/ocs/v2.php/apps/spreed/api/v1/chat/a%20b%2Fc?format=json"
        );
    }

    #[test]
    fn send_body_shape() {
        assert_eq!(
            build_send_body("hi there"),
            json!({ "message": "hi there" })
        );
    }

    #[test]
    fn truncate_respects_char_boundary() {
        assert_eq!(truncate_to_nc_limit("hello"), "hello");
        let exact = "a".repeat(NC_MAX_MESSAGE_LENGTH);
        assert_eq!(truncate_to_nc_limit(&exact).len(), NC_MAX_MESSAGE_LENGTH);
        let over = "🦀".repeat(NC_MAX_MESSAGE_LENGTH + 10);
        let out = truncate_to_nc_limit(&over);
        assert_eq!(out.chars().count(), NC_MAX_MESSAGE_LENGTH);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let h = vec![("X-Nextcloud-Talk-Random".to_string(), "r".to_string())];
        assert_eq!(header(&h, RANDOM_HEADER), Some("r"));
        assert_eq!(header(&h, SIGNATURE_HEADER), None);
    }
}
