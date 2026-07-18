//! Pure Lark / Feishu webhook logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin. It owns everything that does not need
//! the network: config parsing + endpoint resolution, the webhook dispatch
//! (URL-verification handshake vs. real event vs. rejected/encrypted payloads),
//! the platform-payload → [`Inbound`] decode, the `tenant_access_token`
//! request/response shaping, and the send-body build + text chunking. The
//! `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the I/O
//! (blocking `waki` HTTP calls) and reuses this logic verbatim, so the
//! interesting behaviour is covered by a plain host `cargo test`.
//!
//! Authenticity model (plaintext mode): Lark webhooks carry a `token` — the
//! operator-set **verification token** — in the URL-verification body and in the
//! `header.token` of every event. The plugin verifies that token against its own
//! configured `verification_token` and returns `Err(reason)` on mismatch. The
//! component maps token failures to 401 and payload failures to 400, with
//! nothing enqueued. Encrypted transport
//! (`encrypt_key`, AES-256-CBC) is detected and cleanly rejected — see
//! [`handle_webhook`] — and left as a follow-up.

use serde::Deserialize;
use serde_json::{json, Value};

/// Lark (International) Open Platform API origin.
pub const LARK_BASE_URL: &str = "https://open.larksuite.com/open-apis";
/// Feishu (China) Open Platform API origin.
pub const FEISHU_BASE_URL: &str = "https://open.feishu.cn/open-apis";
/// Kept in sync with the manifest / plugin version.
pub const CHANNEL_VERSION: &str = "0.1.0";

/// Reserved `channel` sentinel understood by the host webhook front door: an
/// [`InboundMessage`](crate) carrying this channel is **not** enqueued as a
/// message — instead its `content` is written back as the HTTP 200 response
/// body. Used for the Lark URL-verification challenge echo (and a GET liveness
/// ping). See the plugin authoring brief, section B.1.
pub const WEBHOOK_REPLY_CHANNEL: &str = "__webhook_reply__";

/// Lark event type identifying an inbound IM message (event schema 2.0).
pub const EVENT_MESSAGE_RECEIVE: &str = "im.message.receive_v1";

/// Feishu/Lark API business code returned when the tenant access token is
/// expired or invalid — the shim drops its cached token and retries once.
pub const INVALID_TENANT_TOKEN_CODE: i64 = 99_991_663;

/// Conservative per-message budget for a single Lark text message's decoded
/// content. The API caps a text message well above this; we chunk long agent
/// replies so a single oversized turn is delivered as an ordered sequence
/// rather than rejected wholesale.
pub const LARK_TEXT_MAX_BYTES: usize = 4096;

/// The plugin's config section. Field names mirror the native `LarkConfig`
/// snake_case keys so a `[channels.lark.<alias>]` section can be fed to the
/// plugin verbatim; serde ignores the native fields this v0.1.0 plugin does not
/// use (`mention_only`, `receive_mode`, `port`, `proxy_url`, `excluded_tools`,
/// streaming/reaction tuning, …).
///
/// `api_base_url` is the one key the native config does not carry: the native
/// channel selects its endpoint with the boolean `use_feishu`. This plugin
/// honours `use_feishu` too, and additionally accepts an explicit
/// `api_base_url` override (handy for a test mock or a self-hosted proxy).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LarkConfig {
    /// Whether the channel is active (host-side gate; accepted for parity).
    #[serde(default)]
    pub enabled: bool,
    /// App ID from the Lark/Feishu developer console. Required to send.
    #[serde(default)]
    pub app_id: String,
    /// App Secret from the Lark/Feishu developer console. Required to send.
    #[serde(default)]
    pub app_secret: String,
    /// Webhook verification token. When set, the plugin authenticates every
    /// inbound payload against it (URL-verification `token` and event
    /// `header.token`); a mismatch is rejected with `Err`.
    #[serde(default)]
    pub verification_token: Option<String>,
    /// Webhook AES encrypt key. When set, Lark encrypts event bodies as
    /// `{"encrypt": "..."}`. This v0.1.0 plugin supports **plaintext mode
    /// only** and rejects encrypted bodies (see [`handle_webhook`]); accepted
    /// here so a native section deserializes and so the rejection message can
    /// point at the exact cause.
    #[serde(default)]
    pub encrypt_key: Option<String>,
    /// Explicit API origin override. When unset, the endpoint is chosen by
    /// `use_feishu`.
    #[serde(default)]
    pub api_base_url: Option<String>,
    /// Use the Feishu (China) endpoint instead of Lark (International).
    /// Mirrors the native field; ignored when `api_base_url` is set.
    #[serde(default)]
    pub use_feishu: bool,
    /// When true, group-chat sessions key on the sender's `open_id` (per-user
    /// isolation) instead of the shared `chat_id`. Mirrors the native field.
    #[serde(default)]
    pub per_user_session: bool,
}

impl LarkConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// The resolved API origin (no trailing slash): an explicit `api_base_url`
    /// wins, else Feishu-vs-Lark per `use_feishu`.
    pub fn api_base(&self) -> String {
        if let Some(url) = self.api_base_url.as_deref() {
            let trimmed = url.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if self.use_feishu {
            FEISHU_BASE_URL.to_string()
        } else {
            LARK_BASE_URL.to_string()
        }
    }

    /// `POST` endpoint that exchanges `app_id`/`app_secret` for a
    /// `tenant_access_token`.
    pub fn tenant_token_url(&self) -> String {
        format!("{}/auth/v3/tenant_access_token/internal", self.api_base())
    }

    /// `POST` endpoint that sends a message addressed by `chat_id`.
    pub fn send_url(&self) -> String {
        format!("{}/im/v1/messages?receive_id_type=chat_id", self.api_base())
    }

    /// The configured verification token, trimmed and non-empty, or `None`.
    pub fn verification_token(&self) -> Option<&str> {
        self.verification_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// Whether the app credentials needed to send are present.
    pub fn has_credentials(&self) -> bool {
        !self.app_id.trim().is_empty() && !self.app_secret.trim().is_empty()
    }
}

/// A Lark event mapped to the host inbound-message fields (the `channel` is
/// always `"lark"`, stamped by the host shim). Independent of the WIT record so
/// the pure core carries no wasm dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub channel_alias: Option<String>,
    /// Unix timestamp in milliseconds (`event.message.create_time` verbatim;
    /// Lark already reports it in ms).
    pub timestamp: u64,
    pub thread_ts: Option<String>,
}

/// The result of decoding an inbound webhook request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookOutcome {
    /// Echo `content` back as the HTTP 200 body and enqueue nothing (the
    /// URL-verification challenge, or a GET liveness ping). The shim wraps this
    /// as a single [`WEBHOOK_REPLY_CHANNEL`] inbound message.
    Reply(String),
    /// Real inbound events to enqueue for the agent.
    Events(Vec<Inbound>),
}

/// Whether a payload is an encrypted-transport envelope (`{"encrypt": "..."}`).
pub fn is_encrypted(payload: &Value) -> bool {
    payload
        .get("encrypt")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
}

/// The URL-verification challenge + its embedded token, when the payload is a
/// `url_verification` request. Mirrors the native check (presence of a
/// `challenge` string), and additionally surfaces the `token` so the caller can
/// authenticate the handshake.
pub fn challenge_of(payload: &Value) -> Option<(String, Option<String>)> {
    let challenge = payload.get("challenge").and_then(Value::as_str)?;
    let token = payload
        .get("token")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some((challenge.to_string(), token))
}

/// The exact body to echo for a URL-verification challenge: Lark expects the
/// challenge returned as JSON `{"challenge": "<value>"}`.
pub fn verification_reply(challenge: &str) -> String {
    json!({ "challenge": challenge }).to_string()
}

/// The `header.event_type` of an event-schema-2.0 payload.
pub fn event_type_of(payload: &Value) -> Option<&str> {
    payload
        .pointer("/header/event_type")
        .and_then(Value::as_str)
}

/// The `header.token` (verification token) carried on an event-schema-2.0
/// payload, when present.
pub fn event_token_of(payload: &Value) -> Option<&str> {
    payload.pointer("/header/token").and_then(Value::as_str)
}

/// Extract the plain text of a `text` message's `content` (a JSON *string* like
/// `{"text":"hi"}`). Returns `None` when the content is not parseable JSON with
/// a non-empty `text` field.
pub fn extract_text(content_str: &str) -> Option<String> {
    serde_json::from_str::<Value>(content_str)
        .ok()
        .and_then(|v| {
            v.get("text")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
}

/// The session-key identity for an inbound message. With `per_user_session` the
/// sender's `open_id` keys the session (falling back to `chat_id` when the
/// platform omits it); otherwise every message in a chat shares the `chat_id`
/// session. Mirrors the native `resolve_sender`.
fn resolve_sender<'a>(chat_id: &'a str, open_id: &'a str, per_user_session: bool) -> &'a str {
    if per_user_session && !open_id.is_empty() {
        open_id
    } else {
        chat_id
    }
}

/// Map an `im.message.receive_v1` **text** event to an [`Inbound`]. Returns an
/// empty vec for any other event type / message type (this v0.1.0 plugin
/// delivers text only; post/image/audio/file are skipped), for a missing
/// sender, or for empty text. Returns a one-element vec on success.
///
/// `reply_target` is always the `chat_id` (both 1:1 and group replies address
/// the chat); `sender` is resolved via [`resolve_sender`].
pub fn parse_events(payload: &Value, per_user_session: bool) -> Vec<Inbound> {
    if event_type_of(payload) != Some(EVENT_MESSAGE_RECEIVE) {
        return Vec::new();
    }
    let Some(event) = payload.get("event") else {
        return Vec::new();
    };

    let open_id = event
        .pointer("/sender/sender_id/open_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if open_id.is_empty() {
        return Vec::new();
    }

    let msg_type = event
        .pointer("/message/message_type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if msg_type != "text" {
        return Vec::new();
    }

    let content_str = event
        .pointer("/message/content")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(text) = extract_text(content_str) else {
        return Vec::new();
    };

    let chat_id = event
        .pointer("/message/chat_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(open_id);
    let timestamp = event
        .pointer("/message/create_time")
        .and_then(Value::as_str)
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(0);
    let message_id = event
        .pointer("/message/message_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("lark_{chat_id}_{timestamp}"));

    let sender = resolve_sender(chat_id, open_id, per_user_session);

    vec![Inbound {
        id: message_id,
        sender: sender.to_string(),
        reply_target: chat_id.to_string(),
        content: text,
        channel_alias: None,
        timestamp,
        thread_ts: None,
    }]
}

/// Decode the request body. `None` represents a GET liveness probe, while
/// malformed JSON and unsupported encrypted envelopes are payload errors.
pub fn parse_webhook_body(method: &str, body: &[u8]) -> Result<Option<Value>, String> {
    // Lark performs its verification handshake over POST; a GET is only ever a
    // browser/health probe. Answer it with a bare 200 and enqueue nothing.
    if method.eq_ignore_ascii_case("GET") {
        return Ok(None);
    }

    let payload: Value = serde_json::from_slice(body)
        .map_err(|e| format!("lark: invalid JSON webhook body: {e}"))?;

    if is_encrypted(&payload) {
        return Err(
            "lark: encrypted webhook payloads (encrypt_key / AES-256-CBC) are not supported yet — \
             turn off encryption in the Lark event-subscription settings to use plaintext mode; \
             encrypted transport is a planned follow-up"
                .to_string(),
        );
    }
    Ok(Some(payload))
}

/// Verify the token carried by an already-decoded challenge or event payload.
pub fn authenticate_webhook(cfg: &LarkConfig, payload: &Value) -> Result<(), String> {
    // URL-verification handshake.
    if let Some((_, token)) = challenge_of(payload) {
        if let (Some(expected), Some(got)) = (cfg.verification_token(), token.as_deref()) {
            if got != expected {
                return Err("lark: url_verification token mismatch".to_string());
            }
        }
        return Ok(());
    }

    // Real event: authenticate against the configured verification token when
    // both sides carry one, then decode.
    if let (Some(expected), Some(got)) = (cfg.verification_token(), event_token_of(payload)) {
        if got != expected {
            return Err("lark: event verification token mismatch".to_string());
        }
    }
    Ok(())
}

/// Convert an authenticated Lark payload into a handshake reply or events.
pub fn decode_webhook(cfg: &LarkConfig, payload: &Value) -> WebhookOutcome {
    if let Some((challenge, _)) = challenge_of(payload) {
        return WebhookOutcome::Reply(verification_reply(&challenge));
    }
    WebhookOutcome::Events(parse_events(payload, cfg.per_user_session))
}

/// Decode, authenticate, and map a raw inbound webhook. The split helpers are
/// also exposed so the WIT shim can preserve the host's typed authentication
/// and payload-rejection boundary.
pub fn handle_webhook(
    cfg: &LarkConfig,
    method: &str,
    _query: &str,
    body: &[u8],
) -> Result<WebhookOutcome, String> {
    let Some(payload) = parse_webhook_body(method, body)? else {
        return Ok(WebhookOutcome::Reply("ok".to_string()));
    };
    authenticate_webhook(cfg, &payload)?;
    Ok(decode_webhook(cfg, &payload))
}

/// Build the `tenant_access_token/internal` request body.
pub fn build_token_request_body(app_id: &str, app_secret: &str) -> Value {
    json!({ "app_id": app_id, "app_secret": app_secret })
}

/// Extract the `tenant_access_token` from an exchange response, or a descriptive
/// error when the API reported a non-zero `code` or omitted the token.
pub fn extract_tenant_token(response: &Value) -> Result<String, String> {
    let code = response.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let msg = response
            .get("msg")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(format!(
            "lark: tenant_access_token request failed (code {code}): {msg}"
        ));
    }
    response
        .get("tenant_access_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or_else(|| "lark: missing tenant_access_token in response".to_string())
}

/// The business `code` in an API response (`0`/absent means success).
pub fn response_code(response: &Value) -> i64 {
    response.get("code").and_then(Value::as_i64).unwrap_or(0)
}

/// Whether an API `code` means the tenant access token is expired/invalid (drop
/// the cached token and retry once).
pub fn is_invalid_token(code: i64) -> bool {
    code == INVALID_TENANT_TOKEN_CODE
}

/// Build the `im/v1/messages` request body for a single text message.
pub fn build_send_body(recipient: &str, text: &str) -> Value {
    json!({
        "receive_id": recipient,
        "msg_type": "text",
        // Lark wants the message content as a JSON *string*, not an object.
        "content": json!({ "text": text }).to_string(),
    })
}

/// Split `text` into chunks each at most `max_bytes` bytes, never cutting a
/// UTF-8 character in half. An empty input yields an empty vec (nothing to
/// send); a single character larger than `max_bytes` is skipped. Long agent
/// turns are delivered as an ordered sequence of text messages.
pub fn split_text_chunks(text: &str, max_bytes: usize) -> Vec<String> {
    if text.is_empty() || max_bytes == 0 {
        return Vec::new();
    }
    if text.len() <= max_bytes {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if current.len() + ch.len_utf8() > max_bytes {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
            }
            // A lone char wider than the budget cannot fit any chunk; skip it
            // (only possible for pathologically small `max_bytes`).
            if ch.len_utf8() > max_bytes {
                continue;
            }
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_event(open_id: &str, chat_id: &str, text: &str, token: Option<&str>) -> Value {
        json!({
            "schema": "2.0",
            "header": {
                "event_type": EVENT_MESSAGE_RECEIVE,
                "event_id": "evt-1",
                "token": token,
            },
            "event": {
                "sender": { "sender_id": { "open_id": open_id } },
                "message": {
                    "message_id": "om_msg_1",
                    "chat_id": chat_id,
                    "chat_type": "p2p",
                    "message_type": "text",
                    "create_time": "1700000000000",
                    "content": json!({ "text": text }).to_string(),
                }
            }
        })
    }

    // ── config / endpoints ────────────────────────────────────────────────

    #[test]
    fn config_parses_and_defaults() {
        let cfg = LarkConfig::from_json(
            r#"{"enabled":true,"app_id":"cli_x","app_secret":"sec","verification_token":"vtok"}"#,
        );
        assert!(cfg.enabled);
        assert!(cfg.has_credentials());
        assert_eq!(cfg.verification_token(), Some("vtok"));
        // Default endpoint is Lark International.
        assert_eq!(cfg.api_base(), LARK_BASE_URL);
        assert_eq!(
            cfg.send_url(),
            "https://open.larksuite.com/open-apis/im/v1/messages?receive_id_type=chat_id"
        );
        assert_eq!(
            cfg.tenant_token_url(),
            "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal"
        );

        // A withheld / malformed section is inert defaults, not a hard failure.
        let empty = LarkConfig::from_json("{}");
        assert!(!empty.has_credentials());
        assert_eq!(empty.verification_token(), None);
        assert_eq!(LarkConfig::from_json("not json").app_id, "");
    }

    #[test]
    fn use_feishu_selects_china_endpoint() {
        let cfg = LarkConfig::from_json(r#"{"use_feishu":true}"#);
        assert_eq!(cfg.api_base(), FEISHU_BASE_URL);
        assert_eq!(
            cfg.send_url(),
            "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id"
        );
    }

    #[test]
    fn api_base_url_override_wins_and_trims_slash() {
        let cfg = LarkConfig::from_json(
            r#"{"use_feishu":true,"api_base_url":"https://mock.test/open-apis/"}"#,
        );
        // Explicit override beats use_feishu, trailing slash trimmed.
        assert_eq!(cfg.api_base(), "https://mock.test/open-apis");
        // Blank override falls through to the use_feishu default.
        let blank = LarkConfig::from_json(r#"{"use_feishu":true,"api_base_url":"  "}"#);
        assert_eq!(blank.api_base(), FEISHU_BASE_URL);
    }

    #[test]
    fn empty_verification_token_is_none() {
        let cfg = LarkConfig::from_json(r#"{"verification_token":"   "}"#);
        assert_eq!(cfg.verification_token(), None);
    }

    // ── URL-verification handshake ────────────────────────────────────────

    #[test]
    fn challenge_echoed_as_json() {
        let cfg = LarkConfig::from_json(r#"{"verification_token":"vtok"}"#);
        let body = json!({
            "type": "url_verification",
            "challenge": "abc123",
            "token": "vtok"
        })
        .to_string();
        match handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap() {
            WebhookOutcome::Reply(r) => assert_eq!(r, r#"{"challenge":"abc123"}"#),
            other => panic!("expected reply, got {other:?}"),
        }
    }

    #[test]
    fn challenge_token_mismatch_is_rejected() {
        let cfg = LarkConfig::from_json(r#"{"verification_token":"vtok"}"#);
        let body = json!({
            "type": "url_verification",
            "challenge": "abc123",
            "token": "WRONG"
        })
        .to_string();
        let err = handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap_err();
        assert!(err.contains("token mismatch"), "got: {err}");
    }

    #[test]
    fn challenge_accepted_when_no_verification_token_configured() {
        // Nothing to verify against → the handshake still succeeds (matches the
        // native channel's lenient behaviour).
        let cfg = LarkConfig::from_json("{}");
        let body = json!({ "challenge": "xyz", "token": "whatever" }).to_string();
        match handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap() {
            WebhookOutcome::Reply(r) => assert_eq!(r, r#"{"challenge":"xyz"}"#),
            other => panic!("expected reply, got {other:?}"),
        }
    }

    #[test]
    fn get_is_liveness_reply() {
        let cfg = LarkConfig::from_json("{}");
        match handle_webhook(&cfg, "GET", "", b"").unwrap() {
            WebhookOutcome::Reply(r) => assert_eq!(r, "ok"),
            other => panic!("expected reply, got {other:?}"),
        }
    }

    // ── event decoding ────────────────────────────────────────────────────

    #[test]
    fn parses_a_text_event() {
        let cfg = LarkConfig::from_json(r#"{"verification_token":"vtok"}"#);
        let body = text_event("ou_alice", "oc_chat42", "hello there", Some("vtok")).to_string();
        let events = match handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap() {
            WebhookOutcome::Events(e) => e,
            other => panic!("expected events, got {other:?}"),
        };
        assert_eq!(events.len(), 1);
        let inb = &events[0];
        assert_eq!(inb.id, "om_msg_1");
        // Default (per_user_session=false): sender == chat_id.
        assert_eq!(inb.sender, "oc_chat42");
        assert_eq!(inb.reply_target, "oc_chat42");
        assert_eq!(inb.content, "hello there");
        assert_eq!(inb.timestamp, 1_700_000_000_000);
        assert_eq!(inb.channel_alias, None);
        assert_eq!(inb.thread_ts, None);
    }

    #[test]
    fn per_user_session_keys_on_open_id() {
        let cfg = LarkConfig::from_json(r#"{"verification_token":"vtok","per_user_session":true}"#);
        let body = text_event("ou_alice", "oc_chat42", "hi", Some("vtok")).to_string();
        let events = match handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap() {
            WebhookOutcome::Events(e) => e,
            other => panic!("expected events, got {other:?}"),
        };
        assert_eq!(events[0].sender, "ou_alice");
        // Reply still addresses the chat.
        assert_eq!(events[0].reply_target, "oc_chat42");
    }

    #[test]
    fn event_token_mismatch_is_rejected() {
        let cfg = LarkConfig::from_json(r#"{"verification_token":"vtok"}"#);
        let body = text_event("ou_alice", "oc_chat42", "hi", Some("WRONG")).to_string();
        let err = handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap_err();
        assert!(
            err.contains("event verification token mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn event_without_token_is_accepted_when_none_configured() {
        let cfg = LarkConfig::from_json("{}");
        let body = text_event("ou_alice", "oc_chat42", "hi", None).to_string();
        let events = match handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap() {
            WebhookOutcome::Events(e) => e,
            other => panic!("expected events, got {other:?}"),
        };
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn non_text_message_types_are_skipped() {
        // image message → no inbound (text-only plugin).
        let mut payload = text_event("ou_alice", "oc_chat", "x", None);
        payload["event"]["message"]["message_type"] = json!("image");
        payload["event"]["message"]["content"] = json!(r#"{"image_key":"img_v2_x"}"#);
        assert!(parse_events(&payload, false).is_empty());
    }

    #[test]
    fn non_message_event_types_are_ignored() {
        let payload = json!({
            "schema": "2.0",
            "header": { "event_type": "im.chat.member.bot.added_v1", "token": "vtok" },
            "event": {}
        });
        assert!(parse_events(&payload, false).is_empty());
    }

    #[test]
    fn empty_sender_or_text_is_skipped() {
        let mut no_sender = text_event("", "oc_chat", "hi", None);
        no_sender["event"]["sender"]["sender_id"]["open_id"] = json!("");
        assert!(parse_events(&no_sender, false).is_empty());

        let mut empty_text = text_event("ou_alice", "oc_chat", "", None);
        empty_text["event"]["message"]["content"] = json!(r#"{"text":""}"#);
        assert!(parse_events(&empty_text, false).is_empty());
    }

    #[test]
    fn synthesizes_id_and_falls_back_to_open_id_chat() {
        let mut payload = text_event("ou_bob", "", "yo", None);
        // Blank chat_id → reply addresses the sender's open_id; id synthesised.
        payload["event"]["message"]["chat_id"] = json!("");
        payload["event"]["message"]["message_id"] = json!("");
        let events = parse_events(&payload, false);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reply_target, "ou_bob");
        assert_eq!(events[0].id, "lark_ou_bob_1700000000000");
    }

    #[test]
    fn extract_text_handles_missing_and_empty() {
        assert_eq!(extract_text(r#"{"text":"hi"}"#).as_deref(), Some("hi"));
        assert_eq!(extract_text(r#"{"text":""}"#), None);
        assert_eq!(extract_text(r#"{"other":"x"}"#), None);
        assert_eq!(extract_text("not json"), None);
    }

    // ── encrypted / malformed transport ───────────────────────────────────

    #[test]
    fn encrypted_body_is_cleanly_rejected() {
        let cfg = LarkConfig::from_json(r#"{"encrypt_key":"k","verification_token":"vtok"}"#);
        let body = json!({ "encrypt": "BASE64CIPHERTEXT" }).to_string();
        let err = handle_webhook(&cfg, "POST", "", body.as_bytes()).unwrap_err();
        assert!(err.contains("encrypted"), "got: {err}");
    }

    #[test]
    fn invalid_json_body_is_rejected() {
        let cfg = LarkConfig::from_json("{}");
        let err = handle_webhook(&cfg, "POST", "", b"{not json").unwrap_err();
        assert!(err.contains("invalid JSON"), "got: {err}");
    }

    // ── tenant token exchange ─────────────────────────────────────────────

    #[test]
    fn token_request_body_shape() {
        let body = build_token_request_body("cli_x", "sec_y");
        assert_eq!(body["app_id"], json!("cli_x"));
        assert_eq!(body["app_secret"], json!("sec_y"));
    }

    #[test]
    fn extract_tenant_token_success_and_errors() {
        let ok = json!({ "code": 0, "tenant_access_token": "t-abc", "expire": 7200 });
        assert_eq!(extract_tenant_token(&ok).unwrap(), "t-abc");

        let bad_code = json!({ "code": 10003, "msg": "app not found" });
        let err = extract_tenant_token(&bad_code).unwrap_err();
        assert!(
            err.contains("10003") && err.contains("app not found"),
            "got: {err}"
        );

        let missing = json!({ "code": 0 });
        assert!(extract_tenant_token(&missing).is_err());
    }

    #[test]
    fn response_code_and_invalid_token_classification() {
        assert_eq!(response_code(&json!({ "code": 0 })), 0);
        assert_eq!(response_code(&json!({})), 0);
        assert_eq!(
            response_code(&json!({ "code": 99991663 })),
            INVALID_TENANT_TOKEN_CODE
        );
        assert!(is_invalid_token(INVALID_TENANT_TOKEN_CODE));
        assert!(!is_invalid_token(0));
        assert!(!is_invalid_token(230020));
    }

    // ── send body + chunking ──────────────────────────────────────────────

    #[test]
    fn send_body_shape() {
        let body = build_send_body("oc_chat42", "reply text");
        assert_eq!(body["receive_id"], json!("oc_chat42"));
        assert_eq!(body["msg_type"], json!("text"));
        // content is a JSON *string*, not an object.
        assert_eq!(body["content"], json!(r#"{"text":"reply text"}"#));
    }

    #[test]
    fn send_body_content_escapes_correctly() {
        let body = build_send_body("oc", "line1\nline2 \"q\"");
        let content = body["content"].as_str().unwrap();
        // Round-trips back to the original text.
        let reparsed: Value = serde_json::from_str(content).unwrap();
        assert_eq!(reparsed["text"], json!("line1\nline2 \"q\""));
    }

    #[test]
    fn split_text_chunks_behaviour() {
        // Short text → single chunk.
        assert_eq!(split_text_chunks("hello", 4096), vec!["hello".to_string()]);
        // Empty → nothing to send.
        assert!(split_text_chunks("", 4096).is_empty());
        // Long text → multiple chunks, each within budget, reassembling exactly.
        let long = "a".repeat(10_000);
        let chunks = split_text_chunks(&long, 4096);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.len() <= 4096));
        assert_eq!(chunks.concat(), long);
    }

    #[test]
    fn split_text_chunks_respects_utf8_boundaries() {
        // Each emoji is 4 bytes; budget of 5 fits exactly one per chunk.
        let text = "😀😀😀";
        let chunks = split_text_chunks(text, 5);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.chars().count() == 1));
        assert_eq!(chunks.concat(), text);
    }
}
