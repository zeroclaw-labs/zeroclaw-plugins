//! Pure Gmail Pub/Sub push channel logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin. It owns everything I/O-free and
//! therefore host-testable with a plain `cargo test`:
//!
//!   * parsing the plugin's `[channels.gmail_push.<alias>]` config section,
//!   * the shared-secret `Authorization: Bearer <webhook_secret>` check on the
//!     inbound Pub/Sub push (matching the native gateway),
//!   * decoding the Pub/Sub envelope → `{emailAddress, historyId}` notification,
//!   * parsing a Gmail `messages.get` response into inbound fields (From/Subject
//!     header extraction + MIME body walking with base64url decode + HTML strip),
//!     and
//!   * building the `messages.send`, `users.watch`, and History-API request
//!     bodies / URLs.
//!
//! The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O: it verifies the push, decodes the notification, then calls the Gmail
//! History + messages APIs (blocking `waki`) to fetch the actual message content
//! — the Pub/Sub push itself carries only a `historyId`, never the message.
//!
//! Scope: **text messages only** (send + receive). Attachments are ignored; the
//! plain-text (or HTML-stripped) body is used.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

/// Gmail API origin.
pub const GMAIL_API: &str = "https://gmail.googleapis.com";

/// The URL path segment the host mounts this channel's webhook under
/// (`/plugin/gmail_push`).
pub const WEBHOOK_PATH: &str = "gmail_push";

fn default_label_filter() -> Vec<String> {
    vec!["INBOX".to_string()]
}

/// The plugin's config section, mirroring the native
/// `[channels.gmail_push.<alias>]` snake_case keys. serde ignores fields this
/// v0.1.0 plugin does not use (`excluded_tools`, …).
#[derive(Debug, Clone, Deserialize)]
pub struct GmailPushConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Pub/Sub topic name for `users.watch` registration.
    #[serde(default)]
    pub topic: String,
    /// Gmail labels to watch (default `["INBOX"]`).
    #[serde(default = "default_label_filter")]
    pub label_filter: Vec<String>,
    /// OAuth bearer token for the Gmail API (send + history + message fetch).
    #[serde(default)]
    pub oauth_token: String,
    /// Push endpoint URL (informational; used by the native watch flow).
    #[serde(default)]
    pub webhook_url: String,
    /// Shared secret. When set, the inbound push must present
    /// `Authorization: Bearer <webhook_secret>`; when empty, no auth is required
    /// (mirrors the native gateway).
    #[serde(default)]
    pub webhook_secret: String,
}

impl Default for GmailPushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            topic: String::new(),
            label_filter: default_label_filter(),
            oauth_token: String::new(),
            webhook_url: String::new(),
            webhook_secret: String::new(),
        }
    }
}

impl GmailPushConfig {
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    pub fn oauth_token(&self) -> &str {
        self.oauth_token.trim()
    }

    pub fn webhook_secret(&self) -> &str {
        self.webhook_secret.trim()
    }
}

// ── Inbound authentication ────────────────────────────────────────────────

/// Verify the Pub/Sub push request's `Authorization` header against the
/// configured shared secret. When the secret is empty, all requests are accepted
/// (mirrors the native gateway). Comparison is over the exact `Bearer <secret>`
/// value.
pub fn verify_bearer(webhook_secret: &str, auth_header: &str) -> bool {
    let secret = webhook_secret.trim();
    if secret.is_empty() {
        return true;
    }
    let provided = auth_header.trim().strip_prefix("Bearer ").unwrap_or("");
    constant_time_eq(provided, secret)
}

/// Constant-time byte comparison (length may leak, like the native check).
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

// ── Pub/Sub envelope ──────────────────────────────────────────────────────

/// The outer JSON envelope Google Pub/Sub POSTs to the push endpoint.
#[derive(Debug, Deserialize)]
pub struct PubSubEnvelope {
    pub message: PubSubMessage,
    #[serde(default)]
    pub subscription: String,
}

/// A single Pub/Sub message inside the envelope.
#[derive(Debug, Deserialize)]
pub struct PubSubMessage {
    /// Base64-encoded JSON payload from Gmail.
    pub data: String,
    #[serde(default, rename = "messageId")]
    pub message_id: String,
    #[serde(default, rename = "publishTime")]
    pub publish_time: String,
}

// Pub/Sub examples encode historyId numerically; the Gmail REST API returns a decimal string.
fn deserialize_history_id<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Number(u64),
        Decimal(String),
    }
    match Id::deserialize(de)? {
        Id::Number(n) => Ok(n),
        Id::Decimal(n) => n.parse().map_err(serde::de::Error::custom),
    }
}

/// The decoded payload inside `PubSubMessage.data`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct GmailNotification {
    #[serde(rename = "emailAddress")]
    pub email_address: String,
    #[serde(rename = "historyId", deserialize_with = "deserialize_history_id")]
    pub history_id: u64,
}

/// Decode the Gmail notification from a Pub/Sub message (`base64 → JSON`).
pub fn parse_notification(msg: &PubSubMessage) -> Result<GmailNotification, String> {
    let decoded = BASE64
        .decode(msg.data.trim())
        .map_err(|e| format!("gmail_push: invalid base64 in Pub/Sub message: {e}"))?;
    serde_json::from_slice(&decoded)
        .map_err(|e| format!("gmail_push: invalid JSON in Gmail notification: {e}"))
}

/// Parse a raw Pub/Sub push body into its envelope.
pub fn parse_envelope(body: &[u8]) -> Result<PubSubEnvelope, String> {
    serde_json::from_slice(body).map_err(|e| format!("gmail_push: invalid Pub/Sub envelope: {e}"))
}

/// Gmail can return JSON error envelopes on failure. Only a successful response
/// may be decoded as a history page or counted as a successful send or watch.
pub fn check_api_status(status: u16) -> Result<(), String> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("gmail_push: Gmail API returned HTTP {status}"))
    }
}

/// The last two notification tips for a binding. A repeated delivery of the
/// latest tip replays the same window; the host deduplicates Gmail message IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct HistoryCursor {
    prior: u64,
    latest: u64,
}

pub struct HistoryWindow {
    pub start: u64,
    pub next: Option<HistoryCursor>,
}

impl HistoryCursor {
    pub fn seed(tip: u64) -> Self {
        Self {
            prior: tip,
            latest: tip,
        }
    }

    pub fn window(self, tip: u64) -> Option<HistoryWindow> {
        if tip > self.latest {
            return Some(HistoryWindow {
                start: self.latest,
                next: Some(Self {
                    prior: self.latest,
                    latest: tip,
                }),
            });
        }
        (tip == self.latest && self.prior != self.latest).then_some(HistoryWindow {
            start: self.prior,
            next: None,
        })
    }
}

// ── Gmail API response types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct HistoryResponse {
    pub history: Option<Vec<HistoryRecord>>,
    #[serde(
        default,
        rename = "historyId",
        deserialize_with = "deserialize_history_id"
    )]
    pub history_id: u64,
    #[serde(default, rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryRecord {
    #[serde(default, rename = "messagesAdded")]
    pub messages_added: Vec<MessageAdded>,
}

#[derive(Debug, Deserialize)]
pub struct MessageAdded {
    pub message: MessageRef,
}

#[derive(Debug, Deserialize)]
pub struct MessageRef {
    pub id: String,
}

/// Collect the message IDs added in a History-API page.
pub fn history_message_ids(resp: &HistoryResponse) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(records) = &resp.history {
        for r in records {
            for added in &r.messages_added {
                ids.push(added.message.id.clone());
            }
        }
    }
    ids
}

#[derive(Debug, Deserialize)]
pub struct GmailMessage {
    pub id: String,
    #[serde(default, rename = "threadId")]
    pub thread_id: String,
    #[serde(default)]
    pub snippet: String,
    pub payload: Option<MessagePayload>,
    #[serde(default, rename = "internalDate")]
    pub internal_date: String,
}

#[derive(Debug, Deserialize)]
pub struct MessagePayload {
    #[serde(default)]
    pub headers: Vec<MessageHeader>,
    pub body: Option<MessageBody>,
    #[serde(default)]
    pub parts: Vec<MessagePart>,
    #[serde(default, rename = "mimeType")]
    pub mime_type: String,
}

#[derive(Debug, Deserialize)]
pub struct MessageHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct MessageBody {
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MessagePart {
    #[serde(default, rename = "mimeType")]
    pub mime_type: String,
    pub body: Option<MessageBody>,
    #[serde(default)]
    pub parts: Vec<MessagePart>,
}

// ── Inbound field extraction ──────────────────────────────────────────────

/// The inbound fields extracted from a Gmail message, pre-WIT-lift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundFields {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub thread_ts: Option<String>,
    /// Unix timestamp in **milliseconds** (Gmail `internalDate` is already ms).
    pub timestamp: u64,
}

/// Map a parsed Gmail message to inbound fields. Returns `None` when there is no
/// `From` address. The `content` is `"Subject: <subject>\n\n<body>"` (matching
/// the native channel); no sender allowlist is applied here (the host gates
/// senders via `peer_groups`).
pub fn message_to_inbound(msg: &GmailMessage) -> Option<InboundFields> {
    let from = extract_header(msg, "From").unwrap_or_default();
    let sender_email = extract_email_from_header(&from);
    if sender_email.is_empty() {
        return None;
    }
    let subject = extract_header(msg, "Subject").unwrap_or_default();
    let body = extract_body_text(msg);
    let content = format!("Subject: {subject}\n\n{body}");
    let timestamp = msg.internal_date.trim().parse::<u64>().unwrap_or(0);
    Some(InboundFields {
        id: format!("gmail_{}", msg.id),
        reply_target: sender_email.clone(),
        sender: sender_email,
        content,
        thread_ts: if msg.thread_id.is_empty() {
            None
        } else {
            Some(msg.thread_id.clone())
        },
        timestamp,
    })
}

/// Extract a header value by name (case-insensitive).
pub fn extract_header(msg: &GmailMessage, name: &str) -> Option<String> {
    msg.payload.as_ref().and_then(|p| {
        p.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.clone())
    })
}

/// Extract the plain email address from a `From` header like `"Name <e@x>"`.
pub fn extract_email_from_header(from: &str) -> String {
    if let Some(start) = from.find('<') {
        if let Some(end) = from.rfind('>') {
            if end > start + 1 {
                return from[start + 1..end].to_string();
            }
        }
    }
    from.trim().to_string()
}

/// Strip CR/LF from a header value to prevent header injection.
pub fn sanitize_header_value(value: &str) -> String {
    value.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// Extract the plain-text body: `text/plain` first, then HTML-stripped
/// `text/html`, finally the `snippet`.
pub fn extract_body_text(msg: &GmailMessage) -> String {
    if let Some(payload) = &msg.payload {
        if payload.mime_type == "text/plain" {
            if let Some(text) = decode_body(payload.body.as_ref()) {
                return text;
            }
        }
        if let Some(text) = find_text_in_parts(&payload.parts, "text/plain") {
            return text;
        }
        if let Some(html) = find_text_in_parts(&payload.parts, "text/html") {
            return strip_html(&html);
        }
    }
    msg.snippet.clone()
}

fn find_text_in_parts(parts: &[MessagePart], mime_type: &str) -> Option<String> {
    for part in parts {
        if part.mime_type == mime_type {
            if let Some(text) = decode_body(part.body.as_ref()) {
                return Some(text);
            }
        }
        if let Some(text) = find_text_in_parts(&part.parts, mime_type) {
            return Some(text);
        }
    }
    None
}

/// Decode a base64url (Gmail-style, no padding) message body to a UTF-8 string.
fn decode_body(body: Option<&MessageBody>) -> Option<String> {
    let data = body?.data.as_ref()?;
    let standard = data.replace('-', "+").replace('_', "/");
    let padded = match standard.len() % 4 {
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        _ => standard,
    };
    BASE64
        .decode(&padded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Basic HTML tag stripper with whitespace normalization.
fn strip_html(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ── Outbound send + API bodies/URLs ───────────────────────────────────────

/// Build the URL-safe base64 `raw` RFC 2822 message for `messages.send`.
/// Headers are CRLF-sanitized to prevent injection.
pub fn build_send_raw(recipient: &str, subject: &str, content: &str) -> String {
    let safe_recipient = sanitize_header_value(recipient);
    let safe_subject = sanitize_header_value(subject);
    let rfc2822 = format!(
        "To: {safe_recipient}\r\nSubject: {safe_subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{content}"
    );
    let encoded = BASE64.encode(rfc2822.as_bytes());
    encoded.replace('+', "-").replace('/', "_").replace('=', "")
}

/// The `messages.send` body: `{"raw": <url-safe base64>}`.
pub fn build_send_body(raw: &str) -> Value {
    json!({ "raw": raw })
}

/// The `users.watch` body: `{"topicName": <topic>, "labelIds": <labels>}`.
pub fn build_watch_body(topic: &str, label_filter: &[String]) -> Value {
    json!({ "topicName": topic, "labelIds": label_filter })
}

pub fn send_url() -> String {
    format!("{GMAIL_API}/gmail/v1/users/me/messages/send")
}

pub fn watch_url() -> String {
    format!("{GMAIL_API}/gmail/v1/users/me/watch")
}

pub fn profile_url() -> String {
    format!("{GMAIL_API}/gmail/v1/users/me/profile")
}

pub fn message_url(id: &str) -> String {
    format!("{GMAIL_API}/gmail/v1/users/me/messages/{id}?format=full")
}

/// The History-API URL for `startHistoryId`, with an optional page token.
pub fn history_url(start_history_id: u64, page_token: Option<&str>) -> String {
    let mut url = format!(
        "{GMAIL_API}/gmail/v1/users/me/history?startHistoryId={start_history_id}&historyTypes=messageAdded"
    );
    if let Some(pt) = page_token {
        url.push_str("&pageToken=");
        url.push_str(pt);
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64url(bytes: &[u8]) -> String {
        BASE64
            .encode(bytes)
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "")
    }

    #[test]
    fn unsuccessful_responses_are_rejected_before_history_processing() {
        assert!(check_api_status(200).is_ok());
        assert!(check_api_status(204).is_ok());
        for status in [301, 401, 403, 404, 429, 500] {
            assert!(check_api_status(status).is_err());
        }
    }

    #[test]
    fn a_fresh_webhook_guest_resumes_and_replays_the_committed_window() {
        let seed = HistoryCursor::seed(10);
        assert!(seed.window(10).is_none());
        let first = seed.window(20).unwrap();
        assert_eq!(first.start, 10);
        let saved = serde_json::to_vec(&first.next.unwrap()).unwrap();

        let restored: HistoryCursor = serde_json::from_slice(&saved).unwrap();
        let retry = restored.window(20).unwrap();
        assert_eq!(retry.start, 10);
        assert!(retry.next.is_none());
        assert!(restored.window(9).is_none());
        let later = restored.window(30).unwrap();
        assert_eq!(later.start, 20);
        assert!(later.next.is_some());
    }

    #[test]
    fn rest_history_ids_accept_decimal_strings_and_pubsub_numbers() {
        let rest: HistoryResponse =
            serde_json::from_str(r#"{"historyId":"18446744073709551615"}"#).unwrap();
        assert_eq!(rest.history_id, u64::MAX);
        let push: GmailNotification =
            serde_json::from_str(r#"{"emailAddress":"fixture@example.com","historyId":42}"#)
                .unwrap();
        assert_eq!(push.history_id, 42);
        assert!(serde_json::from_str::<HistoryResponse>(r#"{"historyId":"invalid"}"#).is_err());
    }

    #[test]
    fn config_parses_and_defaults() {
        let cfg = GmailPushConfig::from_json(
            r#"{"topic":"projects/p/topics/t","oauth_token":" tok ","webhook_secret":" s "}"#,
        );
        assert_eq!(cfg.topic, "projects/p/topics/t");
        assert_eq!(cfg.oauth_token(), "tok");
        assert_eq!(cfg.webhook_secret(), "s");
        assert_eq!(cfg.label_filter, vec!["INBOX"]);

        let d = GmailPushConfig::from_json("not json");
        assert!(!d.enabled);
        assert_eq!(d.label_filter, vec!["INBOX"]);
        assert_eq!(d.oauth_token(), "");
    }

    #[test]
    fn bearer_auth() {
        // No secret → accept anything.
        assert!(verify_bearer("", ""));
        assert!(verify_bearer("", "Bearer whatever"));
        // Secret set → must match exactly.
        assert!(verify_bearer("sekret", "Bearer sekret"));
        assert!(!verify_bearer("sekret", "Bearer nope"));
        assert!(!verify_bearer("sekret", "sekret")); // missing Bearer prefix
        assert!(!verify_bearer("sekret", ""));
    }

    #[test]
    fn envelope_and_notification_decode() {
        let payload = json!({"emailAddress":"user@example.com","historyId":12345});
        // Pub/Sub `message.data` is standard base64 (with padding), not URL-safe.
        let data = BASE64.encode(serde_json::to_vec(&payload).unwrap());
        let body = json!({
            "message": {"data": data, "messageId":"m1","publishTime":"2026-03-21T08:00:00Z"},
            "subscription": "projects/p/subscriptions/s"
        });
        let env = parse_envelope(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(env.message.message_id, "m1");
        let n = parse_notification(&env.message).unwrap();
        assert_eq!(n.email_address, "user@example.com");
        assert_eq!(n.history_id, 12345);
    }

    #[test]
    fn notification_rejects_bad_base64_and_json() {
        let bad_b64 = PubSubMessage {
            data: "!!!".into(),
            message_id: String::new(),
            publish_time: String::new(),
        };
        assert!(parse_notification(&bad_b64).is_err());
        let bad_json = PubSubMessage {
            // Valid standard base64, but the decoded bytes are not JSON.
            data: BASE64.encode(b"not json"),
            message_id: String::new(),
            publish_time: String::new(),
        };
        assert!(parse_notification(&bad_json).is_err());
    }

    #[test]
    fn history_ids_collected() {
        let resp: HistoryResponse = serde_json::from_value(json!({
            "history": [
                {"messagesAdded":[{"message":{"id":"a"}},{"message":{"id":"b"}}]},
                {"messagesAdded":[{"message":{"id":"c"}}]}
            ],
            "historyId": 999
        }))
        .unwrap();
        assert_eq!(history_message_ids(&resp), ["a", "b", "c"]);
        assert_eq!(resp.history_id, 999);
        // No history → empty.
        let empty: HistoryResponse = serde_json::from_value(json!({"historyId": 1})).unwrap();
        assert!(history_message_ids(&empty).is_empty());
    }

    #[test]
    fn email_extraction_and_sanitize() {
        assert_eq!(
            extract_email_from_header("John Doe <john@example.com>"),
            "john@example.com"
        );
        assert_eq!(
            extract_email_from_header("user@example.com"),
            "user@example.com"
        );
        assert_eq!(extract_email_from_header(""), "");
        assert_eq!(
            sanitize_header_value("evil@x\r\nBcc: y@z"),
            "evil@xBcc: y@z"
        );
    }

    #[test]
    fn message_to_inbound_plain_and_multipart() {
        // Single-part text/plain.
        let plain: GmailMessage = serde_json::from_value(json!({
            "id":"m1","threadId":"t1","internalDate":"1700000000000",
            "payload":{
                "mimeType":"text/plain",
                "headers":[{"name":"From","value":"A <a@x.com>"},{"name":"Subject","value":"Hi"}],
                "body":{"data": b64url(b"Hello, world!")}
            }
        }))
        .unwrap();
        let inb = message_to_inbound(&plain).unwrap();
        assert_eq!(inb.id, "gmail_m1");
        assert_eq!(inb.sender, "a@x.com");
        assert_eq!(inb.reply_target, "a@x.com");
        assert_eq!(inb.content, "Subject: Hi\n\nHello, world!");
        assert_eq!(inb.thread_ts.as_deref(), Some("t1"));
        assert_eq!(inb.timestamp, 1_700_000_000_000);

        // Multipart HTML → stripped.
        let html: GmailMessage = serde_json::from_value(json!({
            "id":"m2","internalDate":"0",
            "payload":{
                "mimeType":"multipart/alternative",
                "headers":[{"name":"From","value":"b@x.com"}],
                "parts":[{"mimeType":"text/html","body":{"data": b64url(b"<p>Hello <b>W</b></p>")}}]
            }
        }))
        .unwrap();
        let inb2 = message_to_inbound(&html).unwrap();
        assert_eq!(inb2.content, "Subject: \n\nHello W");
        assert_eq!(inb2.thread_ts, None);
    }

    #[test]
    fn message_to_inbound_none_without_from() {
        let msg: GmailMessage = serde_json::from_value(json!({
            "id":"m","internalDate":"0",
            "payload":{"mimeType":"text/plain","headers":[],"body":{"data": b64url(b"x")}}
        }))
        .unwrap();
        assert!(message_to_inbound(&msg).is_none());
    }

    #[test]
    fn body_falls_back_to_snippet() {
        let msg: GmailMessage = serde_json::from_value(json!({
            "id":"m","internalDate":"0","snippet":"snip",
            "payload":{"mimeType":"multipart/mixed","headers":[{"name":"From","value":"a@x"}]}
        }))
        .unwrap();
        assert_eq!(
            message_to_inbound(&msg).unwrap().content,
            "Subject: \n\nsnip"
        );
    }

    #[test]
    fn send_raw_and_bodies() {
        let raw = build_send_raw("to@x.com", "Sub", "Body");
        // Round-trips back to the RFC 2822 message (restore padding + std alphabet).
        let std = raw.replace('-', "+").replace('_', "/");
        let padded = match std.len() % 4 {
            2 => format!("{std}=="),
            3 => format!("{std}="),
            _ => std,
        };
        let decoded = String::from_utf8(BASE64.decode(padded).unwrap()).unwrap();
        assert!(decoded.starts_with("To: to@x.com\r\nSubject: Sub\r\n"));
        assert!(decoded.ends_with("\r\n\r\nBody"));
        assert_eq!(build_send_body("R"), json!({"raw":"R"}));
        assert_eq!(
            build_watch_body("topic", &["INBOX".to_string()]),
            json!({"topicName":"topic","labelIds":["INBOX"]})
        );
    }

    #[test]
    fn urls() {
        assert_eq!(
            send_url(),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
        );
        assert_eq!(
            message_url("abc"),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc?format=full"
        );
        assert_eq!(
            history_url(42, None),
            "https://gmail.googleapis.com/gmail/v1/users/me/history?startHistoryId=42&historyTypes=messageAdded"
        );
        assert_eq!(
            history_url(42, Some("PT")),
            "https://gmail.googleapis.com/gmail/v1/users/me/history?startHistoryId=42&historyTypes=messageAdded&pageToken=PT"
        );
    }
}
