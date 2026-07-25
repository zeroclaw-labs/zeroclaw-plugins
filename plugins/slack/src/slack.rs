//! Pure Slack Events API logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin. It owns everything interesting about
//! being a Slack channel:
//!   - config parse (`SlackConfig`),
//!   - the Slack request-signature check (HMAC-SHA256 over the raw webhook
//!     body, with the 5-minute replay window),
//!   - decoding an Events API payload (`url_verification` handshake and
//!     `event_callback` message events) into inbound messages,
//!   - building the `chat.postMessage` body and chunking long text.
//!
//! The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O (waki HTTP calls with a `Bearer` token, `SystemTime::now`) and reuses
//! this logic verbatim, so the security-critical behavior is covered by a plain
//! host `cargo test`.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Slack's documented replay window: reject a request whose
/// `X-Slack-Request-Timestamp` is more than five minutes from now.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 60 * 5;

/// Chunk boundary for outbound text. Slack's `chat.postMessage` `text` field is
/// capped at 40 000 characters; we split a little under that to leave headroom.
pub const MAX_TEXT_CHARS: usize = 39_000;

/// Reserved channel value the host recognizes: a single inbound message with
/// this `channel` means "reply to the HTTP request with `content` as the body
/// and enqueue nothing" (the webhook-challenge convention).
pub const WEBHOOK_REPLY_CHANNEL: &str = "__webhook_reply__";

/// The platform identifier stamped on real inbound events.
pub const CHANNEL: &str = "slack";

/// The plugin's config section (`[channels.slack.<alias>]` for a mirror, or
/// `[[plugins.entries.slack]].config` as a novel plugin). Field names match the
/// native `SlackConfig` snake_case keys where they overlap (`bot_token`), so a
/// mirror plugin can be fed the native section verbatim; `signing_secret` and
/// `api_base_url` are the additional keys this Events-API webhook plugin reads.
/// serde ignores every other native field (Socket Mode, pacing, threading, …).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SlackConfig {
    /// Slack bot OAuth token (`xoxb-…`). Sent as `Authorization: Bearer` on
    /// every `chat.postMessage`. The "not configured" sentinel is `""`.
    #[serde(default)]
    pub bot_token: Option<String>,
    /// Slack app *signing secret* (Basic Information → App Credentials). Used to
    /// verify the `X-Slack-Signature` HMAC over each inbound webhook body. A
    /// blank secret makes `parse_webhook` reject every request.
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// Web API base, default `https://slack.com/api`. Overridable for a proxy or
    /// a test double. A trailing slash is trimmed.
    #[serde(default)]
    pub api_base_url: Option<String>,
}

impl SlackConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// The bot token (trimmed), or `""` when unset — the "not configured"
    /// sentinel the shim checks before making any call.
    pub fn bot_token(&self) -> &str {
        self.bot_token.as_deref().unwrap_or("").trim()
    }

    /// The signing secret (trimmed), or `""` when unset.
    pub fn signing_secret(&self) -> &str {
        self.signing_secret.as_deref().unwrap_or("").trim()
    }

    /// Web API base origin, trailing slash trimmed, defaulting to the public
    /// Slack API host.
    pub fn api_base(&self) -> &str {
        let base = self
            .api_base_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("https://slack.com/api");
        base.trim_end_matches('/')
    }

    /// `POST {api_base}/chat.postMessage` — the send endpoint.
    pub fn post_message_url(&self) -> String {
        format!("{}/chat.postMessage", self.api_base())
    }
}

/// A Slack message event mapped to the host inbound-message fields (the
/// `channel` is stamped by the host shim, always [`CHANNEL`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    /// Unix timestamp in milliseconds (the WIT `inbound-message.timestamp`
    /// unit), derived from the Slack event `ts`.
    pub timestamp: u64,
}

/// The result of decoding one inbound webhook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookOutcome {
    /// A `url_verification` handshake: echo this exact string back in the HTTP
    /// response body (the `__webhook_reply__` convention).
    Challenge(String),
    /// Zero or more real events to enqueue (`channel = "slack"`).
    Messages(Vec<Inbound>),
}

/// Case-insensitive header lookup. Host-supplied headers are already
/// lower-cased, but the compare is defensive.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Compute the Slack request signature `v0=<hex(HMAC-SHA256(secret, base))>`
/// over the base string `v0:<timestamp>:<body>`. Exposed for tests and reused
/// by [`verify_signature`] indirectly; callers verifying should prefer
/// [`verify_signature`] (constant-time compare).
pub fn compute_signature(signing_secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    format!("v0={}", hex::encode(mac.finalize().into_bytes()))
}

/// Verify a Slack webhook's authenticity: the timestamp is within the replay
/// window and the `X-Slack-Signature` HMAC matches (constant-time). `now_secs`
/// is the current Unix time in seconds (injected so this is deterministic in
/// tests). The component maps any failure here to the typed unauthorized
/// rejection (HTTP 401).
pub fn verify_signature(
    signing_secret: &str,
    timestamp_header: &str,
    signature_header: &str,
    body: &[u8],
    now_secs: i64,
) -> Result<(), String> {
    if signing_secret.is_empty() {
        return Err("slack: signing_secret not configured".to_string());
    }
    let ts: i64 = timestamp_header
        .trim()
        .parse()
        .map_err(|_| "slack: X-Slack-Request-Timestamp is not an integer".to_string())?;
    if (now_secs - ts).abs() > MAX_TIMESTAMP_SKEW_SECS {
        return Err("slack: stale request timestamp (replay window exceeded)".to_string());
    }
    let hex_sig = signature_header
        .trim()
        .strip_prefix("v0=")
        .ok_or_else(|| "slack: X-Slack-Signature missing 'v0=' prefix".to_string())?;
    let provided = hex::decode(hex_sig)
        .map_err(|_| "slack: X-Slack-Signature is not valid hex".to_string())?;

    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(b"v0:");
    mac.update(timestamp_header.trim().as_bytes());
    mac.update(b":");
    mac.update(body);
    mac.verify_slice(&provided)
        .map_err(|_| "slack: signature mismatch".to_string())
}

/// Decode a Slack event `ts` (e.g. `"1355517523.000005"`, seconds with a
/// microsecond fraction) into Unix milliseconds. Returns `0` when unparseable.
pub fn ts_to_millis(ts: &str) -> u64 {
    ts.trim()
        .parse::<f64>()
        .ok()
        .filter(|s| s.is_finite() && *s >= 0.0)
        .map(|s| (s * 1000.0) as u64)
        .unwrap_or(0)
}

/// Map the `event` object of an `event_callback` to zero or one [`Inbound`].
/// Emits a message only for a plain user text message: `type == "message"`,
/// non-empty `text`, a `user`, a `channel`, and no `bot_id`/`subtype` (which
/// mark bot posts, edits, joins, file-shares, and other non-conversational
/// events this text-only v0.1.0 plugin skips).
fn parse_event(event: &Value) -> Vec<Inbound> {
    if event.get("type").and_then(Value::as_str) != Some("message") {
        return Vec::new();
    }
    // Bot posts (self-loop guard) and any subtyped message (edits, joins,
    // channel_topic, file_share, …) are skipped.
    if event.get("bot_id").is_some() || event.get("subtype").is_some() {
        return Vec::new();
    }
    let text = event.get("text").and_then(Value::as_str).unwrap_or("");
    if text.is_empty() {
        return Vec::new();
    }
    let Some(user) = event
        .get("user")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Vec::new();
    };
    let Some(channel) = event
        .get("channel")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Vec::new();
    };
    let ts = event.get("ts").and_then(Value::as_str).unwrap_or("");
    let id = if ts.is_empty() {
        format!("slack_{user}_{channel}")
    } else {
        format!("slack_{ts}")
    };
    vec![Inbound {
        id,
        sender: user.to_string(),
        reply_target: channel.to_string(),
        content: text.to_string(),
        timestamp: ts_to_millis(ts),
    }]
}

/// Authenticate a raw Slack webhook. Returns `Ok(false)` for a GET liveness
/// probe and `Ok(true)` for an authenticated POST that should be decoded.
pub fn authenticate_webhook(
    signing_secret: &str,
    headers: &[(String, String)],
    body: &[u8],
    now_secs: i64,
) -> Result<bool, String> {
    // The host passes the request line via reserved lower-cased headers.
    let method = header(headers, "x-webhook-method").unwrap_or("POST");
    if method.eq_ignore_ascii_case("GET") {
        return Ok(false);
    }

    let timestamp = header(headers, "x-slack-request-timestamp")
        .ok_or_else(|| "slack: missing X-Slack-Request-Timestamp header".to_string())?;
    let signature = header(headers, "x-slack-signature")
        .ok_or_else(|| "slack: missing X-Slack-Signature header".to_string())?;
    verify_signature(signing_secret, timestamp, signature, body, now_secs)?;
    Ok(true)
}

/// Decode an already-authenticated Slack webhook body.
pub fn decode_webhook(body: &[u8]) -> Result<WebhookOutcome, String> {
    let payload: Value =
        serde_json::from_slice(body).map_err(|e| format!("slack: invalid JSON body: {e}"))?;

    match payload.get("type").and_then(Value::as_str) {
        Some("url_verification") => {
            let challenge = payload
                .get("challenge")
                .and_then(Value::as_str)
                .ok_or_else(|| "slack: url_verification missing 'challenge'".to_string())?;
            Ok(WebhookOutcome::Challenge(challenge.to_string()))
        }
        Some("event_callback") => {
            let msgs = payload.get("event").map(parse_event).unwrap_or_default();
            Ok(WebhookOutcome::Messages(msgs))
        }
        // url-less retries, app_rate_limited, unknown envelopes → nothing.
        _ => Ok(WebhookOutcome::Messages(Vec::new())),
    }
}

/// Authenticate and decode a raw inbound webhook. The split helpers are also
/// exposed so the WIT shim can preserve the host's typed authentication and
/// payload-rejection boundary.
pub fn parse_webhook(
    signing_secret: &str,
    headers: &[(String, String)],
    body: &[u8],
    now_secs: i64,
) -> Result<WebhookOutcome, String> {
    if !authenticate_webhook(signing_secret, headers, body, now_secs)? {
        return Ok(WebhookOutcome::Messages(Vec::new()));
    }
    decode_webhook(body)
}

/// Build the `chat.postMessage` request body. `thread_ts`, when present and
/// non-empty, threads the reply; otherwise the message posts to the channel
/// root.
pub fn build_send_body(channel: &str, text: &str, thread_ts: Option<&str>) -> Value {
    let mut body = json!({ "channel": channel, "text": text });
    if let Some(ts) = thread_ts.map(str::trim).filter(|s| !s.is_empty()) {
        body["thread_ts"] = json!(ts);
    }
    body
}

/// Split `text` into chunks of at most `max` characters, preferring to break at
/// the last newline (then the last space) inside each window so words and lines
/// stay intact; falls back to a hard character split for an over-long unbroken
/// run. An empty input yields no chunks (nothing to send).
pub fn chunk_text(text: &str, max: usize) -> Vec<String> {
    if text.is_empty() || max == 0 {
        return if text.is_empty() {
            Vec::new()
        } else {
            vec![text.to_string()]
        };
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < chars.len() {
        let hard_end = (start + max).min(chars.len());
        let mut split = hard_end;
        if hard_end < chars.len() {
            // Prefer a newline break, then a space break, strictly after `start`.
            if let Some(pos) = (start..hard_end).rev().find(|&i| chars[i] == '\n') {
                if pos > start {
                    split = pos + 1;
                }
            } else if let Some(pos) = (start..hard_end).rev().find(|&i| chars[i] == ' ') {
                if pos > start {
                    split = pos + 1;
                }
            }
        }
        chunks.push(chars[start..split].iter().collect());
        start = split;
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";

    fn signed_headers(ts: &str, body: &[u8]) -> Vec<(String, String)> {
        vec![
            ("x-webhook-method".to_string(), "POST".to_string()),
            ("x-slack-request-timestamp".to_string(), ts.to_string()),
            (
                "x-slack-signature".to_string(),
                compute_signature(SECRET, ts, body),
            ),
        ]
    }

    // ── config ────────────────────────────────────────────────────────────

    #[test]
    fn config_defaults_when_empty() {
        let cfg = SlackConfig::from_json("");
        assert_eq!(cfg.bot_token(), "");
        assert_eq!(cfg.signing_secret(), "");
        assert_eq!(cfg.api_base(), "https://slack.com/api");
        assert_eq!(
            cfg.post_message_url(),
            "https://slack.com/api/chat.postMessage"
        );
    }

    #[test]
    fn config_defaults_when_malformed() {
        let cfg = SlackConfig::from_json("not json {");
        assert_eq!(cfg.bot_token(), "");
    }

    #[test]
    fn config_parses_and_trims() {
        let cfg = SlackConfig::from_json(
            r#"{"bot_token":"  xoxb-abc  ","signing_secret":" s3cr3t ","api_base_url":"https://proxy.example/api/"}"#,
        );
        assert_eq!(cfg.bot_token(), "xoxb-abc");
        assert_eq!(cfg.signing_secret(), "s3cr3t");
        assert_eq!(cfg.api_base(), "https://proxy.example/api");
        assert_eq!(
            cfg.post_message_url(),
            "https://proxy.example/api/chat.postMessage"
        );
    }

    #[test]
    fn config_ignores_unknown_native_fields() {
        // Fed the native [channels.slack.*] section verbatim: extra keys ignored.
        let cfg = SlackConfig::from_json(
            r#"{"enabled":true,"bot_token":"xoxb-1","app_token":"xapp-1","channel_ids":["C1"],"mention_only":true,"signing_secret":"sek"}"#,
        );
        assert_eq!(cfg.bot_token(), "xoxb-1");
        assert_eq!(cfg.signing_secret(), "sek");
    }

    // ── signature ─────────────────────────────────────────────────────────

    #[test]
    fn signature_round_trip_verifies() {
        let body = br#"{"type":"event_callback"}"#;
        let sig = compute_signature(SECRET, "1531420618", body);
        assert!(sig.starts_with("v0="));
        assert!(verify_signature(SECRET, "1531420618", &sig, body, 1531420620).is_ok());
    }

    #[test]
    fn signature_known_vector() {
        // Slack's own documented example base string + secret.
        let secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        let ts = "1531420618";
        let expected = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
        assert_eq!(compute_signature(secret, ts, body), expected);
        assert!(verify_signature(secret, ts, expected, body, 1531420618).is_ok());
    }

    #[test]
    fn signature_rejects_stale_timestamp() {
        let body = b"{}";
        let sig = compute_signature(SECRET, "1000", body);
        // now is 10 minutes later than the request timestamp.
        let err = verify_signature(SECRET, "1000", &sig, body, 1000 + 600).unwrap_err();
        assert!(err.contains("stale"), "{err}");
    }

    #[test]
    fn signature_rejects_future_timestamp() {
        let body = b"{}";
        let sig = compute_signature(SECRET, "2000", body);
        // now is 10 minutes before the request timestamp.
        let err = verify_signature(SECRET, "2000", &sig, body, 2000 - 600).unwrap_err();
        assert!(err.contains("stale"), "{err}");
    }

    #[test]
    fn signature_rejects_tampered_body() {
        let body = br#"{"type":"event_callback","event":{"text":"hi"}}"#;
        let sig = compute_signature(SECRET, "1531420618", body);
        let tampered = br#"{"type":"event_callback","event":{"text":"HACKED"}}"#;
        assert!(verify_signature(SECRET, "1531420618", &sig, tampered, 1531420618).is_err());
    }

    #[test]
    fn signature_rejects_wrong_secret() {
        let body = b"{}";
        let sig = compute_signature("other-secret", "1531420618", body);
        assert!(verify_signature(SECRET, "1531420618", &sig, body, 1531420618).is_err());
    }

    #[test]
    fn signature_rejects_missing_prefix() {
        let body = b"{}";
        let err = verify_signature(SECRET, "1531420618", "deadbeef", body, 1531420618).unwrap_err();
        assert!(err.contains("v0="), "{err}");
    }

    #[test]
    fn signature_rejects_non_hex() {
        let err = verify_signature(SECRET, "1531420618", "v0=zzzz", b"{}", 1531420618).unwrap_err();
        assert!(err.contains("hex"), "{err}");
    }

    #[test]
    fn signature_rejects_non_numeric_timestamp() {
        let err = verify_signature(SECRET, "notanumber", "v0=ab", b"{}", 1531420618).unwrap_err();
        assert!(err.contains("integer"), "{err}");
    }

    #[test]
    fn signature_rejects_empty_secret() {
        assert!(verify_signature("", "1531420618", "v0=ab", b"{}", 1531420618).is_err());
    }

    // ── parse_webhook ───────────────────────────────────────────────────────

    #[test]
    fn get_probe_returns_empty() {
        let headers = vec![("x-webhook-method".to_string(), "GET".to_string())];
        // No signature headers at all — a GET must not require them.
        let out = parse_webhook(SECRET, &headers, b"", 0).unwrap();
        assert_eq!(out, WebhookOutcome::Messages(Vec::new()));
    }

    #[test]
    fn url_verification_returns_challenge() {
        let ts = "1531420618";
        let body = br#"{"type":"url_verification","challenge":"3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"}"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        assert_eq!(
            out,
            WebhookOutcome::Challenge(
                "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P".to_string()
            )
        );
    }

    #[test]
    fn url_verification_missing_challenge_errs() {
        let ts = "1531420618";
        let body = br#"{"type":"url_verification"}"#;
        let headers = signed_headers(ts, body);
        assert!(parse_webhook(SECRET, &headers, body, 1531420618).is_err());
    }

    #[test]
    fn message_event_maps_to_inbound() {
        let ts = "1531420618";
        let body = br#"{
            "type":"event_callback",
            "event":{
                "type":"message",
                "user":"U123",
                "channel":"C456",
                "text":"hello there",
                "ts":"1531420618.000200"
            }
        }"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        let WebhookOutcome::Messages(msgs) = out else {
            panic!("expected Messages");
        };
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(m.sender, "U123");
        assert_eq!(m.reply_target, "C456");
        assert_eq!(m.content, "hello there");
        assert_eq!(m.id, "slack_1531420618.000200");
        assert_eq!(m.timestamp, 1_531_420_618_000);
    }

    #[test]
    fn bot_message_is_skipped() {
        let ts = "1531420618";
        let body = br#"{"type":"event_callback","event":{"type":"message","user":"U1","channel":"C1","text":"beep","bot_id":"B999","ts":"1.0"}}"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        assert_eq!(out, WebhookOutcome::Messages(Vec::new()));
    }

    #[test]
    fn subtyped_message_is_skipped() {
        let ts = "1531420618";
        let body = br#"{"type":"event_callback","event":{"type":"message","subtype":"message_changed","user":"U1","channel":"C1","text":"edited","ts":"1.0"}}"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        assert_eq!(out, WebhookOutcome::Messages(Vec::new()));
    }

    #[test]
    fn empty_text_message_is_skipped() {
        let ts = "1531420618";
        let body = br#"{"type":"event_callback","event":{"type":"message","user":"U1","channel":"C1","text":"","ts":"1.0"}}"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        assert_eq!(out, WebhookOutcome::Messages(Vec::new()));
    }

    #[test]
    fn non_message_event_is_ignored() {
        let ts = "1531420618";
        let body =
            br#"{"type":"event_callback","event":{"type":"reaction_added","user":"U1","item":{}}}"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        assert_eq!(out, WebhookOutcome::Messages(Vec::new()));
    }

    #[test]
    fn unknown_envelope_type_is_ignored() {
        let ts = "1531420618";
        let body = br#"{"type":"app_rate_limited","minute_rate_limited":1518467820}"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        assert_eq!(out, WebhookOutcome::Messages(Vec::new()));
    }

    #[test]
    fn message_without_user_is_skipped() {
        let ts = "1531420618";
        let body = br#"{"type":"event_callback","event":{"type":"message","channel":"C1","text":"hi","ts":"1.0"}}"#;
        let headers = signed_headers(ts, body);
        let out = parse_webhook(SECRET, &headers, body, 1531420618).unwrap();
        assert_eq!(out, WebhookOutcome::Messages(Vec::new()));
    }

    #[test]
    fn missing_signature_header_errs() {
        let ts = "1531420618";
        let body = br#"{"type":"url_verification","challenge":"x"}"#;
        let headers = vec![
            ("x-webhook-method".to_string(), "POST".to_string()),
            ("x-slack-request-timestamp".to_string(), ts.to_string()),
        ];
        let err = parse_webhook(SECRET, &headers, body, 1531420618).unwrap_err();
        assert!(err.contains("X-Slack-Signature"), "{err}");
    }

    #[test]
    fn missing_timestamp_header_errs() {
        let body = br#"{"type":"url_verification","challenge":"x"}"#;
        let headers = vec![
            ("x-webhook-method".to_string(), "POST".to_string()),
            ("x-slack-signature".to_string(), "v0=ab".to_string()),
        ];
        let err = parse_webhook(SECRET, &headers, body, 1531420618).unwrap_err();
        assert!(err.contains("X-Slack-Request-Timestamp"), "{err}");
    }

    #[test]
    fn invalid_json_after_valid_signature_errs() {
        let ts = "1531420618";
        let body = b"{not valid json";
        let headers = signed_headers(ts, body);
        let err = parse_webhook(SECRET, &headers, body, 1531420618).unwrap_err();
        assert!(err.contains("invalid JSON"), "{err}");
    }

    #[test]
    fn bad_signature_never_reaches_parsing() {
        // A valid url_verification body but a signature over different bytes:
        // must be rejected before the challenge is ever read.
        let ts = "1531420618";
        let body = br#"{"type":"url_verification","challenge":"secret-value"}"#;
        // Sign a *different* body, so the signature mismatches the one received.
        let headers = signed_headers(ts, br#"{"type":"url_verification","challenge":"other"}"#);
        assert!(parse_webhook(SECRET, &headers, body, 1531420618).is_err());
    }

    // ── ts_to_millis ────────────────────────────────────────────────────────

    #[test]
    fn ts_to_millis_conversions() {
        assert_eq!(ts_to_millis("1531420618.000200"), 1_531_420_618_000);
        assert_eq!(ts_to_millis("0.000000"), 0);
        assert_eq!(ts_to_millis(""), 0);
        assert_eq!(ts_to_millis("garbage"), 0);
    }

    // ── build_send_body ─────────────────────────────────────────────────────

    #[test]
    fn send_body_basic() {
        let b = build_send_body("C123", "hello", None);
        assert_eq!(b["channel"], "C123");
        assert_eq!(b["text"], "hello");
        assert!(b.get("thread_ts").is_none());
    }

    #[test]
    fn send_body_threaded() {
        let b = build_send_body("C123", "hi", Some("1531420618.000200"));
        assert_eq!(b["thread_ts"], "1531420618.000200");
    }

    #[test]
    fn send_body_ignores_blank_thread() {
        let b = build_send_body("C123", "hi", Some("   "));
        assert!(b.get("thread_ts").is_none());
    }

    // ── chunk_text ──────────────────────────────────────────────────────────

    #[test]
    fn chunk_short_text_single() {
        assert_eq!(chunk_text("hello", 100), vec!["hello".to_string()]);
    }

    #[test]
    fn chunk_empty_is_none() {
        assert!(chunk_text("", 100).is_empty());
    }

    #[test]
    fn chunk_breaks_on_newline() {
        // max small enough to force a split; prefer the newline boundary.
        let text = "line one\nline two\nline three";
        let chunks = chunk_text(text, 12);
        // Every chunk within the limit, reassembly is lossless.
        assert!(chunks.iter().all(|c| c.chars().count() <= 12));
        assert_eq!(chunks.concat(), text);
        assert!(chunks.len() >= 2);
        // First break lands right after the first newline.
        assert_eq!(chunks[0], "line one\n");
    }

    #[test]
    fn chunk_breaks_on_space_when_no_newline() {
        let text = "aaaa bbbb cccc dddd";
        let chunks = chunk_text(text, 10);
        assert!(chunks.iter().all(|c| c.chars().count() <= 10));
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn chunk_hard_splits_unbroken_run() {
        let text = "x".repeat(25);
        let chunks = chunk_text(&text, 10);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].chars().count(), 10);
        assert_eq!(chunks[1].chars().count(), 10);
        assert_eq!(chunks[2].chars().count(), 5);
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn chunk_respects_char_boundaries() {
        // Multi-byte chars must not be split mid-codepoint.
        let text = "é".repeat(25);
        let chunks = chunk_text(&text, 10);
        assert!(chunks.iter().all(|c| c.chars().count() <= 10));
        assert_eq!(chunks.concat(), text);
    }
}
