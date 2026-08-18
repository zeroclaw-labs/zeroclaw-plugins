//! Pure Mochat REST logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it maps a Mochat message-receive JSON
//! payload to the fields the host's inbound message needs, and builds the
//! `message/send` request body. The `#[cfg(target_family = "wasm")]` component
//! shim in `lib.rs` does only the I/O (waki HTTP calls) and reuses this logic
//! verbatim, so the interesting behavior is covered by a plain host
//! `cargo test`.
//!
//! Endpoints (all relative to the configured `api_url`, matching the native
//! `MochatChannel`):
//!   * `GET  {api_url}/api/message/receive[?since_id=<id>]` — poll for messages.
//!   * `POST {api_url}/api/message/send`                    — send a text reply.
//!   * `GET  {api_url}/api/health`                          — reachability probe.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{json, Value};

/// The plugin's config section (`[channels.mochat.<alias>]` for a mirror, or
/// `[[plugins.entries.mochat]].config` as a novel plugin). Field names are the
/// snake_case keys the host serializes and match the native `MochatConfig`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MochatConfig {
    /// Whether this channel is active. Carried for parity with the native
    /// config; the host decides whether to load the channel.
    #[serde(default)]
    pub enabled: bool,
    /// Mochat API base URL (self-hosted). Required to reach the service; a
    /// trailing slash is trimmed by [`MochatConfig::base_url`].
    #[serde(default)]
    pub api_url: String,
    /// Mochat API token, sent as an `Authorization: Bearer` credential.
    #[serde(default)]
    pub api_token: String,
    /// Poll interval in seconds for new messages (host-side pacing). Default: 5.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Tools excluded from this channel's tool spec (host-side concern; carried
    /// for parity with the native config).
    #[serde(default)]
    pub excluded_tools: Vec<String>,
}

fn default_poll_interval() -> u64 {
    5
}

impl MochatConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        // Malformed input falls back to an empty object so serde field defaults
        // (e.g. poll_interval_secs) apply rather than the all-zero derive default.
        serde_json::from_str(config_json)
            .or_else(|_| serde_json::from_str("{}"))
            .unwrap_or_default()
    }

    /// The API origin with any trailing slash removed (matches the native
    /// channel's `trim_end_matches('/')`).
    pub fn base_url(&self) -> &str {
        self.api_url.trim_end_matches('/')
    }

    /// Whether both the URL and token are present. When either is missing the
    /// plugin stays inert (poll returns `None`, send errors) instead of hitting
    /// the network.
    pub fn has_credentials(&self) -> bool {
        !self.api_url.is_empty() && !self.api_token.is_empty()
    }
}

/// A Mochat message mapped to the host inbound-message fields (the `channel` is
/// always `"mochat"`, stamped by the host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    /// Unix timestamp when present on the message; `0` means "unknown" and the
    /// component shim stamps the current time.
    pub timestamp: u64,
}

/// Build the `GET .../api/message/receive` URL, appending `?since_id=<id>` when
/// a cursor from a prior poll is present (mirrors the native poller).
pub fn receive_url(base_url: &str, since_id: Option<&str>) -> String {
    match since_id {
        Some(id) if !id.is_empty() => format!("{base_url}/api/message/receive?since_id={id}"),
        _ => format!("{base_url}/api/message/receive"),
    }
}

/// Build the `POST .../api/message/send` URL.
pub fn send_url(base_url: &str) -> String {
    format!("{base_url}/api/message/send")
}

/// Build the `GET .../api/health` URL.
pub fn health_url(base_url: &str) -> String {
    format!("{base_url}/api/health")
}

/// Extract the ordered list of message objects from a `message/receive`
/// response. The native channel accepts either a `data` or a `messages` array;
/// anything else yields an empty list.
pub fn extract_messages(response: &Value) -> Vec<Value> {
    response
        .get("data")
        .or_else(|| response.get("messages"))
        .and_then(Value::as_array)
        .map(|arr| arr.to_vec())
        .unwrap_or_default()
}

/// The platform message id used for deduplication and the poll cursor:
/// `messageId` or `id`, else the empty string (the native channel treats an
/// empty id as "not deduplicated / do not advance the cursor").
pub fn message_id(msg: &Value) -> String {
    msg.get("messageId")
        .or_else(|| msg.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Optional Unix timestamp carried on a message, if the server includes one.
/// The native channel ignores this and stamps `now()`; the component shim does
/// the same when this returns `0`.
fn message_timestamp(msg: &Value) -> u64 {
    for key in ["timestamp", "createTime", "sendTime", "time"] {
        if let Some(ts) = msg.get(key).and_then(Value::as_u64) {
            return ts;
        }
    }
    0
}

/// Map one Mochat message to an [`Inbound`], replicating the native inbound
/// field mapping exactly:
///   * sender      = `fromUserId` or `sender`, else `"unknown"`.
///   * content     = `content.text` or `content` (as a bare string), trimmed.
///   * reply_target= the sender (replies route back to the originating user).
///
/// Returns `None` when the trimmed content is empty (the native poller skips
/// such messages), so the poll loop simply drops them.
pub fn parse_message(msg: &Value) -> Option<Inbound> {
    let sender = msg
        .get("fromUserId")
        .or_else(|| msg.get("sender"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let content = msg
        .get("content")
        .and_then(|c| c.get("text").and_then(Value::as_str).or_else(|| c.as_str()))
        .unwrap_or("")
        .trim()
        .to_string();

    if content.is_empty() {
        return None;
    }

    let timestamp = message_timestamp(msg);
    let mid = message_id(msg);
    let id = if mid.is_empty() {
        format!("mochat_{sender}_{timestamp}")
    } else {
        mid
    };

    Some(Inbound {
        id,
        sender: sender.clone(),
        reply_target: sender,
        content,
        timestamp,
    })
}

/// Build the `message/send` request body (native shape):
/// `{ "toUserId": <recipient>, "msgType": "text", "content": { "text": <text> } }`.
pub fn build_send_body(recipient: &str, content: &str) -> Value {
    json!({
        "toUserId": recipient,
        "msgType": "text",
        "content": { "text": content },
    })
}

/// Whether a `message/send` response indicates success. The native channel
/// accepts `code == 0` or `code == 200`; a missing/other code is a failure.
pub fn is_send_ok(response: &Value) -> bool {
    let code = response.get("code").and_then(Value::as_i64).unwrap_or(-1);
    code == 0 || code == 200
}

/// A human-readable error for a failed `message/send`, using the response's
/// `msg` or `message` field (matching the native error text).
pub fn send_error(response: &Value) -> String {
    let code = response.get("code").and_then(Value::as_i64).unwrap_or(-1);
    let msg = response
        .get("msg")
        .or_else(|| response.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("unknown error");
    format!("mochat API error (code={code}): {msg}")
}

/// Capacity of the message-dedup set before half of it is evicted (matches the
/// native `DEDUP_CAPACITY`).
pub const DEDUP_CAPACITY: usize = 10_000;

/// A bounded set of already-seen message ids, mirroring the native channel's
/// deduplication so a server that does not honor `since_id` never re-delivers a
/// message. An empty id is never considered a duplicate (and is not tracked).
#[derive(Debug, Default)]
pub struct DedupSet {
    seen: HashSet<String>,
}

impl DedupSet {
    /// Return `true` if `id` was already seen; otherwise record it and return
    /// `false`. When the set is full, half of it is evicted first (same policy
    /// as the native channel).
    pub fn is_duplicate(&mut self, id: &str) -> bool {
        if id.is_empty() {
            return false;
        }
        if self.seen.contains(id) {
            return true;
        }
        if self.seen.len() >= DEDUP_CAPACITY {
            let to_remove: Vec<String> =
                self.seen.iter().take(DEDUP_CAPACITY / 2).cloned().collect();
            for key in to_remove {
                self.seen.remove(&key);
            }
        }
        self.seen.insert(id.to_string());
        false
    }
}
