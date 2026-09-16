//! Pure Telegram Bot API logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it maps a Telegram `Update` JSON to
//! the fields the host's inbound message needs, and builds the `sendMessage`
//! request body. The `#[cfg(target_family = "wasm")]` component shim in
//! `lib.rs` does only the I/O (waki HTTP calls) and reuses this logic verbatim,
//! so the interesting behavior is covered by a plain host `cargo test`.

use serde::Deserialize;
use serde_json::{json, Value};

/// The plugin's config section (`[channels.telegram.<alias>]` for a mirror, or
/// `[[plugins.entries.telegram]].config` as a novel plugin). Field names are the
/// snake_case keys the host serializes.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TelegramConfig {
    /// Bot API token from @BotFather. Required to reach the API.
    #[serde(default)]
    pub bot_token: String,
    /// API origin, overridable for a local Bot API server or a test mock.
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    /// Allow-list of usernames / numeric ids. `["*"]` allows anyone; empty
    /// denies everyone. A sender is allowed if any of its identities matches.
    #[serde(default)]
    pub allowed_users: Vec<String>,
    /// Optional Telegram `parse_mode` (e.g. `"HTML"`, `"MarkdownV2"`). When
    /// unset, message text is sent verbatim as plain text (safest default).
    #[serde(default)]
    pub parse_mode: Option<String>,
}

fn default_api_base_url() -> String {
    "https://api.telegram.org".to_string()
}

impl TelegramConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }
}

/// A Telegram message mapped to the host inbound-message fields (the `channel`
/// is always `"telegram"`, stamped by the host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub channel_alias: Option<String>,
    pub timestamp: u64,
    pub thread_ts: Option<String>,
}

/// Map one Telegram `Update` to an [`Inbound`]. Returns `None` for updates this
/// plugin does not handle (no `message`, or a non-text message), so the poll
/// loop simply skips them. `message` and `edited_message` are both accepted.
pub fn parse_update(update: &Value) -> Option<Inbound> {
    let msg = update
        .get("message")
        .or_else(|| update.get("edited_message"))?;

    let text = msg.get("text").and_then(Value::as_str)?.to_string();

    let chat_id = msg.get("chat")?.get("id").and_then(Value::as_i64)?;
    let message_id = msg.get("message_id").and_then(Value::as_i64)?;
    let date = msg.get("date").and_then(Value::as_u64).unwrap_or(0);
    let thread_id = msg.get("message_thread_id").and_then(Value::as_i64);

    let sender = msg
        .get("from")
        .map(|from| {
            from.get("username")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    from.get("id")
                        .and_then(Value::as_i64)
                        .map(|id| id.to_string())
                })
                .unwrap_or_else(|| "unknown".to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Forum-topic messages route to a thread-scoped target so replies land in
    // the same topic; plain chats use the bare chat id.
    let reply_target = match thread_id {
        Some(t) => format!("{chat_id}:{t}"),
        None => chat_id.to_string(),
    };

    Some(Inbound {
        id: format!("telegram_{chat_id}_{message_id}"),
        sender,
        reply_target,
        content: text,
        channel_alias: None,
        timestamp: date,
        thread_ts: thread_id.map(|t| t.to_string()),
    })
}

/// The next `getUpdates` offset that acknowledges everything up to `update_id`.
pub fn next_offset(update_id: i64) -> i64 {
    update_id + 1
}

/// Whether `identities` (e.g. `[username, numeric_id]`) is permitted by
/// `allowlist`. `["*"]` allows anyone; an empty list denies everyone; otherwise
/// an entry matches after trimming and stripping a leading `@`.
pub fn is_user_allowed(identities: &[String], allowlist: &[String]) -> bool {
    if allowlist.iter().any(|a| a.trim() == "*") {
        return true;
    }
    let norm = |s: &str| s.trim().trim_start_matches('@').to_ascii_lowercase();
    let allowed: Vec<String> = allowlist.iter().map(|a| norm(a)).collect();
    identities.iter().any(|id| allowed.contains(&norm(id)))
}

/// Split a `reply_target`/recipient into `(chat_id, thread_id)`; a `chat:thread`
/// form (forum topic) yields a `Some(thread)`.
pub fn split_recipient(recipient: &str) -> (String, Option<String>) {
    match recipient.split_once(':') {
        Some((chat, thread)) => (chat.to_string(), Some(thread.to_string())),
        None => (recipient.to_string(), None),
    }
}

/// Build the `sendMessage` request body. `parse_mode` is included only when the
/// operator configured one (default: plain text — no `parse_mode`). A thread id
/// becomes `message_thread_id` so replies land in the right forum topic.
pub fn build_send_payload(
    chat_id: &str,
    text: &str,
    thread: Option<&str>,
    parse_mode: Option<&str>,
) -> Value {
    let mut body = json!({ "chat_id": chat_id, "text": text });
    if let Some(mode) = parse_mode.filter(|m| !m.is_empty()) {
        body["parse_mode"] = json!(mode);
    }
    if let Some(t) = thread.and_then(|t| t.parse::<i64>().ok()) {
        body["message_thread_id"] = json!(t);
    }
    body
}

/// Telegram caps a message at 4096 UTF-16 code units; we split conservatively on
/// character count, preferring paragraph then line boundaries, so a long agent
/// reply is delivered as several messages instead of being rejected.
pub fn chunk_text(text: &str, max: usize) -> Vec<String> {
    if text.chars().count() <= max {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for line in text.split_inclusive('\n') {
        if current.chars().count() + line.chars().count() > max && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
        }
        // A single line longer than `max` is hard-split by chars.
        if line.chars().count() > max {
            let mut buf = String::new();
            for ch in line.chars() {
                if buf.chars().count() + 1 > max {
                    chunks.push(std::mem::take(&mut buf));
                }
                buf.push(ch);
            }
            current.push_str(&buf);
        } else {
            current.push_str(line);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Extract the ordered updates from a `getUpdates` response, as
/// `(update_id, Update)` pairs; `ok: false` or a missing `result` yields empty.
pub fn extract_updates(response: &Value) -> Vec<(i64, Value)> {
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Vec::new();
    }
    response
        .get("result")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|u| {
                    u.get("update_id")
                        .and_then(Value::as_i64)
                        .map(|id| (id, u.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}
