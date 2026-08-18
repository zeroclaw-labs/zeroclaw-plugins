//! Pure Reddit OAuth2 API logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it maps a Reddit `message/unread`
//! inbox item to the fields the host's inbound message needs, builds the token
//! request's HTTP Basic header, and classifies a `send` recipient into a comment
//! reply vs. a DM. The `#[cfg(target_family = "wasm")]` component shim in
//! `lib.rs` does only the I/O (waki HTTP calls with the `Bearer` token) and
//! reuses this logic verbatim, so the interesting behavior is covered by a plain
//! host `cargo test`.

use serde::Deserialize;
use serde_json::Value;

/// The plugin's config section (`[channels.reddit.<alias>]` for a mirror, or
/// `[[plugins.entries.reddit]].config` as a novel plugin). Field names match the
/// native `RedditConfig` snake_case keys so a mirror plugin can be fed the native
/// section verbatim; serde ignores the fields this plugin does not use
/// (`enabled`, `excluded_tools`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RedditConfig {
    /// Reddit OAuth2 client ID (the "web app"/"script" app id). Required.
    #[serde(default)]
    pub client_id: String,
    /// Reddit OAuth2 client secret. Sent with `client_id` as HTTP Basic auth to
    /// the token endpoint. Required.
    #[serde(default)]
    pub client_secret: String,
    /// Reddit OAuth2 refresh token for persistent access. Exchanged for a
    /// short-lived access token via the `refresh_token` grant. Required.
    #[serde(default)]
    pub refresh_token: String,
    /// Reddit bot username (without the `u/` prefix). Used for the self-loop
    /// guard (inbox items authored by the bot are dropped) and as the bot's
    /// self-handle.
    #[serde(default)]
    pub username: String,
    /// Subreddits to accept items from (without the `r/` prefix). Empty accepts
    /// items from any subreddit the bot has access to; DMs (which carry no
    /// subreddit) are always accepted.
    #[serde(default)]
    pub subreddits: Vec<String>,
}

impl RedditConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// Whether the three OAuth2 credentials are present — the "not configured"
    /// sentinel the shim checks before making any call.
    pub fn has_credentials(&self) -> bool {
        !self.client_id.trim().is_empty()
            && !self.client_secret.is_empty()
            && !self.refresh_token.is_empty()
    }
}

/// A Reddit inbox item mapped to the host inbound-message fields (the `channel`
/// is always `"reddit"`, stamped by the host shim).
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

/// OAuth2 + REST endpoints.
pub const REDDIT_API_BASE: &str = "https://oauth.reddit.com";
pub const REDDIT_TOKEN_URL: &str = "https://www.reddit.com/api/v1/access_token";
/// Reddit requires a descriptive, unique `User-Agent` on every request.
pub const USER_AGENT: &str = concat!(
    "zeroclaw:channel:v",
    env!("CARGO_PKG_VERSION"),
    " (by /u/zeroclaw-bot)"
);
/// Inbox items fetched per poll. Small so a poll stays cheap and never stalls
/// `send`; Reddit caps clients at 60 requests/minute so we do a single short
/// poll per `poll_message`.
pub const UNREAD_LIMIT: u32 = 25;

/// Build the `Authorization: Basic <base64(client_id:client_secret)>` header
/// value the token endpoint requires.
pub fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    let raw = format!("{client_id}:{client_secret}");
    format!("Basic {}", base64_encode(raw.as_bytes()))
}

/// Standard (RFC 4648) base64 with `=` padding. Hand-rolled to keep the plugin's
/// dependency set to `serde`/`serde_json`/`waki` — the token endpoint's HTTP
/// Basic header is the only place we need it.
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The form fields for the `refresh_token` grant sent to the token endpoint.
pub fn token_form(refresh_token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
    ]
}

/// Extract the `access_token` from a token-endpoint response. Returns `None`
/// when it is absent or empty (an error response like `{"error":...}`), so the
/// shim surfaces a clear failure instead of caching a blank token.
pub fn parse_token_response(response: &Value) -> Option<String> {
    let token = response.get("access_token").and_then(Value::as_str)?;
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Extract each inbox listing child's `data` object from a `message/unread`
/// response (`{data:{children:[{kind,data:{…}}]}}`). Missing/malformed shapes
/// yield an empty vec.
pub fn extract_children(response: &Value) -> Vec<Value> {
    response
        .get("data")
        .and_then(|d| d.get("children"))
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|c| c.get("data").cloned()).collect())
        .unwrap_or_default()
}

/// The Reddit fullname (`t1_…`, `t4_…`) of an inbox item, used to mark it read.
/// `None` when absent/empty.
pub fn item_fullname(item: &Value) -> Option<String> {
    item.get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Join fullnames into the comma-separated `id` the `api/read_message` endpoint
/// expects.
pub fn join_fullnames(fullnames: &[String]) -> String {
    fullnames.join(",")
}

/// Whether a `send` recipient is a Reddit fullname (a comment/post/message
/// thing) rather than a username. A fullname routes to `api/comment` (a threaded
/// reply); a bare username routes to `api/compose` (a DM). Mirrors the native
/// channel's `t1_`/`t3_`/`t4_` prefix check.
pub fn is_thing_fullname(recipient: &str) -> bool {
    recipient.starts_with("t1_") || recipient.starts_with("t3_") || recipient.starts_with("t4_")
}

/// Map one Reddit inbox item's `data` object to an [`Inbound`]. Returns `None`
/// for items this plugin does not deliver, mirroring the native channel:
///   - items authored by the bot itself (self-loop guard),
///   - items with an empty author or empty body,
///   - items from a subreddit outside the allow-list (when one is configured;
///     DMs, which carry no subreddit, are always accepted).
///
/// `reply_target` is the parent fullname for a comment reply (so the reply is
/// threaded onto the right comment) and the author's username for a DM (so the
/// reply is a DM back). `thread_ts` carries the parent fullname when present.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn parse_item(item: &Value, username: &str, subreddits: &[String]) -> Option<Inbound> {
    let author = item.get("author").and_then(Value::as_str).unwrap_or("");
    let body = item.get("body").and_then(Value::as_str).unwrap_or("");
    let name = item.get("name").and_then(Value::as_str).unwrap_or("");

    // Skip messages from ourselves, and items missing an author or body.
    if author.eq_ignore_ascii_case(username) || author.is_empty() || body.is_empty() {
        return None;
    }

    // If a subreddit allow-list is set, skip items from other subreddits. Items
    // without a subreddit (e.g. DMs) are always accepted.
    if !subreddits.is_empty() {
        if let Some(item_sub) = item.get("subreddit").and_then(Value::as_str) {
            if !subreddits
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(item_sub))
            {
                return None;
            }
        }
    }

    let parent_id = item.get("parent_id").and_then(Value::as_str);
    let message_type = item.get("type").and_then(Value::as_str);

    // Comment replies reply to the parent thing; DMs reply to the author.
    let reply_target = if message_type == Some("comment_reply") || parent_id.is_some() {
        parent_id.unwrap_or(name).to_string()
    } else {
        author.to_string()
    };

    let created = item
        .get("created_utc")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let timestamp = if created < 0.0 { 0 } else { created as u64 };

    Some(Inbound {
        id: format!("reddit_{name}"),
        sender: author.to_string(),
        reply_target,
        content: body.to_string(),
        channel_alias: None,
        timestamp,
        thread_ts: parent_id.map(str::to_string),
    })
}
