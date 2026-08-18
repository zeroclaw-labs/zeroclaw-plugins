//! Pure X/Twitter API v2 logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it maps a `GET /users/{id}/mentions`
//! response to the fields the host's inbound message needs, builds the
//! `POST /tweets` request body, and derives the poll URLs. The
//! `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the I/O
//! (waki HTTP calls, OAuth2 Bearer header) and reuses this logic verbatim, so
//! the interesting behavior is covered by a plain host `cargo test`.

use serde::Deserialize;
use serde_json::{json, Value};

/// The plugin's config section (`[channels.twitter.<alias>]` for a mirror, or
/// `[[plugins.entries.twitter]].config` as a novel plugin). Field names are the
/// snake_case keys the host serializes — `bearer_token`, `enabled`, and
/// `excluded_tools` mirror the native `TwitterConfig` so a mirror plugin is fed
/// the same section unchanged.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TwitterConfig {
    /// Twitter API v2 Bearer Token (OAuth 2.0). Required to reach the API.
    #[serde(default)]
    pub bearer_token: String,
    /// Whether the operator enabled this channel. The host decides whether to
    /// load the plugin; kept here only so the native section deserializes
    /// cleanly.
    #[serde(default)]
    pub enabled: bool,
    /// API origin, overridable for a test mock. Defaults to the X v2 base.
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    /// Allow-list of author ids / usernames. `["*"]` allows anyone; empty means
    /// no plugin-level gating. A sender is allowed if any of its identities
    /// matches. (Native gating is done host-side via peer groups; this is an
    /// optional plugin-level filter.)
    #[serde(default)]
    pub allowed_users: Vec<String>,
    /// Tools excluded from this channel's tool spec (host-side concern; carried
    /// only so the native section deserializes cleanly).
    #[serde(default)]
    pub excluded_tools: Vec<String>,
}

fn default_api_base_url() -> String {
    "https://api.x.com/2".to_string()
}

impl TwitterConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }
}

/// A mention tweet mapped to the host inbound-message fields (the `channel` is
/// always `"twitter"`, stamped by the host).
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

/// `GET /users/me` → the authenticated bot's numeric user id (`data.id`).
pub fn parse_self_id(response: &Value) -> Option<String> {
    response
        .get("data")?
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// `GET /users/me` → the bot's `@handle` from `data.username`, when present.
pub fn parse_self_handle(response: &Value) -> Option<String> {
    response
        .get("data")?
        .get("username")
        .and_then(Value::as_str)
        .map(|u| format!("@{u}"))
}

/// Build the `GET /users/me` URL.
pub fn build_self_url(api_base_url: &str) -> String {
    format!("{}/users/me", api_base_url.trim_end_matches('/'))
}

/// Build the mentions-poll URL for `user_id`, requesting `author_id` and
/// `created_at` on each tweet and paginating from `since_id` when known.
pub fn build_mentions_url(api_base_url: &str, user_id: &str, since_id: Option<&str>) -> String {
    let mut url = format!(
        "{}/users/{}/mentions?tweet.fields=author_id,created_at&max_results=20",
        api_base_url.trim_end_matches('/'),
        user_id
    );
    if let Some(id) = since_id.filter(|s| !s.is_empty()) {
        url.push_str("&since_id=");
        url.push_str(id);
    }
    url
}

/// Build the `POST /tweets` URL.
pub fn build_tweets_url(api_base_url: &str) -> String {
    format!("{}/tweets", api_base_url.trim_end_matches('/'))
}

/// Map a `GET /users/{id}/mentions` response's `data[]` to [`Inbound`]s in
/// chronological (oldest-first) order, so buffering + `pop_front` delivers them
/// in the order they were posted. The API returns newest-first, so the list is
/// reversed. A missing/empty `data` yields an empty vec (e.g. `ok`-less error
/// bodies or a poll with nothing new).
pub fn parse_mentions(response: &Value) -> Vec<Inbound> {
    let Some(arr) = response.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<Inbound> = arr.iter().filter_map(parse_tweet).collect();
    out.reverse();
    out
}

/// Map one tweet object (`{id, text, author_id, created_at}`) to an [`Inbound`].
/// Returns `None` when it lacks an id or text. `sender` is the `author_id`;
/// `reply_target` is the tweet id (a reply is threaded via `in_reply_to_tweet_id`
/// in [`build_tweet_body`]).
fn parse_tweet(tweet: &Value) -> Option<Inbound> {
    let id = tweet.get("id").and_then(Value::as_str)?.to_string();
    let text = tweet.get("text").and_then(Value::as_str)?.to_string();
    let author_id = tweet
        .get("author_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    Some(Inbound {
        id: id.clone(),
        sender: author_id,
        reply_target: id,
        content: text,
        channel_alias: None,
        // The X API reports `created_at` as an RFC3339 string, not an epoch;
        // the host stamps its own receive time, so this is left 0 rather than
        // pull in a date parser for the pure core.
        timestamp: 0,
        thread_ts: None,
    })
}

/// The `meta.newest_id` cursor from a mentions response, used to advance
/// `since_id` so the next poll only returns tweets newer than this batch.
pub fn newest_id(response: &Value) -> Option<String> {
    response
        .get("meta")?
        .get("newest_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Fallback cursor when `meta.newest_id` is absent: the numerically largest
/// tweet id in `data[]`. Tweet ids are monotonic snowflakes, so max-by-value is
/// "most recent".
pub fn max_tweet_id(response: &Value) -> Option<String> {
    response
        .get("data")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|t| t.get("id").and_then(Value::as_str))
        .max_by_key(|id| id.parse::<u128>().unwrap_or(0))
        .map(str::to_string)
}

/// Derive the cursor to advance to after a poll: prefer `meta.newest_id`, else
/// the largest tweet id seen. `None` leaves the cursor unchanged.
pub fn advance_cursor(response: &Value) -> Option<String> {
    newest_id(response).or_else(|| max_tweet_id(response))
}

/// Extract the created tweet id (`data.id`) from a `POST /tweets` response, used
/// to chain a multi-tweet reply thread. `None` (or empty) signals the create
/// failed.
pub fn created_tweet_id(response: &Value) -> Option<String> {
    response
        .get("data")?
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Normalize a `reply_target`/recipient into the tweet id to reply to. Accepts
/// a bare id (what this plugin emits) or a `tweet:{id}` form (the native
/// recipient convention). An empty recipient yields `None`, posting a
/// standalone tweet.
pub fn reply_id_from_recipient(recipient: &str) -> Option<String> {
    let id = recipient.strip_prefix("tweet:").unwrap_or(recipient).trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

/// Build the `POST /tweets` request body: `{text}` plus a
/// `reply.in_reply_to_tweet_id` when replying.
pub fn build_tweet_body(text: &str, reply_to: Option<&str>) -> Value {
    let mut body = json!({ "text": text });
    if let Some(id) = reply_to.filter(|s| !s.is_empty()) {
        body["reply"] = json!({ "in_reply_to_tweet_id": id });
    }
    body
}

/// Whether `identities` (e.g. `[author_id]`) is permitted by `allowlist`.
/// `["*"]` allows anyone; an empty list denies everyone (callers only gate when
/// the list is non-empty); otherwise an entry matches after trimming and
/// stripping a leading `@`, case-insensitively.
pub fn is_user_allowed(identities: &[String], allowlist: &[String]) -> bool {
    if allowlist.iter().any(|a| a.trim() == "*") {
        return true;
    }
    let norm = |s: &str| s.trim().trim_start_matches('@').to_ascii_lowercase();
    let allowed: Vec<String> = allowlist.iter().map(|a| norm(a)).collect();
    identities.iter().any(|id| allowed.contains(&norm(id)))
}

/// A tweet is capped at 280 characters; split a long agent reply into
/// tweet-sized pieces (posted as a self-reply thread by the shim), preferring
/// whitespace boundaries. All characters are preserved, so the concatenation of
/// the chunks equals the input; an over-long single word is hard-split by char.
pub fn chunk_tweet(text: &str, max: usize) -> Vec<String> {
    if text.chars().count() <= max {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for word in text.split_inclusive(char::is_whitespace) {
        if current.chars().count() + word.chars().count() > max && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
        }
        if word.chars().count() > max {
            // A single word longer than `max` is hard-split by chars.
            let mut buf = std::mem::take(&mut current);
            for ch in word.chars() {
                if buf.chars().count() + 1 > max {
                    chunks.push(std::mem::take(&mut buf));
                }
                buf.push(ch);
            }
            current = buf;
        } else {
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Tweet character cap for `POST /tweets`.
pub const TWEET_MAX_CHARS: usize = 280;
