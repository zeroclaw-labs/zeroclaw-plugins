//! Pure Mattermost REST API v4 logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it maps a Mattermost post JSON to the
//! fields the host's inbound message needs, and builds the `createPost` request
//! body. The `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does
//! only the I/O (waki HTTP calls with a `Bearer` token) and reuses this logic
//! verbatim, so the interesting behavior is covered by a plain host
//! `cargo test`.

use serde::Deserialize;
use serde_json::{json, Value};

/// The plugin's config section (`[channels.mattermost.<alias>]` for a mirror, or
/// `[[plugins.entries.mattermost]].config` as a novel plugin). Field names match
/// the native `MattermostConfig` snake_case keys so a mirror plugin can be fed
/// the native section verbatim. Only the fields this plugin uses are
/// declared; serde ignores the rest (login flow, team allowlist, discovery,
/// pacing, …).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MattermostConfig {
    /// Mattermost server URL, e.g. `https://mattermost.example.com`. Required to
    /// reach the API. A trailing slash is trimmed by [`MattermostConfig::base_url`].
    #[serde(default)]
    pub url: String,
    /// Personal access / bot token. Sent as `Authorization: Bearer <token>`.
    /// The native config also supports a `login_id` + `password` login flow;
    /// this plugin only implements the static-token path.
    #[serde(default)]
    pub bot_token: Option<String>,
    /// Channel IDs the bot serves. The plugin currently operates on a single
    /// channel: the first explicit (non-blank, non-`"*"`) entry. An empty list
    /// or a `["*"]` wildcard (native auto-discovery) leaves the plugin inert.
    #[serde(default)]
    pub channel_ids: Vec<String>,
    /// When true (the default), replies thread on the original post; when false,
    /// top-level replies go to the channel root. Existing threads always stay
    /// threaded regardless of this flag.
    #[serde(default)]
    pub thread_replies: Option<bool>,
}

impl MattermostConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// Server origin with any trailing slash trimmed, for consistent path joins.
    pub fn base_url(&self) -> &str {
        self.url.trim_end_matches('/')
    }

    /// The bot token (trimmed), or `""` when unset — the "not configured"
    /// sentinel the shim checks before making any call.
    pub fn token(&self) -> &str {
        self.bot_token.as_deref().unwrap_or("").trim()
    }

    /// The single channel this plugin polls: the first explicit entry in
    /// `channel_ids` (trimmed, skipping blanks and the `"*"` wildcard). `None`
    /// means the operator asked for native auto-discovery, which the plugin does
    /// not implement yet.
    pub fn channel_id(&self) -> Option<String> {
        self.channel_ids
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty() && *s != "*")
            .map(ToString::to_string)
    }

    /// Whether top-level replies should thread on the original post. Defaults to
    /// `true`, matching the native channel's `thread_replies.unwrap_or(true)`.
    pub fn thread_replies(&self) -> bool {
        self.thread_replies.unwrap_or(true)
    }
}

/// A Mattermost post mapped to the host inbound-message fields (the `channel` is
/// always `"mattermost"`, stamped by the host shim).
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

/// `GET /api/v4/users/me` → the bot's `id` (used as `self_handle` and for the
/// self-loop guard; matches the `sender` we stamp from `user_id`).
pub fn parse_self_user_id(response: &Value) -> Option<String> {
    response
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// `GET /api/v4/users/me` → the bot's `@username` mention form, for
/// `self_addressed_mention`.
pub fn parse_self_username(response: &Value) -> Option<String> {
    response
        .get("username")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|u| format!("@{u}"))
}

/// The `create_at` (Unix milliseconds) of a post, or `0` when absent. This is
/// the value tracked as the poll cursor (`?since=`).
pub fn post_create_at(post: &Value) -> i64 {
    post.get("create_at").and_then(Value::as_i64).unwrap_or(0)
}

/// Extract the posts from a `GET /channels/{id}/posts` response as a list sorted
/// oldest-first by `create_at`. The response shape is
/// `{ order: [postId, …], posts: { postId: {…} } }`; we iterate the `posts` map
/// (so thread-context replies not in `order` are included) and sort, mirroring
/// the native channel's `poll_channel`.
pub fn extract_posts(response: &Value) -> Vec<Value> {
    let Some(posts) = response.get("posts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut list: Vec<Value> = posts.values().cloned().collect();
    list.sort_by_key(post_create_at);
    list
}

/// Map one Mattermost post to an [`Inbound`]. Returns `None` for posts this
/// plugin does not deliver: our own posts (`user_id == self_user_id`, the
/// self-loop guard) and empty-body posts (joins, system messages, attachment-
/// only posts the plugin can't transcribe).
///
/// Reply routing mirrors the native channel:
///   - existing thread (`root_id` set)      → `channel_id:root_id`
///   - top-level post + `thread_replies`     → `channel_id:post_id`
///   - top-level post + `!thread_replies`    → `channel_id`
pub fn parse_post(post: &Value, self_user_id: &str, thread_replies: bool) -> Option<Inbound> {
    let id = post
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let channel_id = post
        .get("channel_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let user_id = post.get("user_id").and_then(Value::as_str).unwrap_or("");
    let message = post.get("message").and_then(Value::as_str).unwrap_or("");
    let root_id = post.get("root_id").and_then(Value::as_str).unwrap_or("");
    let create_at = post_create_at(post);

    // Self-loop guard: never re-ingest the bot's own posts.
    if !self_user_id.is_empty() && user_id == self_user_id {
        return None;
    }
    // Skip empty bodies (system posts, joins, attachment-only posts).
    if message.is_empty() {
        return None;
    }

    let reply_target = if !root_id.is_empty() {
        format!("{channel_id}:{root_id}")
    } else if thread_replies {
        format!("{channel_id}:{id}")
    } else {
        channel_id.to_string()
    };

    // The native channel reports `timestamp` in seconds (`create_at / 1000`);
    // mirror that so this plugin and the built-in channel are interchangeable.
    let timestamp = if create_at > 0 {
        (create_at / 1000) as u64
    } else {
        0
    };

    Some(Inbound {
        id: format!("mattermost_{id}"),
        sender: user_id.to_string(),
        reply_target,
        content: message.to_string(),
        channel_alias: None,
        timestamp,
        thread_ts: if root_id.is_empty() {
            None
        } else {
            Some(root_id.to_string())
        },
    })
}

/// Split a `reply_target`/recipient into `(channel_id, root_id)`. A
/// `channel:root` form (a threaded reply) yields `Some(root)`; a bare channel id
/// yields `None`.
pub fn split_recipient(recipient: &str) -> (String, Option<String>) {
    match recipient.split_once(':') {
        Some((channel, root)) => (channel.to_string(), Some(root.to_string())),
        None => (recipient.to_string(), None),
    }
}

/// Build the `POST /api/v4/posts` request body. `root_id` is included only for a
/// threaded reply (non-empty), so a top-level reply omits it.
pub fn build_send_body(channel_id: &str, message: &str, root_id: Option<&str>) -> Value {
    let mut body = json!({ "channel_id": channel_id, "message": message });
    if let Some(root) = root_id.filter(|r| !r.is_empty()) {
        body["root_id"] = json!(root);
    }
    body
}

/// `GET /api/v4/channels/{channel_id}/posts?since={create_at_ms}` — the poll
/// URL. `since` is the max `create_at` (Unix ms) seen so far.
pub fn posts_poll_url(base_url: &str, channel_id: &str, since: i64) -> String {
    format!(
        "{}/api/v4/channels/{}/posts?since={}",
        base_url.trim_end_matches('/'),
        channel_id,
        since
    )
}

/// `POST /api/v4/posts` — the create-post endpoint.
pub fn posts_url(base_url: &str) -> String {
    format!("{}/api/v4/posts", base_url.trim_end_matches('/'))
}

/// `GET /api/v4/users/me` — the bot-identity endpoint.
pub fn me_url(base_url: &str) -> String {
    format!("{}/api/v4/users/me", base_url.trim_end_matches('/'))
}
