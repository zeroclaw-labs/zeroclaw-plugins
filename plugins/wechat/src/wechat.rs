//! Pure WeChat iLink Bot API logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it maps an iLink `getupdates`
//! message to the fields the host's inbound message needs, and builds the
//! `getupdates` / `sendmessage` / `getconfig` request bodies. The
//! `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! I/O (blocking `waki` HTTP calls with the iLink `Bearer` token) and reuses
//! this logic verbatim, so the interesting behavior is covered by a plain host
//! `cargo test`.

use serde::Deserialize;
use serde_json::{Value, json};

/// Default iLink Bot API origin.
pub const DEFAULT_API_BASE_URL: &str = "https://ilinkai.weixin.qq.com";
/// Default iLink CDN origin (media up/download).
pub const DEFAULT_CDN_BASE_URL: &str = "https://novac2c.cdn.weixin.qq.com/c2c";
/// Reported in every request's `base_info.channel_version`; kept in sync with
/// the manifest / plugin version.
pub const CHANNEL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// iLink message item type: text.
pub const ITEM_TYPE_TEXT: u64 = 1;
/// iLink message item type: voice (carries a transcription in `voice_item.text`).
pub const ITEM_TYPE_VOICE: u64 = 3;
/// iLink Bot outbound `message_type`.
pub const MESSAGE_TYPE_BOT: u64 = 2;
/// iLink Bot outbound `message_state` (finished / complete).
pub const MESSAGE_STATE_FINISH: u64 = 2;
/// Session-expired error code returned by the iLink API (`ret`/`errcode`).
pub const SESSION_EXPIRED_ERRCODE: i64 = -14;

/// The plugin's config section (`[channels.wechat.<alias>]` for a mirror, or
/// `[[plugins.entries.wechat]].config` as a novel plugin). Field names match the
/// native `WeChatConfig` snake_case keys so a mirror plugin can be fed the native
/// section verbatim; serde ignores the fields this plugin does not use
/// (`enabled`, `excluded_tools`, `state_dir`).
///
/// `bot_token` is the one field the native config does *not* carry: the native
/// channel obtains its iLink session token via an interactive QR-code login and
/// persists it to `state_dir/account.json`. That flow (render a QR to a TTY,
/// long-poll for the phone scan) cannot run inside the wasm sandbox, so an
/// operator supplies the already-established token here (see README). It is an
/// extra optional key — a native mirror section without it simply leaves the
/// plugin unsessioned, and `poll`/`send` behave accordingly.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WeChatConfig {
    /// Whether this channel is active (host-side gate; the plugin does not act
    /// on it, but it is accepted so the native section deserializes).
    #[serde(default)]
    pub enabled: bool,
    /// Override the iLink API base URL. Defaults to [`DEFAULT_API_BASE_URL`].
    #[serde(default)]
    pub api_base_url: Option<String>,
    /// Override the iLink CDN base URL. Defaults to [`DEFAULT_CDN_BASE_URL`].
    #[serde(default)]
    pub cdn_base_url: Option<String>,
    /// Directory the native channel persists token/cursor to. Unused by the
    /// sandboxed plugin (no filesystem); accepted for native-section parity.
    #[serde(default)]
    pub state_dir: Option<String>,
    /// Tools excluded from this channel's tool spec (host-side; accepted for
    /// native-section parity).
    #[serde(default)]
    pub excluded_tools: Vec<String>,
    /// iLink Bot session token (`bot_token`) obtained via a one-time native
    /// QR-code login. Plugin-only key; empty means "no session" (see struct
    /// docs). When present, all API calls are authorized with `Bearer <token>`.
    #[serde(default)]
    pub bot_token: String,
}

impl WeChatConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// The iLink API origin with any trailing slash trimmed, falling back to the
    /// public host when unset or blank.
    pub fn api_base(&self) -> String {
        resolve_base(self.api_base_url.as_deref(), DEFAULT_API_BASE_URL)
    }

    /// The iLink CDN origin with any trailing slash trimmed, falling back to the
    /// public CDN when unset or blank.
    pub fn cdn_base(&self) -> String {
        resolve_base(self.cdn_base_url.as_deref(), DEFAULT_CDN_BASE_URL)
    }

    /// The trimmed session token (may be empty).
    pub fn token(&self) -> &str {
        self.bot_token.trim()
    }

    /// Whether an iLink session token is configured — the "not configured"
    /// sentinel the shim checks before making any authorized call.
    pub fn has_session(&self) -> bool {
        !self.token().is_empty()
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

/// An iLink message mapped to the host inbound-message fields (the `channel` is
/// always `"wechat"`, stamped by the host shim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub channel_alias: Option<String>,
    /// Unix timestamp in milliseconds (`create_time_ms` verbatim).
    pub timestamp: u64,
    pub thread_ts: Option<String>,
}

/// Build the `base_info` object attached to every iLink request body.
pub fn base_info(channel_version: &str) -> Value {
    json!({ "channel_version": channel_version })
}

/// Build the `/ilink/bot/getupdates` request body. `longpoll_timeout_ms` is a
/// best-effort hint asking the server for a short (or immediate, when `0`) hold
/// so a blocking poll never stalls an interleaved `send`.
pub fn build_getupdates_body(cursor: &str, longpoll_timeout_ms: u64, channel_version: &str) -> Value {
    json!({
        "get_updates_buf": cursor,
        "longpolling_timeout_ms": longpoll_timeout_ms,
        "base_info": base_info(channel_version),
    })
}

/// Build the `/ilink/bot/sendmessage` request body for a single text item.
/// `context_token` scopes the reply to the inbound conversation (empty when
/// unknown); `client_id` is a per-send idempotency key.
pub fn build_send_body(
    to: &str,
    text: &str,
    context_token: &str,
    client_id: &str,
    channel_version: &str,
) -> Value {
    json!({
        "msg": {
            "from_user_id": "",
            "to_user_id": to,
            "client_id": client_id,
            "message_type": MESSAGE_TYPE_BOT,
            "message_state": MESSAGE_STATE_FINISH,
            "item_list": [
                { "type": ITEM_TYPE_TEXT, "text_item": { "text": text } }
            ],
            "context_token": context_token,
        },
        "base_info": base_info(channel_version),
    })
}

/// Build the `/ilink/bot/getconfig` request body used as a lightweight health
/// probe (empty user).
pub fn build_getconfig_body(channel_version: &str) -> Value {
    json!({
        "ilink_user_id": "",
        "context_token": "",
        "base_info": base_info(channel_version),
    })
}

/// The significant API error code in a response, or `None` when the call
/// succeeded. iLink reports failure in either `ret` or `errcode`; a non-zero
/// value in either is an error.
pub fn response_error_code(response: &Value) -> Option<i64> {
    let ret = response.get("ret").and_then(Value::as_i64).unwrap_or(0);
    let errcode = response.get("errcode").and_then(Value::as_i64).unwrap_or(0);
    if ret != 0 {
        Some(ret)
    } else if errcode != 0 {
        Some(errcode)
    } else {
        None
    }
}

/// Whether an error code means the iLink session has expired (the token must be
/// dropped and re-established via QR login).
pub fn is_session_expired(code: i64) -> bool {
    code == SESSION_EXPIRED_ERRCODE
}

/// The next `get_updates_buf` cursor from a `getupdates` response, when the
/// server advanced it (non-empty).
pub fn next_cursor(response: &Value) -> Option<String> {
    response
        .get("get_updates_buf")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The ordered `msgs` array from a `getupdates` response (empty when absent).
pub fn extract_msgs(response: &Value) -> Vec<Value> {
    response
        .get("msgs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The `from_user_id` of a message, when present and non-empty.
pub fn sender_id(msg: &Value) -> Option<String> {
    msg.get("from_user_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The `context_token` carried on a message, when present and non-empty. Cached
/// per sender by the shim so a later `send` can associate its reply.
pub fn context_token_of(msg: &Value) -> Option<String> {
    msg.get("context_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Extract the text content of an iLink message's `item_list`. Handles text
/// items (with an optional quoted-`ref_msg` prefix) and voice transcriptions;
/// returns an empty string when no textual item is found.
pub fn extract_text_from_items(items: &[Value]) -> String {
    for item in items {
        let item_type = item.get("type").and_then(Value::as_u64).unwrap_or(0);
        match item_type {
            ITEM_TYPE_TEXT => {
                if let Some(text) = item
                    .get("text_item")
                    .and_then(|ti| ti.get("text"))
                    .and_then(Value::as_str)
                {
                    let ref_prefix = match item.get("ref_msg") {
                        Some(ref_msg) => {
                            let title =
                                ref_msg.get("title").and_then(Value::as_str).unwrap_or("");
                            if title.is_empty() {
                                String::new()
                            } else {
                                format!("[引用: {title}]\n")
                            }
                        }
                        None => String::new(),
                    };
                    return format!("{ref_prefix}{text}");
                }
            }
            ITEM_TYPE_VOICE => {
                if let Some(text) = item
                    .get("voice_item")
                    .and_then(|vi| vi.get("text"))
                    .and_then(Value::as_str)
                    .filter(|t| !t.is_empty())
                {
                    return text.to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// Map one `getupdates` message to an [`Inbound`]. Returns `None` when the
/// message has no sender or no textual content (this plugin delivers text
/// only; media items are skipped). WeChat conversations are 1:1, so both the
/// `sender` and the `reply_target` are the peer's `from_user_id`.
pub fn parse_message(msg: &Value, channel_alias: Option<&str>) -> Option<Inbound> {
    let from = sender_id(msg)?;

    let items = msg
        .get("item_list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let content = extract_text_from_items(&items);
    if content.is_empty() {
        return None;
    }

    let create_time_ms = msg.get("create_time_ms").and_then(Value::as_u64).unwrap_or(0);
    let id = msg
        .get("message_id")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(str::to_string))
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("wechat_{from}_{create_time_ms}"));

    Some(Inbound {
        id,
        sender: from.clone(),
        reply_target: from,
        content,
        channel_alias: channel_alias.map(str::to_string),
        timestamp: create_time_ms,
        thread_ts: None,
    })
}

/// Lightweight Markdown → plain-text pass (WeChat renders no Markdown). A
/// dependency-free subset of the native channel's converter: it drops fenced
/// code-block markers (keeping the code), strips leading heading / blockquote /
/// bullet markers, and removes inline emphasis markers (`**`, `__`, `~~`,
/// backtick). Text with no Markdown is returned essentially unchanged.
pub fn to_plain_text(text: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut in_code = false;

    for raw in text.lines() {
        if raw.trim_start().starts_with("```") {
            in_code = !in_code;
            continue; // drop the fence line itself, keep the fenced content
        }
        if in_code {
            lines.push(raw.to_string());
            continue;
        }

        let mut line = raw.to_string();

        // Leading heading markers: `#`..`######` followed by a space.
        if let Some(rest) = strip_heading(line.trim_start()) {
            line = rest;
        }
        // Leading blockquote marker.
        {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix("> ").or_else(|| t.strip_prefix('>')) {
                line = rest.to_string();
            }
        }
        // Leading unordered-list bullet.
        {
            let t = line.trim_start();
            for marker in ["- ", "* ", "+ "] {
                if let Some(rest) = t.strip_prefix(marker) {
                    line = rest.to_string();
                    break;
                }
            }
        }
        // Inline emphasis markers.
        line = line
            .replace("**", "")
            .replace("__", "")
            .replace("~~", "")
            .replace('`', "");

        lines.push(line);
    }

    let mut result = lines.join("\n");
    while result.contains("\n\n\n") {
        result = result.replace("\n\n\n", "\n\n");
    }
    result.trim().to_string()
}

/// Strip a leading ATX heading marker (`#` × 1..=6 then a space) from an already
/// left-trimmed line, returning the heading text; `None` when the line is not a
/// heading.
fn strip_heading(s: &str) -> Option<String> {
    let hashes = s.bytes().take_while(|&b| b == b'#').count();
    if hashes == 0 || hashes > 6 {
        return None;
    }
    let rest = &s[hashes..];
    if rest.is_empty() || rest.starts_with(' ') {
        Some(rest.trim_start().to_string())
    } else {
        None
    }
}

/// Standard-alphabet Base64 encoder (with `=` padding), dependency-free. Used to
/// format the `X-WECHAT-UIN` client header the way the native channel does.
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// A random-ish `X-WECHAT-UIN` header value: `base64(decimal(seed as u32))`,
/// mirroring the native channel (which base64-encodes a random `u32`). The shim
/// derives `seed` from the wall clock + a per-request counter.
pub fn wechat_uin(seed: u64) -> String {
    let n = (seed as u32).to_string();
    base64_encode(n.as_bytes())
}
