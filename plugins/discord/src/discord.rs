//! Pure Discord Gateway protocol logic: no wasm, no HTTP, no WebSocket.
//!
//! Everything here is deterministic: config parsing, gateway frame parsing,
//! the IDENTIFY/RESUME/HEARTBEAT payload builders, the MESSAGE_CREATE filter,
//! message chunking, REST response classification, the delivery rules for a
//! reply, the [`ChannelChecks`] schedule, and the [`Gateway`] state machine
//! that decides when to discover, dial, handshake, heartbeat, back off, or
//! park. The component shim in `lib.rs` performs the I/O those decisions call
//! for and feeds the results back, so this module is covered by a plain host
//! `cargo test` without a live Discord connection.
//!
//! No type here holds the bot token. The token is an argument of the payload
//! builders only, so the shim reads it from the host at the point of use and
//! drops it as soon as the payload or request is built.

use std::collections::VecDeque;

use serde_json::{json, Value};

/// Discord REST and Gateway API version pinned by this plugin.
pub const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

/// Discord's per-message content limit, in characters.
pub const MAX_MESSAGE_CHARS: usize = 2000;

/// Heartbeat interval used when a Hello omits `heartbeat_interval`.
pub const DEFAULT_HEARTBEAT_MS: u64 = 41_250;

/// Discord's epoch, 2015-01-01T00:00:00Z, in Unix milliseconds.
pub const DISCORD_EPOCH_MS: u64 = 1_420_070_400_000;

// ── Gateway intents (API v10 bit positions) ──────────────────────────────────

pub const INTENT_GUILDS: u64 = 1 << 0;
pub const INTENT_GUILD_MEMBERS: u64 = 1 << 1;
pub const INTENT_GUILD_PRESENCES: u64 = 1 << 8;
pub const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
pub const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
pub const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;

/// The IDENTIFY intents used when `intents_mask` is unset: guild and direct
/// messages with their content (37376).
///
/// The built-in channel also requests `GUILDS` (37377). This plugin never reads
/// guild topology, and a large guild's `GUILD_CREATE` can exceed the host's
/// WebSocket frame limit, so it leaves `GUILDS` out. Set `intents_mask` to
/// request it.
pub const DEFAULT_INTENTS: u64 =
    INTENT_GUILD_MESSAGES | INTENT_DIRECT_MESSAGES | INTENT_MESSAGE_CONTENT;

// ── Gateway opcodes ──────────────────────────────────────────────────────────

const OP_DISPATCH: u64 = 0;
const OP_HEARTBEAT: u64 = 1;
const OP_RECONNECT: u64 = 7;
const OP_INVALID_SESSION: u64 = 9;
const OP_HELLO: u64 = 10;
const OP_HEARTBEAT_ACK: u64 = 11;

// ── Gateway timing ───────────────────────────────────────────────────────────

/// Reconnect backoff: doubles from the floor to the ceiling, and resets when a
/// session is established (READY or RESUMED).
pub const BACKOFF_FLOOR_MS: u64 = 1_000;
pub const BACKOFF_CEILING_MS: u64 = 60_000;

/// Minimum spacing between two IDENTIFYs.
pub const IDENTIFY_SPACING_MS: u64 = 5_000;

/// Spacing between IDENTIFYs once discovery reports this many or fewer
/// session starts left in Discord's daily budget.
pub const LOW_BUDGET_IDENTIFY_SPACING_MS: u64 = 300_000;
pub const LOW_IDENTIFY_BUDGET: u64 = 100;

/// At most this many IDENTIFYs in any rolling hour (960 a day, under Discord's
/// 1,000), whether or not discovery has reported the daily budget.
pub const MAX_IDENTIFIES_PER_HOUR: usize = 40;
pub const IDENTIFY_WINDOW_MS: u64 = 3_600_000;

/// How long to hold IDENTIFY when the daily budget is exhausted and discovery
/// did not say when it resets.
pub const EXHAUSTED_BUDGET_WAIT_MS: u64 = 3_600_000;

/// Delay before reconnecting after an invalid session (op 9).
pub const INVALID_SESSION_WAIT_MS: u64 = 1_000;

/// A connection that sends no Hello within this long after the dial, or
/// establishes no session within the second limit after its Hello, is dropped.
pub const HELLO_TIMEOUT_MS: u64 = 20_000;
pub const SESSION_TIMEOUT_MS: u64 = 60_000;

/// After an oversized frame the next attempt waits at least this long, and
/// this many oversized frames park the instance.
pub const OVERSIZE_FLOOR_MS: u64 = 30_000;
pub const OVERSIZE_STRIKES: u32 = 3;

/// A parked instance probes after the first delay, doubling up to the ceiling
/// on every further park.
pub const PARK_FIRST_PROBE_MS: u64 = 60_000;
pub const PARK_MAX_PROBE_MS: u64 = 1_800_000;

/// A misconfigured instance retries this often.
pub const MISCONFIGURED_RETRY_MS: u64 = 60_000;

/// A session that lasts this long resets the reconnect backoff, and its first
/// server-requested reconnect is immediate.
pub const SESSION_SETTLED_MS: u64 = 10_000;

/// A session that stays established this long clears the oversize strikes and
/// the park probe delay.
pub const STABLE_SESSION_MS: u64 = 600_000;

// ── Reply timing ─────────────────────────────────────────────────────────────

/// No reply request starts later than this into a send. Each request is
/// bounded by the shim's own timeouts, so a send ends inside the host's
/// default 30 s call deadline.
pub const SEND_START_BUDGET_MS: u64 = 15_000;

/// Pause between the parts of a long reply.
pub const CHUNK_SPACING_MS: u64 = 500;

/// A rate-limited part is retried once when Discord asks for a wait this
/// short.
pub const MAX_RATE_LIMIT_WAIT_MS: u64 = 2_000;

// ── Config ───────────────────────────────────────────────────────────────────

/// The public part of one instance's config, as `config.get` returns it.
///
/// The host has already validated the object against the manifest's closed
/// schema. The `bot_token` property is `x-secret`, so it never appears here;
/// the shim reads it with `secrets.get` at the point of use.
#[derive(Clone, Debug, PartialEq)]
pub struct DiscordConfig {
    pub guild_ids: Vec<String>,
    pub channel_ids: Vec<String>,
    pub listen_to_bots: bool,
    pub mention_only: bool,
    pub intents_mask: Option<u64>,
    /// REST and gateway-discovery base. Defaults to [`DISCORD_API_BASE`].
    pub api_base: String,
    /// Gateway base to dial instead of discovering one through
    /// `GET /gateway/bot`. A session's `resume_gateway_url` still wins on a
    /// resume.
    pub gateway_url: Option<String>,
}

impl Default for DiscordConfig {
    fn default() -> Self {
        Self {
            guild_ids: Vec::new(),
            channel_ids: Vec::new(),
            listen_to_bots: false,
            mention_only: false,
            intents_mask: None,
            api_base: DISCORD_API_BASE.to_string(),
            gateway_url: None,
        }
    }
}

impl DiscordConfig {
    /// Parse the public config object returned by `config.get`. Accepts
    /// everything the manifest schema accepts.
    pub fn from_public_json(s: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(s).map_err(|_| "discord: config is not valid JSON".to_string())?;
        let object = value
            .as_object()
            .ok_or_else(|| "discord: config is not a JSON object".to_string())?;
        let api_base = match object.get("api_base") {
            None | Some(Value::Null) => DISCORD_API_BASE.to_string(),
            Some(Value::String(base)) if is_http_url(base) => {
                base.trim_end_matches('/').to_string()
            }
            Some(_) => return Err("discord: api_base must be an http or https URL".to_string()),
        };
        let gateway_url = match object.get("gateway_url") {
            None | Some(Value::Null) => None,
            Some(Value::String(url)) if is_ws_url(url) => Some(url.clone()),
            Some(_) => return Err("discord: gateway_url must be a ws or wss URL".to_string()),
        };
        Ok(Self {
            guild_ids: id_list(object.get("guild_ids"), "guild_ids")?,
            channel_ids: id_list(object.get("channel_ids"), "channel_ids")?,
            listen_to_bots: flag(object.get("listen_to_bots"), "listen_to_bots")?,
            mention_only: flag(object.get("mention_only"), "mention_only")?,
            intents_mask: match object.get("intents_mask") {
                None | Some(Value::Null) => None,
                Some(mask) => Some(whole_number(mask).ok_or_else(|| {
                    "discord: intents_mask must be a non-negative integer".to_string()
                })?),
            },
            api_base,
            gateway_url,
        })
    }

    /// The IDENTIFY intents: `intents_mask` verbatim when set (including `0`),
    /// otherwise [`DEFAULT_INTENTS`].
    pub fn intents(&self) -> u64 {
        self.intents_mask.unwrap_or(DEFAULT_INTENTS)
    }
}

/// A JSON integer, including one written with a zero fraction (`37376.0`),
/// which JSON Schema also counts as an integer.
fn whole_number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let float = value.as_f64()?;
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let whole = (float.fract() == 0.0 && (0.0..=u64::MAX as f64).contains(&float))
            .then_some(float as u64);
        whole
    })
}

fn id_list(value: Option<&Value>, field: &str) -> Result<Vec<String>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("discord: {field} must be an array of Discord ids"))?;
    items
        .iter()
        .map(|item| match item.as_str() {
            Some(id) if is_decimal_id(id) => Ok(id.to_string()),
            _ => Err(format!("discord: {field} must be an array of Discord ids")),
        })
        .collect()
}

fn flag(value: Option<&Value>, field: &str) -> Result<bool, String> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(format!("discord: {field} must be true or false")),
    }
}

fn is_http_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://")) && !s.contains(char::is_whitespace)
}

fn is_ws_url(s: &str) -> bool {
    (s.starts_with("ws://") || s.starts_with("wss://")) && !s.contains(char::is_whitespace)
}

// ── Outbound gateway payloads ────────────────────────────────────────────────

/// IDENTIFY (op 2): a fresh session with the token and intents. Single shard,
/// no presence, the same properties as the built-in channel.
pub fn build_identify(token: &str, intents: u64) -> String {
    json!({
        "op": 2,
        "d": {
            "token": token,
            "intents": intents,
            "properties": { "os": "linux", "browser": "zeroclaw", "device": "zeroclaw" }
        }
    })
    .to_string()
}

/// RESUME (op 6): replay a dropped session from the last sequence received.
pub fn build_resume(token: &str, session_id: &str, seq: i64) -> String {
    json!({ "op": 6, "d": { "token": token, "session_id": session_id, "seq": seq } }).to_string()
}

/// HEARTBEAT (op 1): `d` is the last sequence received, or `null` before any.
pub fn build_heartbeat(seq: Option<i64>) -> String {
    json!({ "op": 1, "d": seq }).to_string()
}

/// The REST body for a plain text message.
pub fn build_send_body(content: &str) -> Value {
    json!({ "content": content })
}

/// The gateway WebSocket URL for a base returned by discovery, a session's
/// resume URL, or the `gateway_url` setting.
pub fn gateway_ws_url(base: &str) -> String {
    format!("{}/?v=10&encoding=json", base.trim_end_matches('/'))
}

/// The host of a URL, for log lines: no scheme, path, query, or credentials.
pub fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
}

/// An `http` or `https` URL split the way `wasi:http` takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTarget {
    pub https: bool,
    pub authority: String,
    /// The path and query, `/` when the URL has neither.
    pub path_with_query: String,
}

/// Split an `http` or `https` URL for `wasi:http`. `None` for any other
/// scheme, an empty host, or embedded credentials.
pub fn split_http_url(url: &str) -> Option<HttpTarget> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else {
        (false, url.strip_prefix("http://")?)
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') || authority.contains('#') {
        return None;
    }
    let path_with_query = match tail {
        "" => "/".to_string(),
        tail if tail.starts_with('?') => format!("/{tail}"),
        tail => tail.to_string(),
    };
    Some(HttpTarget {
        https,
        authority: authority.to_string(),
        path_with_query: path_with_query.split('#').next().unwrap_or("/").to_string(),
    })
}

// ── Inbound gateway frames ───────────────────────────────────────────────────

/// A decoded gateway frame: opcode, dispatch type (op 0 only), sequence, and
/// payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub op: u64,
    pub t: Option<String>,
    pub s: Option<i64>,
    pub d: Value,
}

/// Parse one gateway text frame. Non-JSON input yields `None` and is skipped.
pub fn parse_frame(text: &str) -> Option<Frame> {
    let value: Value = serde_json::from_str(text).ok()?;
    Some(Frame {
        op: value.get("op").and_then(Value::as_u64)?,
        t: value.get("t").and_then(Value::as_str).map(String::from),
        s: value.get("s").and_then(Value::as_i64),
        d: value.get("d").cloned().unwrap_or(Value::Null),
    })
}

/// A message bound for the host, before it is lifted to the WIT type.
#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    /// `discord_<message id>`, the id format of the built-in channel.
    pub id: String,
    /// The author's user id.
    pub sender: String,
    /// The channel id to reply into: a guild channel, thread, or DM channel.
    pub reply_target: String,
    /// The message text, trimmed.
    pub content: String,
    /// When the message was created, in Unix milliseconds, from its id.
    pub timestamp_ms: u64,
}

/// Conversational message types: DEFAULT (0) and REPLY (19), as in the
/// built-in channel.
fn is_conversational_type(message_type: u64) -> bool {
    matches!(message_type, 0 | 19)
}

/// Whether `content` mentions the bot as `<@id>` or `<@!id>`.
pub fn contains_bot_mention(content: &str, bot_user_id: &str) -> bool {
    !bot_user_id.is_empty()
        && (content.contains(&format!("<@{bot_user_id}>"))
            || content.contains(&format!("<@!{bot_user_id}>")))
}

/// Filter a MESSAGE_CREATE payload and map it to an [`Inbound`], or `None`
/// when it is dropped.
///
/// The gates follow the built-in channel, in order: a conversational type; a
/// message id; an author that is not the bot itself; other bots and webhooks
/// only with `listen_to_bots`; the guild allowlist (DMs pass); the channel
/// allowlist (a direct match, without the built-in channel's thread-parent
/// lookup); the mention gate (guild messages only); and non-empty content.
/// Which senders may reach the agent is decided by the host's peer groups.
pub fn message_create_to_inbound(
    d: &Value,
    cfg: &DiscordConfig,
    bot_user_id: &str,
) -> Option<Inbound> {
    let message_type = d.get("type").and_then(Value::as_u64).unwrap_or(0);
    if !is_conversational_type(message_type) {
        return None;
    }
    let id = d
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| is_snowflake(id))?;
    let author = d.get("author");
    let author_id = author
        .and_then(|a| a.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if author_id.is_empty() || author_id == bot_user_id {
        return None;
    }
    let from_bot = author
        .and_then(|a| a.get("bot"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if from_bot && !cfg.listen_to_bots {
        return None;
    }
    let guild_id = d.get("guild_id").and_then(Value::as_str);
    if let Some(guild_id) = guild_id {
        if !cfg.guild_ids.is_empty() && !cfg.guild_ids.iter().any(|g| g == guild_id) {
            return None;
        }
    }
    let channel_id = d.get("channel_id").and_then(Value::as_str).unwrap_or("");
    if !cfg.channel_ids.is_empty()
        && !channel_id.is_empty()
        && !cfg.channel_ids.iter().any(|c| c == channel_id)
    {
        return None;
    }
    let content = d.get("content").and_then(Value::as_str).unwrap_or("");
    if cfg.mention_only && guild_id.is_some() && !contains_bot_mention(content, bot_user_id) {
        return None;
    }
    let content = content.trim();
    if content.is_empty() {
        return None;
    }
    Some(Inbound {
        id: format!("discord_{id}"),
        sender: author_id.to_string(),
        reply_target: if channel_id.is_empty() {
            author_id.to_string()
        } else {
            channel_id.to_string()
        },
        content: content.to_string(),
        timestamp_ms: snowflake_ms(id).unwrap_or(0),
    })
}

/// The bot's own user id from a READY payload.
pub fn ready_user_id(d: &Value) -> Option<String> {
    d.get("user")
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str)
        .filter(|id| is_snowflake(id))
        .map(String::from)
}

fn string_at(d: &Value, key: &str) -> Option<String> {
    d.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

// ── Snowflakes, recipients, chunking ─────────────────────────────────────────

/// 1 to 20 ASCII digits: what the manifest schema admits for a Discord id.
pub fn is_decimal_id(s: &str) -> bool {
    (1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `s` is a Discord id: a decimal id that fits in a `u64`.
pub fn is_snowflake(s: &str) -> bool {
    is_decimal_id(s) && s.parse::<u64>().is_ok()
}

/// The creation time encoded in a Discord id, in Unix milliseconds.
pub fn snowflake_ms(id: &str) -> Option<u64> {
    let id: u64 = id.parse().ok()?;
    Some((id >> 22) + DISCORD_EPOCH_MS)
}

/// The channel a send targets: the message's recipient, or the first
/// configured `channel_ids` entry when the recipient is empty, as in the
/// built-in channel. The target must be a Discord id, because it becomes a
/// path segment of the REST URL.
pub fn effective_recipient<'a>(
    recipient: &'a str,
    channel_ids: &'a [String],
) -> Result<&'a str, String> {
    let target = if recipient.is_empty() {
        channel_ids.first().map(String::as_str).ok_or_else(|| {
            "discord: the message has no recipient and channel_ids is empty".to_string()
        })?
    } else {
        recipient
    };
    if is_snowflake(target) {
        Ok(target)
    } else {
        Err("discord: the recipient is not a Discord channel id".to_string())
    }
}

/// Split `content` into chunks of at most `max_chars` characters, as the
/// built-in channel does: break after the last newline in the window when it
/// is at least half way in, otherwise after the last space, otherwise at the
/// limit. Empty content yields no chunks.
pub fn chunk_text(content: &str, max_chars: usize) -> Vec<String> {
    if content.is_empty() {
        return Vec::new();
    }
    let max_chars = max_chars.max(1);
    let mut chunks = Vec::new();
    let mut remaining = content;
    while !remaining.is_empty() {
        let hard_split = remaining
            .char_indices()
            .nth(max_chars)
            .map_or(remaining.len(), |(index, _)| index);
        let end = if hard_split == remaining.len() {
            hard_split
        } else {
            let window = &remaining[..hard_split];
            match window.rfind('\n') {
                Some(newline) if window[..newline].chars().count() >= max_chars / 2 => newline + 1,
                _ => window.rfind(' ').map_or(hard_split, |space| space + 1),
            }
        };
        chunks.push(remaining[..end].to_string());
        remaining = &remaining[end..];
    }
    chunks
}

// ── Bot id from token ────────────────────────────────────────────────────────

/// The bot's user id, decoded from its token: the first `.` segment is the
/// base64 of the ASCII id. Accepts the standard and URL-safe alphabets, with
/// or without padding.
pub fn bot_user_id_from_token(token: &str) -> Option<String> {
    let segment = token.split('.').next()?;
    let bytes = base64_decode(segment)?;
    let id = String::from_utf8(bytes).ok()?;
    is_snowflake(&id).then_some(id)
}

/// Minimal base64 decoder, so the core needs no extra dependency.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn sextet(b: u8) -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => u32::from(b - b'A'),
            b'a'..=b'z' => u32::from(b - b'a') + 26,
            b'0'..=b'9' => u32::from(b - b'0') + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in input.bytes() {
        if b == b'=' {
            break;
        }
        acc = (acc << 6) | sextet(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

// ── REST responses ───────────────────────────────────────────────────────────

/// The outcome of `GET /gateway/bot`.
#[derive(Debug, Clone, PartialEq)]
pub enum Discovery {
    /// The gateway to dial and what is left of the daily session budget.
    Ready {
        url: String,
        remaining: Option<u64>,
        reset_after_ms: Option<u64>,
    },
    /// Discord rejected the token (401).
    Unauthorized,
    /// Rate limited (429): try again after this long.
    RateLimited { retry_after_ms: u64 },
    /// Any other status, an unusable body, or a request that never completed
    /// (`status` 0).
    Failed { status: u16 },
}

/// Classify a `GET /gateway/bot` response. A plaintext `ws://` gateway is
/// accepted only when `allow_plaintext` is set, which the shim does for a
/// plaintext `api_base`; the gateway handshake carries the token.
pub fn parse_gateway_bot(status: u16, body: &[u8], allow_plaintext: bool) -> Discovery {
    match status {
        200 => {
            let Ok(value) = serde_json::from_slice::<Value>(body) else {
                return Discovery::Failed { status };
            };
            let usable =
                |url: &&str| is_ws_url(url) && (url.starts_with("wss://") || allow_plaintext);
            let Some(url) = value.get("url").and_then(Value::as_str).filter(usable) else {
                return Discovery::Failed { status };
            };
            let limit = value.get("session_start_limit");
            Discovery::Ready {
                url: url.to_string(),
                remaining: limit
                    .and_then(|l| l.get("remaining"))
                    .and_then(Value::as_u64),
                reset_after_ms: limit
                    .and_then(|l| l.get("reset_after"))
                    .and_then(Value::as_u64),
            }
        }
        401 => Discovery::Unauthorized,
        429 => Discovery::RateLimited {
            retry_after_ms: retry_after_ms(body).unwrap_or(BACKOFF_CEILING_MS),
        },
        _ => Discovery::Failed { status },
    }
}

/// The `retry_after` of a 429 body (seconds, possibly fractional), in
/// milliseconds rounded up and capped at an hour.
pub fn retry_after_ms(body: &[u8]) -> Option<u64> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let seconds = value.get("retry_after")?.as_f64()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let millis = (seconds * 1000.0).ceil().min(3_600_000.0) as u64;
    Some(millis)
}

/// The outcome of one `POST /channels/{id}/messages`.
#[derive(Debug, Clone, PartialEq)]
pub enum SendOutcome {
    Delivered,
    RateLimited { retry_after_ms: u64 },
    Rejected(String),
}

/// Classify a send response. A rejection names the status and, when the body
/// carries them, Discord's error code and message; nothing else from the body.
pub fn classify_send(status: u16, body: &[u8]) -> SendOutcome {
    if (200..300).contains(&status) {
        return SendOutcome::Delivered;
    }
    if status == 429 {
        return SendOutcome::RateLimited {
            retry_after_ms: retry_after_ms(body).unwrap_or(BACKOFF_CEILING_MS),
        };
    }
    let meaning = match status {
        401 => "Discord rejected the bot token",
        403 => "the bot lacks permission to post in this channel",
        404 => "Discord does not know this channel",
        _ => "Discord refused the message",
    };
    let mut reason = format!("discord: send failed with HTTP {status}: {meaning}");
    if let Some((code, message)) = discord_error(body) {
        reason.push_str(&format!(" (Discord error {code}: {message})"));
    }
    SendOutcome::Rejected(reason)
}

/// Discord's `{code, message}` error object, the message bounded and stripped
/// of control characters.
fn discord_error(body: &[u8]) -> Option<(u64, String)> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value.get("code")?.as_u64()?;
    let message: String = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    Some((code, message))
}

// ── Reply delivery ───────────────────────────────────────────────────────────

/// What delivering a reply needs from outside, so the rules can be tested
/// without a network or a real clock.
pub trait ReplyTransport {
    /// Milliseconds on a monotonic clock.
    fn now_ms(&self) -> u64;
    fn sleep_ms(&mut self, ms: u64);
    /// Post one part; the response status and body, or why no response came.
    fn post(&mut self, body: &Value) -> Result<(u16, Vec<u8>), String>;
}

/// Post `chunks` in order, [`CHUNK_SPACING_MS`] apart. No request starts after
/// [`SEND_START_BUDGET_MS`]; a part rate limited for at most
/// [`MAX_RATE_LIMIT_WAIT_MS`] is retried once. An error names how many parts
/// were delivered before it.
pub fn deliver(transport: &mut impl ReplyTransport, chunks: &[String]) -> Result<(), String> {
    let started = transport.now_ms();
    let total = chunks.len();
    for (index, chunk) in chunks.iter().enumerate() {
        if index > 0 {
            transport.sleep_ms(CHUNK_SPACING_MS);
        }
        if transport.now_ms().saturating_sub(started) > SEND_START_BUDGET_MS {
            return Err(with_progress(
                "discord: ran out of time before every part was sent".to_string(),
                index,
                total,
            ));
        }
        let body = build_send_body(chunk);
        let mut retried = false;
        loop {
            let (status, response) = transport.post(&body).map_err(|error| {
                with_progress(
                    format!("discord: send request failed: {error}"),
                    index,
                    total,
                )
            })?;
            match classify_send(status, &response) {
                SendOutcome::Delivered => break,
                SendOutcome::RateLimited { retry_after_ms }
                    if !retried
                        && retry_after_ms <= MAX_RATE_LIMIT_WAIT_MS
                        && transport.now_ms().saturating_sub(started) + retry_after_ms
                            <= SEND_START_BUDGET_MS =>
                {
                    retried = true;
                    transport.sleep_ms(retry_after_ms);
                }
                SendOutcome::RateLimited { retry_after_ms } => {
                    return Err(with_progress(
                        format!("discord: rate limited for {retry_after_ms} ms"),
                        index,
                        total,
                    ));
                }
                SendOutcome::Rejected(reason) => return Err(with_progress(reason, index, total)),
            }
        }
    }
    Ok(())
}

/// Append how many parts were delivered, when any were.
pub fn with_progress(reason: String, delivered: usize, total: usize) -> String {
    if delivered == 0 {
        reason
    } else {
        format!("{reason} (after {delivered} of {total} parts were delivered)")
    }
}

// ── Channel checks ───────────────────────────────────────────────────────────

/// Minimum spacing between two channel checks, so a long `channel_ids` list
/// is checked over several calls rather than in a burst.
pub const CHANNEL_CHECK_SPACING_MS: u64 = 1_000;

/// A check that gets no response or a 5xx is tried again this many times,
/// first after this long and then after twice as long.
pub const CHANNEL_CHECK_RETRIES: u32 = 2;
pub const CHANNEL_CHECK_RETRY_MS: u64 = 30_000;

/// What `GET /channels/{id}` says about one `channel_ids` entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ChannelAccess {
    /// 200: the bot can view the channel.
    Visible,
    /// 403: the bot cannot view the channel, so Discord sends it no events
    /// from there.
    Hidden,
    /// 404, or 400 (expected for an id that is not a Discord id): Discord
    /// knows no channel with this id.
    Unknown,
    /// 429: check again after this long.
    RateLimited { retry_after_ms: u64 },
    /// Any other status, or a request that never completed (`status` 0).
    Failed { status: u16 },
}

impl ChannelAccess {
    /// What the operator can do about an entry the bot cannot use. Never
    /// includes config values.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::Hidden => Some(
                "Discord sends no messages from it: grant the bot's role or member View Channel there, or add the bot to the channel's server",
            ),
            Self::Unknown => Some(
                "Discord knows no channel with this id: it was deleted or is not a channel id; fix this entry in channel_ids",
            ),
            _ => None,
        }
    }
}

/// Classify a `GET /channels/{id}` response.
pub fn classify_channel(status: u16, body: &[u8]) -> ChannelAccess {
    match status {
        200 => ChannelAccess::Visible,
        403 => ChannelAccess::Hidden,
        // A 20-digit id above u64::MAX passes the config schema but is not a
        // snowflake; Discord is expected to refuse it with a 400.
        400 | 404 => ChannelAccess::Unknown,
        429 => ChannelAccess::RateLimited {
            retry_after_ms: retry_after_ms(body).unwrap_or(BACKOFF_CEILING_MS),
        },
        _ => ChannelAccess::Failed { status },
    }
}

/// What the shim logs after a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckReport {
    /// Nothing: the bot can view the channel, or the check runs again later.
    Quiet,
    /// The bot cannot use this entry: warn with the access's hint.
    Unusable,
    /// The check kept failing: say the entry is checked again next session.
    GaveUp,
}

/// The check, once per session, that the bot can view each `channel_ids`
/// entry. Discord sends no events from a channel the bot cannot view, so such
/// an entry is otherwise silent: no message, no error, and a healthy instance.
///
/// It keeps which entries this session has checked, not the list: the list is
/// read from the config on each call, so an entry an edit adds is checked too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelChecks {
    checked: Vec<String>,
    /// The entry whose checks keep failing, and how many times they have.
    /// Its retry wait holds back every check, on purpose: no response or a
    /// 5xx almost always means every request would fail.
    failing: Option<(String, u32)>,
    /// When the next check may start; `None` before the first session.
    next_at_ms: Option<u64>,
}

impl ChannelChecks {
    /// A session was established. READY starts the checks over, keeping any
    /// pending wait; a resume continues where the session's checks left off.
    pub fn on_identified(&mut self, now_ms: u64, resumed: bool) {
        if !resumed {
            self.checked.clear();
            self.failing = None;
            self.next_at_ms = Some(self.next_at_ms.map_or(now_ms, |at| at.max(now_ms)));
        }
    }

    /// The entry to check now: the first one this session has not checked,
    /// once the spacing or a wait allows. Only while `gateway` has a session
    /// and `idle` says this call read every queued gateway event and has no
    /// message waiting for the host. `None` when `channel_ids` is empty, which
    /// watches every channel.
    pub fn due<'a>(
        &self,
        now_ms: u64,
        cfg: &'a DiscordConfig,
        gateway: &Gateway,
        idle: bool,
    ) -> Option<&'a str> {
        if !gateway.identified() || !idle || now_ms < self.next_at_ms? {
            return None;
        }
        cfg.channel_ids
            .iter()
            .map(String::as_str)
            .find(|id| !self.checked.iter().any(|checked| checked == id))
    }

    /// Record the outcome of checking `id` and say what to log. A rate-limited
    /// entry is checked again after the wait. One that got no response or a
    /// 5xx is retried [`CHANNEL_CHECK_RETRIES`] times; any other outcome, or a
    /// failure past the retries, is final for this session.
    pub fn on_checked(&mut self, now_ms: u64, id: &str, access: &ChannelAccess) -> CheckReport {
        let (wait, report) = match access {
            ChannelAccess::RateLimited { retry_after_ms } => (
                (*retry_after_ms).max(CHANNEL_CHECK_SPACING_MS),
                CheckReport::Quiet,
            ),
            ChannelAccess::Failed { status } if *status == 0 || (500..600).contains(status) => {
                let failures = match &self.failing {
                    Some((failing, failures)) if failing == id => failures + 1,
                    _ => 1,
                };
                if failures <= CHANNEL_CHECK_RETRIES {
                    self.failing = Some((id.to_string(), failures));
                    (CHANNEL_CHECK_RETRY_MS << (failures - 1), CheckReport::Quiet)
                } else {
                    self.settle(id);
                    (CHANNEL_CHECK_SPACING_MS, CheckReport::GaveUp)
                }
            }
            ChannelAccess::Failed { .. } => {
                self.settle(id);
                (CHANNEL_CHECK_SPACING_MS, CheckReport::GaveUp)
            }
            ChannelAccess::Hidden | ChannelAccess::Unknown => {
                self.settle(id);
                (CHANNEL_CHECK_SPACING_MS, CheckReport::Unusable)
            }
            ChannelAccess::Visible => {
                self.settle(id);
                (CHANNEL_CHECK_SPACING_MS, CheckReport::Quiet)
            }
        };
        self.next_at_ms = Some(now_ms.saturating_add(wait));
        report
    }

    fn settle(&mut self, id: &str) {
        self.checked.push(id.to_string());
        self.failing = None;
    }
}

// ── Close codes ──────────────────────────────────────────────────────────────

/// Close codes after which reconnecting cannot help until the operator acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatalClose {
    /// 4004: the token was rejected.
    AuthenticationFailed,
    /// 4010 and 4011: an invalid shard, or Discord requires sharding.
    Sharding,
    /// 4012: Discord rejected the gateway API version.
    ApiVersion,
    /// 4013: the intents mask is invalid.
    InvalidIntents,
    /// 4014: a privileged intent is not enabled for the bot.
    DisallowedIntents,
}

/// What a gateway close means for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseClass {
    Fatal(FatalClose),
    /// 4007 and 4009: the session cannot be resumed; IDENTIFY again.
    NewSession,
    /// Everything else, including a close without a frame: resume.
    Resume,
}

pub fn classify_close(code: Option<u16>) -> CloseClass {
    match code {
        Some(4004) => CloseClass::Fatal(FatalClose::AuthenticationFailed),
        Some(4010 | 4011) => CloseClass::Fatal(FatalClose::Sharding),
        Some(4012) => CloseClass::Fatal(FatalClose::ApiVersion),
        Some(4013) => CloseClass::Fatal(FatalClose::InvalidIntents),
        Some(4014) => CloseClass::Fatal(FatalClose::DisallowedIntents),
        Some(4007 | 4009) => CloseClass::NewSession,
        _ => CloseClass::Resume,
    }
}

/// The Developer Portal names of the privileged intents in `mask`.
pub fn privileged_intents(mask: u64) -> Vec<&'static str> {
    [
        (INTENT_MESSAGE_CONTENT, "Message Content"),
        (INTENT_GUILD_MEMBERS, "Server Members"),
        (INTENT_GUILD_PRESENCES, "Presence"),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, name)| name)
    .collect()
}

// ── Gateway state machine ────────────────────────────────────────────────────

/// Why an instance stopped trying until it is probed again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkReason {
    /// A 4004 close, or a 401 from discovery.
    InvalidToken,
    /// A 4014 close: a privileged intent is not enabled for the bot.
    DisallowedIntents,
    /// A 4013 close.
    InvalidIntents,
    /// A 4010 or 4011 close.
    Sharding,
    /// A 4012 close.
    ApiVersion,
    /// Too many gateway events larger than the host's frame limit.
    Oversize,
}

impl ParkReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::DisallowedIntents => "disallowed_intents",
            Self::InvalidIntents => "invalid_intents",
            Self::Sharding => "sharding_required",
            Self::ApiVersion => "api_version",
            Self::Oversize => "oversize",
        }
    }

    /// What the operator can do about it. Never includes config values.
    pub fn hint(self, intents: u64) -> String {
        match self {
            Self::InvalidToken => {
                "Discord rejected the bot token; set a valid one in this instance's bot_token".to_string()
            }
            Self::DisallowedIntents => {
                let names = privileged_intents(intents);
                if names.is_empty() {
                    format!("a privileged intent in mask {intents} is not enabled for this bot in the Discord Developer Portal (Bot, Privileged Gateway Intents)")
                } else {
                    format!(
                        "enable {} for this bot in the Discord Developer Portal (Bot, Privileged Gateway Intents)",
                        names.join(", ")
                    )
                }
            }
            Self::InvalidIntents => format!("Discord rejected intents mask {intents}; fix intents_mask"),
            Self::Sharding => "Discord requires sharding for this bot, which this plugin does not support".to_string(),
            Self::ApiVersion => "Discord rejected gateway API version 10".to_string(),
            Self::Oversize => "gateway events exceeded the host's WebSocket frame limit; remove high-volume intents from intents_mask".to_string(),
        }
    }
}

impl From<FatalClose> for ParkReason {
    fn from(close: FatalClose) -> Self {
        match close {
            FatalClose::AuthenticationFailed => Self::InvalidToken,
            FatalClose::Sharding => Self::Sharding,
            FatalClose::ApiVersion => Self::ApiVersion,
            FatalClose::InvalidIntents => Self::InvalidIntents,
            FatalClose::DisallowedIntents => Self::DisallowedIntents,
        }
    }
}

/// A connection the operator has to fix; retried every
/// [`MISCONFIGURED_RETRY_MS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misconfiguration {
    /// The host refused the gateway host: it is not in the instance's
    /// `egress_hosts`, or resolves to a private address without a carve-out.
    EgressDenied,
    /// The instance holds no WebSocket grant.
    AccessDenied,
    /// The host refused the gateway URL as malformed.
    InvalidGatewayUrl,
}

impl Misconfiguration {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EgressDenied => "egress_denied",
            Self::AccessDenied => "access_denied",
            Self::InvalidGatewayUrl => "invalid_gateway_url",
        }
    }
}

/// Where the connection stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// No connection. Nothing happens before `retry_at_ms`.
    Down { retry_at_ms: u64 },
    /// Discovery returned `url`; dial it on a later call.
    Dial { url: String, resume: bool },
    /// Connected.
    Up,
    /// Stopped until the probe at `probe_at_ms`.
    Parked {
        reason: ParkReason,
        probe_at_ms: u64,
    },
    /// Waiting for the operator; retried at `retry_at_ms`.
    Misconfigured {
        reason: Misconfiguration,
        retry_at_ms: u64,
    },
}

impl Phase {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Down { .. } => "down",
            Self::Dial { .. } => "dial",
            Self::Up => "up",
            Self::Parked { .. } => "parked",
            Self::Misconfigured { .. } => "misconfigured",
        }
    }
}

/// The single network step a `poll-message` call may take. Discovery and
/// dialing never share a call, so a call waits on at most one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nothing is due.
    Wait,
    /// `GET /gateway/bot`.
    Discover,
    /// Dial the gateway.
    Connect { url: String, resume: bool },
    /// Connected: drain events and heartbeat.
    Pump,
}

/// The handshake owed after a Hello. The shim builds the payload with the
/// token it reads at that moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handshake {
    Identify { intents: u64 },
    Resume { session_id: String, seq: i64 },
}

impl Handshake {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Identify { .. } => "identify",
            Self::Resume { .. } => "resume",
        }
    }

    /// The payload, built with the token the caller just read.
    pub fn payload(&self, token: &str) -> String {
        match self {
            Self::Identify { intents } => build_identify(token, *intents),
            Self::Resume { session_id, seq } => build_resume(token, session_id, *seq),
        }
    }
}

/// What the shim does in response to one gateway frame.
#[derive(Debug, Clone, PartialEq)]
pub enum FrameAction {
    None,
    /// Send this handshake now; it stays owed until it is sent.
    Handshake(Handshake),
    /// Send this text frame (a heartbeat the server asked for).
    Send(String),
    /// Queue this message for the host.
    Emit(Inbound),
    /// A session is established.
    Identified {
        resumed: bool,
    },
    /// The server asked for a reconnect (op 7) or invalidated the session
    /// (op 9).
    Reconnect {
        keep_session: bool,
    },
}

/// What the heartbeat schedule asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Beat {
    Idle,
    Send(String),
    /// The previous heartbeat was never acknowledged although every queued
    /// event was read: the connection is a zombie.
    Zombie,
}

/// What the health check answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Unhealthy,
    /// No session yet: ask Discord whether the token works.
    AskDiscord,
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disconnect {
    /// The peer closed, with its close code when it sent a frame.
    Closed(Option<u16>),
    /// An event exceeded the host's frame or message limit.
    Oversize,
    Zombie,
    /// No Hello after the dial, or no session after the Hello, in time.
    HandshakeTimeout,
    /// The transport failed, or a send on it did.
    Transport,
    /// op 7 or op 9.
    ServerReconnect {
        keep_session: bool,
    },
}

impl Disconnect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed(_) => "closed",
            Self::Oversize => "oversize",
            Self::Zombie => "zombie",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::Transport => "transport",
            Self::ServerReconnect { .. } => "server_reconnect",
        }
    }
}

/// How a dial failed, reduced from the host's `websocket-error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    DestinationDenied,
    AccessDenied,
    InvalidUrl,
    /// DNS, TCP, TLS, the upgrade, a timeout, the connection limit, or a host
    /// service that was unavailable.
    Transient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Heartbeat {
    interval_ms: u64,
    due_at_ms: u64,
    awaiting_ack: bool,
}

/// Doubling reconnect backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    next_ms: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next_ms: BACKOFF_FLOOR_MS,
        }
    }
}

impl Backoff {
    /// The delay to wait now; the following one doubles, up to the ceiling.
    pub fn next_delay(&mut self) -> u64 {
        let delay = self.next_ms;
        self.next_ms = (delay * 2).min(BACKOFF_CEILING_MS);
        delay
    }

    pub fn reset(&mut self) {
        self.next_ms = BACKOFF_FLOOR_MS;
    }
}

/// The gateway session and connection state machine.
///
/// It holds protocol state only: the session coordinates, the heartbeat
/// schedule, handshake deadlines, backoff, the identify gate, and park
/// counters. All times are milliseconds on one monotonic clock chosen by the
/// caller. It is rebuilt with the instance, so its limits apply per instance
/// lifetime.
#[derive(Debug, Clone)]
pub struct Gateway {
    phase: Phase,
    bot_user_id: String,
    session_id: Option<String>,
    resume_url: Option<String>,
    seq: Option<i64>,
    /// The current connection was dialed to resume.
    resuming: bool,
    /// The current connection is plaintext `ws://`.
    plaintext: bool,
    identified: bool,
    identified_at_ms: Option<u64>,
    owed_handshake: Option<Handshake>,
    hello_due_ms: Option<u64>,
    session_due_ms: Option<u64>,
    heartbeat: Option<Heartbeat>,
    backoff: Backoff,
    next_identify_at_ms: u64,
    identify_spacing_ms: u64,
    recent_identifies: VecDeque<u64>,
    oversize_strikes: u32,
    park_delay_ms: u64,
    rng: u64,
}

impl Gateway {
    /// A gateway that has not connected yet. `seed` drives the heartbeat
    /// jitter.
    pub fn new(now_ms: u64, bot_user_id: impl Into<String>, seed: u64) -> Self {
        Self {
            phase: Phase::Down {
                retry_at_ms: now_ms,
            },
            bot_user_id: bot_user_id.into(),
            session_id: None,
            resume_url: None,
            seq: None,
            resuming: false,
            plaintext: false,
            identified: false,
            identified_at_ms: None,
            owed_handshake: None,
            hello_due_ms: None,
            session_due_ms: None,
            heartbeat: None,
            backoff: Backoff::default(),
            next_identify_at_ms: 0,
            identify_spacing_ms: IDENTIFY_SPACING_MS,
            recent_identifies: VecDeque::new(),
            oversize_strikes: 0,
            park_delay_ms: PARK_FIRST_PROBE_MS,
            rng: seed | 1,
        }
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    pub fn bot_user_id(&self) -> &str {
        &self.bot_user_id
    }

    pub fn identified(&self) -> bool {
        self.identified
    }

    /// A session exists that a new connection can resume.
    pub fn can_resume(&self) -> bool {
        self.session_id.is_some() && self.seq.is_some()
    }

    /// The handshake still owed on this connection, if any.
    pub fn owed_handshake(&self) -> Option<&Handshake> {
        self.owed_handshake.as_ref()
    }

    /// The step this call may take.
    pub fn next_step(&self, now_ms: u64, cfg: &DiscordConfig) -> Step {
        match &self.phase {
            Phase::Up => Step::Pump,
            Phase::Parked { probe_at_ms, .. } => {
                if now_ms < *probe_at_ms {
                    return Step::Wait;
                }
                // A configured gateway is probed by dialing it; there may be no
                // discovery endpoint in front of it.
                match &cfg.gateway_url {
                    Some(url) => self.connect_step(now_ms, url, false),
                    None => Step::Discover,
                }
            }
            Phase::Dial { url, resume } => self.connect_step(now_ms, url, *resume),
            Phase::Down { retry_at_ms } | Phase::Misconfigured { retry_at_ms, .. } => {
                if now_ms < *retry_at_ms {
                    return Step::Wait;
                }
                if self.can_resume() {
                    return match self.resume_url.as_ref().or(cfg.gateway_url.as_ref()) {
                        Some(url) => Step::Connect {
                            url: url.clone(),
                            resume: true,
                        },
                        None => Step::Discover,
                    };
                }
                match &cfg.gateway_url {
                    Some(url) => self.connect_step(now_ms, url, false),
                    None => Step::Discover,
                }
            }
        }
    }

    /// A dial that will IDENTIFY waits for the identify gate; a resume does
    /// not spend an IDENTIFY.
    fn connect_step(&self, now_ms: u64, url: &str, resume: bool) -> Step {
        if !resume && now_ms < self.identify_allowed_at(now_ms) {
            Step::Wait
        } else {
            Step::Connect {
                url: url.to_string(),
                resume,
            }
        }
    }

    /// When the next IDENTIFY may go out: after the spacing since the last
    /// one, any wait discovery imposed, and the rolling hourly cap.
    fn identify_allowed_at(&self, now_ms: u64) -> u64 {
        let in_window = self
            .recent_identifies
            .iter()
            .filter(|at| now_ms.saturating_sub(**at) < IDENTIFY_WINDOW_MS)
            .count();
        let cap = if in_window >= MAX_IDENTIFIES_PER_HOUR {
            self.recent_identifies
                .iter()
                .rev()
                .nth(MAX_IDENTIFIES_PER_HOUR - 1)
                .map_or(0, |at| at.saturating_add(IDENTIFY_WINDOW_MS))
        } else {
            0
        };
        self.next_identify_at_ms.max(cap)
    }

    pub fn on_discovery(&mut self, now_ms: u64, outcome: Discovery) {
        let reason = match self.phase {
            Phase::Parked { reason, .. } => Some(reason),
            _ => None,
        };
        match outcome {
            Discovery::Ready {
                url,
                remaining,
                reset_after_ms,
            } => {
                self.identify_spacing_ms =
                    if remaining.is_some_and(|left| left <= LOW_IDENTIFY_BUDGET) {
                        LOW_BUDGET_IDENTIFY_SPACING_MS
                    } else {
                        IDENTIFY_SPACING_MS
                    };
                if remaining == Some(0) {
                    let wait = reset_after_ms.unwrap_or(EXHAUSTED_BUDGET_WAIT_MS);
                    self.next_identify_at_ms =
                        self.next_identify_at_ms.max(now_ms.saturating_add(wait));
                }
                self.phase = Phase::Dial {
                    url,
                    resume: self.can_resume(),
                };
            }
            Discovery::Unauthorized => self.park(now_ms, ParkReason::InvalidToken),
            Discovery::RateLimited { retry_after_ms } => match reason {
                Some(reason) => self.park(now_ms, reason),
                None => {
                    let delay = retry_after_ms.max(self.backoff.next_delay());
                    self.retry_after(now_ms, delay);
                }
            },
            Discovery::Failed { .. } => match reason {
                Some(reason) => self.park(now_ms, reason),
                None => {
                    let delay = self.backoff.next_delay();
                    self.retry_after(now_ms, delay);
                }
            },
        }
    }

    /// A dial to `url` succeeded.
    pub fn on_connected(&mut self, now_ms: u64, url: &str, resume: bool) {
        self.phase = Phase::Up;
        self.resuming = resume && self.can_resume();
        self.plaintext = url.starts_with("ws://");
        self.identified = false;
        self.identified_at_ms = None;
        self.owed_handshake = None;
        self.heartbeat = None;
        self.hello_due_ms = Some(now_ms.saturating_add(HELLO_TIMEOUT_MS));
        self.session_due_ms = None;
    }

    pub fn on_connect_failed(&mut self, now_ms: u64, failure: ConnectFailure, resume: bool) {
        match failure {
            // A resume host the grant does not cover: start over through
            // discovery, which may hand out a granted one.
            ConnectFailure::DestinationDenied | ConnectFailure::InvalidUrl if resume => {
                self.wipe_session();
                let delay = self.backoff.next_delay();
                self.retry_after(now_ms, delay);
            }
            ConnectFailure::DestinationDenied => {
                self.misconfigure(now_ms, Misconfiguration::EgressDenied)
            }
            ConnectFailure::AccessDenied => {
                self.misconfigure(now_ms, Misconfiguration::AccessDenied)
            }
            ConnectFailure::InvalidUrl => {
                self.misconfigure(now_ms, Misconfiguration::InvalidGatewayUrl)
            }
            ConnectFailure::Transient => {
                let delay = self.backoff.next_delay();
                self.retry_after(now_ms, delay);
            }
        }
    }

    /// Apply one text frame.
    pub fn on_frame(&mut self, now_ms: u64, text: &str, cfg: &DiscordConfig) -> FrameAction {
        let Some(frame) = parse_frame(text) else {
            return FrameAction::None;
        };
        if let Some(seq) = frame.s {
            self.seq = Some(seq);
        }
        match frame.op {
            OP_HELLO => {
                let interval_ms = frame
                    .d
                    .get("heartbeat_interval")
                    .and_then(Value::as_u64)
                    .filter(|ms| *ms > 0)
                    .unwrap_or(DEFAULT_HEARTBEAT_MS);
                let first_beat_ms = interval_ms.saturating_mul(self.jitter_permille()) / 1000;
                self.heartbeat = Some(Heartbeat {
                    interval_ms,
                    due_at_ms: now_ms.saturating_add(first_beat_ms),
                    awaiting_ack: false,
                });
                self.hello_due_ms = None;
                self.session_due_ms = Some(now_ms.saturating_add(SESSION_TIMEOUT_MS));
                let handshake = match (&self.session_id, self.seq) {
                    (Some(session_id), Some(seq)) if self.resuming => Handshake::Resume {
                        session_id: session_id.clone(),
                        seq,
                    },
                    _ => Handshake::Identify {
                        intents: cfg.intents(),
                    },
                };
                self.owed_handshake = Some(handshake.clone());
                FrameAction::Handshake(handshake)
            }
            OP_HEARTBEAT => FrameAction::Send(build_heartbeat(self.seq)),
            OP_HEARTBEAT_ACK => {
                if let Some(heartbeat) = &mut self.heartbeat {
                    heartbeat.awaiting_ack = false;
                }
                FrameAction::None
            }
            OP_RECONNECT => FrameAction::Reconnect { keep_session: true },
            OP_INVALID_SESSION => {
                let resumable = frame.d.as_bool().unwrap_or(false);
                if !resumable {
                    self.wipe_session();
                }
                FrameAction::Reconnect {
                    keep_session: resumable,
                }
            }
            OP_DISPATCH => match frame.t.as_deref() {
                Some("READY") => {
                    self.session_id = string_at(&frame.d, "session_id");
                    // The resume handshake carries the token: never downgrade
                    // to plaintext from an encrypted connection.
                    let plaintext = self.plaintext;
                    self.resume_url = string_at(&frame.d, "resume_gateway_url")
                        .filter(|url| is_ws_url(url) && (url.starts_with("wss://") || plaintext));
                    if let Some(id) = ready_user_id(&frame.d) {
                        self.bot_user_id = id;
                    }
                    self.mark_identified(now_ms);
                    FrameAction::Identified { resumed: false }
                }
                Some("RESUMED") => {
                    self.mark_identified(now_ms);
                    FrameAction::Identified { resumed: true }
                }
                Some("MESSAGE_CREATE") => {
                    message_create_to_inbound(&frame.d, cfg, &self.bot_user_id)
                        .map_or(FrameAction::None, FrameAction::Emit)
                }
                _ => FrameAction::None,
            },
            _ => FrameAction::None,
        }
    }

    /// The owed handshake was sent.
    pub fn on_handshake_sent(&mut self, now_ms: u64) {
        if let Some(Handshake::Identify { .. }) = self.owed_handshake.take() {
            self.next_identify_at_ms = now_ms.saturating_add(self.identify_spacing_ms);
            self.recent_identifies.push_back(now_ms);
            while self.recent_identifies.len() > MAX_IDENTIFIES_PER_HOUR {
                self.recent_identifies.pop_front();
            }
        }
    }

    /// No Hello in time after the dial, or no session in time after the
    /// Hello.
    pub fn handshake_overdue(&self, now_ms: u64) -> bool {
        self.hello_due_ms.is_some_and(|due| now_ms >= due)
            || self.session_due_ms.is_some_and(|due| now_ms >= due)
    }

    /// What the heartbeat schedule asks for. `caught_up` is whether every
    /// queued event was read this call; until then an acknowledgement may
    /// still be waiting in the queue.
    pub fn heartbeat_step(&self, now_ms: u64, caught_up: bool) -> Beat {
        let Some(heartbeat) = &self.heartbeat else {
            return Beat::Idle;
        };
        if now_ms < heartbeat.due_at_ms {
            return Beat::Idle;
        }
        if heartbeat.awaiting_ack {
            return if caught_up { Beat::Zombie } else { Beat::Idle };
        }
        Beat::Send(build_heartbeat(self.seq))
    }

    pub fn on_heartbeat_sent(&mut self, now_ms: u64) {
        if let Some(heartbeat) = &mut self.heartbeat {
            heartbeat.awaiting_ack = true;
            heartbeat.due_at_ms = now_ms.saturating_add(heartbeat.interval_ms);
        }
    }

    pub fn on_disconnect(&mut self, now_ms: u64, cause: Disconnect) {
        let lasted_ms = self.identified_at_ms.map(|at| now_ms.saturating_sub(at));
        let settled = lasted_ms.is_some_and(|ms| ms >= SESSION_SETTLED_MS);
        if settled {
            self.backoff.reset();
        }
        if lasted_ms.is_some_and(|ms| ms >= STABLE_SESSION_MS) {
            self.oversize_strikes = 0;
            self.park_delay_ms = PARK_FIRST_PROBE_MS;
        }
        // A resume that got its Hello but never its RESUMED.
        let resume_unanswered = self.resuming && self.hello_due_ms.is_none();
        self.resuming = false;
        self.identified = false;
        self.identified_at_ms = None;
        self.owed_handshake = None;
        self.hello_due_ms = None;
        self.session_due_ms = None;
        self.heartbeat = None;
        match cause {
            Disconnect::Closed(code) => match classify_close(code) {
                CloseClass::Fatal(close) => {
                    self.wipe_session();
                    self.park(now_ms, close.into());
                }
                CloseClass::NewSession => {
                    self.wipe_session();
                    let delay = self.backoff.next_delay();
                    self.retry_after(now_ms, delay);
                }
                CloseClass::Resume => {
                    let delay = self.backoff.next_delay();
                    self.retry_after(now_ms, delay);
                }
            },
            // Resuming would replay the event that did not fit.
            Disconnect::Oversize => {
                self.wipe_session();
                self.oversize_strikes += 1;
                if self.oversize_strikes >= OVERSIZE_STRIKES {
                    self.park(now_ms, ParkReason::Oversize);
                } else {
                    let delay = self.backoff.next_delay().max(OVERSIZE_FLOOR_MS);
                    self.retry_after(now_ms, delay);
                }
            }
            // A resume that never completes is not worth repeating; a missing
            // Hello says nothing about the session.
            Disconnect::HandshakeTimeout => {
                if resume_unanswered {
                    self.wipe_session();
                }
                let delay = self.backoff.next_delay();
                self.retry_after(now_ms, delay);
            }
            Disconnect::Zombie | Disconnect::Transport => {
                let delay = self.backoff.next_delay();
                self.retry_after(now_ms, delay);
            }
            // A settled session reconnects at once; a gateway that asks again
            // right away is backed off.
            Disconnect::ServerReconnect { keep_session: true } => {
                let delay = if settled {
                    0
                } else {
                    self.backoff.next_delay()
                };
                self.retry_after(now_ms, delay);
            }
            Disconnect::ServerReconnect {
                keep_session: false,
            } => {
                self.wipe_session();
                let delay = self.backoff.next_delay().max(INVALID_SESSION_WAIT_MS);
                self.retry_after(now_ms, delay);
            }
        }
    }

    /// The health check's answer: unhealthy while stopped or unable to read
    /// config, healthy while a session is established, and otherwise a
    /// question for Discord.
    pub fn health(&self, config_readable: bool) -> Health {
        if self.stopped() || !config_readable {
            Health::Unhealthy
        } else if self.identified {
            Health::Healthy
        } else {
            Health::AskDiscord
        }
    }

    /// Parked or misconfigured: waiting on the operator or a probe.
    pub fn stopped(&self) -> bool {
        matches!(
            self.phase,
            Phase::Parked { .. } | Phase::Misconfigured { .. }
        )
    }

    fn mark_identified(&mut self, now_ms: u64) {
        self.identified = true;
        self.identified_at_ms = Some(now_ms);
        self.session_due_ms = None;
    }

    fn wipe_session(&mut self) {
        self.session_id = None;
        self.resume_url = None;
        self.seq = None;
    }

    fn retry_after(&mut self, now_ms: u64, delay_ms: u64) {
        self.phase = Phase::Down {
            retry_at_ms: now_ms.saturating_add(delay_ms),
        };
    }

    fn park(&mut self, now_ms: u64, reason: ParkReason) {
        self.phase = Phase::Parked {
            reason,
            probe_at_ms: now_ms.saturating_add(self.park_delay_ms),
        };
        self.park_delay_ms = (self.park_delay_ms * 2).min(PARK_MAX_PROBE_MS);
    }

    fn misconfigure(&mut self, now_ms: u64, reason: Misconfiguration) {
        self.phase = Phase::Misconfigured {
            reason,
            retry_at_ms: now_ms.saturating_add(MISCONFIGURED_RETRY_MS),
        };
    }

    /// 0..1000, from an xorshift generator seeded at construction.
    fn jitter_permille(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x % 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOT: &str = "123456789012345678";
    const GATEWAY: &str = "wss://gateway.discord.gg";

    fn msg(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    fn hello(interval: u64) -> String {
        format!(r#"{{"op":10,"d":{{"heartbeat_interval":{interval}}}}}"#)
    }

    fn ready(seq: i64) -> String {
        format!(
            r#"{{"op":0,"t":"READY","s":{seq},"d":{{"session_id":"sess","resume_gateway_url":"wss://resume.discord.gg","user":{{"id":"{BOT}","username":"zc"}}}}}}"#
        )
    }

    /// A gateway that discovered, connected, and identified at `t`.
    fn established(t: u64) -> (Gateway, DiscordConfig) {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(t, BOT, 7);
        gw.on_discovery(t, ready_discovery());
        gw.on_connected(t, GATEWAY, false);
        assert!(matches!(
            gw.on_frame(t, &hello(40_000), &cfg),
            FrameAction::Handshake(Handshake::Identify { .. })
        ));
        gw.on_handshake_sent(t);
        assert_eq!(
            gw.on_frame(t, &ready(1), &cfg),
            FrameAction::Identified { resumed: false }
        );
        (gw, cfg)
    }

    fn ready_discovery() -> Discovery {
        Discovery::Ready {
            url: GATEWAY.into(),
            remaining: Some(1000),
            reset_after_ms: Some(0),
        }
    }

    // ── config ──

    #[test]
    fn config_parses_public_fields() {
        let cfg = DiscordConfig::from_public_json(
            r#"{"guild_ids":["1","2"],"channel_ids":["99"],"listen_to_bots":true,"mention_only":true,
                "intents_mask":513,"api_base":"http://127.0.0.1:9/api/v10/","gateway_url":"ws://127.0.0.1:8/gateway"}"#,
        )
        .unwrap();
        assert_eq!(cfg.guild_ids, vec!["1", "2"]);
        assert_eq!(cfg.channel_ids, vec!["99"]);
        assert!(cfg.listen_to_bots && cfg.mention_only);
        assert_eq!(cfg.intents(), 513);
        assert_eq!(
            cfg.api_base, "http://127.0.0.1:9/api/v10",
            "a trailing slash is dropped"
        );
        assert_eq!(cfg.gateway_url.as_deref(), Some("ws://127.0.0.1:8/gateway"));
    }

    #[test]
    fn config_defaults_when_fields_are_absent() {
        let cfg = DiscordConfig::from_public_json("{}").unwrap();
        assert_eq!(cfg, DiscordConfig::default());
        assert_eq!(cfg.intents(), DEFAULT_INTENTS);
        assert_eq!(DEFAULT_INTENTS, 37376);
    }

    #[test]
    fn config_intents_mask_zero_is_honored() {
        let cfg = DiscordConfig::from_public_json(r#"{"intents_mask":0}"#).unwrap();
        assert_eq!(cfg.intents(), 0);
    }

    #[test]
    fn config_accepts_everything_the_schema_accepts() {
        // The schema's id pattern admits 20-digit values above u64::MAX, and
        // JSON Schema counts 37376.0 as an integer. A live edit to either must
        // not stop the instance from reading its config.
        let cfg = DiscordConfig::from_public_json(
            r#"{"guild_ids":["99999999999999999999"],"intents_mask":37376.0}"#,
        )
        .unwrap();
        assert_eq!(cfg.guild_ids, vec!["99999999999999999999"]);
        assert_eq!(cfg.intents(), 37376);
        assert!(DiscordConfig::from_public_json(r#"{"intents_mask":1.5}"#).is_err());
    }

    #[test]
    fn config_rejects_malformed_values() {
        for bad in [
            "not json",
            "[]",
            r#"{"guild_ids":"1"}"#,
            r#"{"guild_ids":[1]}"#,
            r#"{"channel_ids":["abc"]}"#,
            r#"{"channel_ids":["123456789012345678901"]}"#,
            r#"{"mention_only":"yes"}"#,
            r#"{"intents_mask":-1}"#,
            r#"{"api_base":"ftp://x"}"#,
            r#"{"gateway_url":"https://gateway.discord.gg"}"#,
        ] {
            assert!(
                DiscordConfig::from_public_json(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn config_never_carries_a_token() {
        // A stray bot_token in the public object is ignored, not kept.
        let cfg = DiscordConfig::from_public_json(r#"{"bot_token":"secret"}"#).unwrap();
        assert!(!format!("{cfg:?}").contains("secret"));
    }

    // ── payloads and URLs ──

    #[test]
    fn identify_payload_shape() {
        let v: Value = serde_json::from_str(&build_identify("TKN", 37376)).unwrap();
        assert_eq!(v["op"], 2);
        assert_eq!(v["d"]["token"], "TKN");
        assert_eq!(v["d"]["intents"], 37376);
        assert_eq!(v["d"]["properties"]["browser"], "zeroclaw");
    }

    #[test]
    fn resume_payload_shape() {
        let v: Value = serde_json::from_str(&build_resume("TKN", "sess-1", 42)).unwrap();
        assert_eq!(v["op"], 6);
        assert_eq!(v["d"]["session_id"], "sess-1");
        assert_eq!(v["d"]["seq"], 42);
    }

    #[test]
    fn heartbeat_payload_seq_and_null() {
        let v: Value = serde_json::from_str(&build_heartbeat(Some(7))).unwrap();
        assert_eq!((v["op"].as_u64(), v["d"].as_i64()), (Some(1), Some(7)));
        let v: Value = serde_json::from_str(&build_heartbeat(None)).unwrap();
        assert!(v["d"].is_null());
    }

    #[test]
    fn handshake_payload_uses_the_token_it_is_given() {
        let identify = Handshake::Identify { intents: 1 }.payload("T1");
        assert!(identify.contains("\"T1\"") && identify.contains("\"op\":2"));
        let resume = Handshake::Resume {
            session_id: "s".into(),
            seq: 3,
        }
        .payload("T2");
        assert!(resume.contains("\"T2\"") && resume.contains("\"op\":6"));
    }

    #[test]
    fn gateway_url_and_host() {
        assert_eq!(
            gateway_ws_url(GATEWAY),
            "wss://gateway.discord.gg/?v=10&encoding=json"
        );
        assert_eq!(
            gateway_ws_url("ws://127.0.0.1:8765/gateway/"),
            "ws://127.0.0.1:8765/gateway/?v=10&encoding=json"
        );
        assert_eq!(
            url_host("wss://gateway.discord.gg/?v=10"),
            "gateway.discord.gg"
        );
        assert_eq!(url_host("ws://user:pw@127.0.0.1:8765/x"), "127.0.0.1:8765");
        assert_eq!(url_host("https://discord.com"), "discord.com");
    }

    #[test]
    fn http_urls_split_for_wasi_http() {
        assert_eq!(
            split_http_url("https://discord.com/api/v10/gateway/bot"),
            Some(HttpTarget {
                https: true,
                authority: "discord.com".into(),
                path_with_query: "/api/v10/gateway/bot".into()
            })
        );
        assert_eq!(
            split_http_url("http://127.0.0.1:8765/api/v10/channels/1/messages?x=1"),
            Some(HttpTarget {
                https: false,
                authority: "127.0.0.1:8765".into(),
                path_with_query: "/api/v10/channels/1/messages?x=1".into()
            })
        );
        assert_eq!(
            split_http_url("https://discord.com")
                .unwrap()
                .path_with_query,
            "/"
        );
        assert_eq!(
            split_http_url("https://discord.com?a=1")
                .unwrap()
                .path_with_query,
            "/?a=1"
        );
        assert!(split_http_url("ftp://x/y").is_none());
        assert!(split_http_url("https:///path").is_none());
        assert!(
            split_http_url("https://user:pw@host/x").is_none(),
            "no embedded credentials"
        );
    }

    // ── frames and messages ──

    #[test]
    fn parse_frame_extracts_fields() {
        let f =
            parse_frame(r#"{"op":0,"t":"MESSAGE_CREATE","s":12,"d":{"content":"hi"}}"#).unwrap();
        assert_eq!(
            (f.op, f.t.as_deref(), f.s),
            (0, Some("MESSAGE_CREATE"), Some(12))
        );
        assert!(parse_frame("garbage").is_none());
        assert!(
            parse_frame(r#"{"d":{}}"#).is_none(),
            "a frame without an opcode is skipped"
        );
    }

    fn create(json: &str) -> Option<Inbound> {
        message_create_to_inbound(&msg(json), &DiscordConfig::default(), BOT)
    }

    #[test]
    fn message_create_maps_fields() {
        let inbound = create(
            r#"{"id":"175928847299117063","type":0,"channel_id":"55","guild_id":"9","author":{"id":"42"},"content":"  hello bot \n"}"#,
        )
        .unwrap();
        assert_eq!(inbound.id, "discord_175928847299117063");
        assert_eq!(inbound.sender, "42");
        assert_eq!(inbound.reply_target, "55");
        assert_eq!(
            inbound.content, "hello bot",
            "content is trimmed like the built-in channel"
        );
        assert_eq!(
            inbound.timestamp_ms, 1_462_015_105_796,
            "milliseconds from the snowflake"
        );
    }

    #[test]
    fn message_create_drops_unusable_messages() {
        // own message
        assert!(create(&format!(
            r#"{{"id":"1","type":0,"channel_id":"c","author":{{"id":"{BOT}"}},"content":"x"}}"#
        ))
        .is_none());
        // another bot
        assert!(create(
            r#"{"id":"1","type":0,"channel_id":"c","author":{"id":"7","bot":true},"content":"x"}"#
        )
        .is_none());
        // a thread-created notice
        assert!(create(
            r#"{"id":"1","type":18,"channel_id":"c","author":{"id":"7"},"content":"x"}"#
        )
        .is_none());
        // blank
        assert!(create(
            r#"{"id":"1","type":0,"channel_id":"c","author":{"id":"7"},"content":"   "}"#
        )
        .is_none());
        // no id, or an id that is not a snowflake
        assert!(
            create(r#"{"type":0,"channel_id":"c","author":{"id":"7"},"content":"x"}"#).is_none()
        );
        assert!(create(
            r#"{"id":"abc","type":0,"channel_id":"c","author":{"id":"7"},"content":"x"}"#
        )
        .is_none());
        // no author
        assert!(create(r#"{"id":"1","type":0,"channel_id":"c","content":"x"}"#).is_none());
    }

    #[test]
    fn message_create_reply_type_and_dm_fallback() {
        let inbound = create(r#"{"id":"1","type":19,"author":{"id":"7"},"content":"x"}"#).unwrap();
        assert_eq!(
            inbound.reply_target, "7",
            "no channel id: reply to the author"
        );
    }

    #[test]
    fn message_create_listen_to_bots_admits_bots() {
        let cfg = DiscordConfig {
            listen_to_bots: true,
            ..DiscordConfig::default()
        };
        let d = msg(
            r#"{"id":"1","type":0,"channel_id":"c","author":{"id":"7","bot":true},"content":"hi"}"#,
        );
        assert!(message_create_to_inbound(&d, &cfg, BOT).is_some());
    }

    #[test]
    fn message_create_guild_and_channel_allowlists() {
        let cfg = DiscordConfig {
            guild_ids: vec!["10".into()],
            channel_ids: vec!["20".into()],
            ..DiscordConfig::default()
        };
        let check = |json: &str| message_create_to_inbound(&msg(json), &cfg, BOT).is_some();
        assert!(!check(
            r#"{"id":"1","type":0,"guild_id":"11","channel_id":"20","author":{"id":"7"},"content":"x"}"#
        ));
        assert!(!check(
            r#"{"id":"1","type":0,"guild_id":"10","channel_id":"21","author":{"id":"7"},"content":"x"}"#
        ));
        assert!(check(
            r#"{"id":"1","type":0,"guild_id":"10","channel_id":"20","author":{"id":"7"},"content":"x"}"#
        ));
        // A DM passes the guild allowlist, but its DM channel must be listed.
        assert!(!check(
            r#"{"id":"1","type":0,"channel_id":"30","author":{"id":"7"},"content":"x"}"#
        ));
        assert!(check(
            r#"{"id":"1","type":0,"channel_id":"20","author":{"id":"7"},"content":"x"}"#
        ));
    }

    #[test]
    fn message_create_mention_only_gates_guilds_not_dms() {
        let cfg = DiscordConfig {
            mention_only: true,
            ..DiscordConfig::default()
        };
        let check = |json: &str| message_create_to_inbound(&msg(json), &cfg, BOT).is_some();
        assert!(!check(
            r#"{"id":"1","type":0,"guild_id":"g","channel_id":"c","author":{"id":"7"},"content":"hello"}"#
        ));
        assert!(check(&format!(
            r#"{{"id":"1","type":0,"guild_id":"g","channel_id":"c","author":{{"id":"7"}},"content":"<@{BOT}> hi"}}"#
        )));
        assert!(check(&format!(
            r#"{{"id":"1","type":0,"guild_id":"g","channel_id":"c","author":{{"id":"7"}},"content":"<@!{BOT}> hi"}}"#
        )));
        assert!(check(
            r#"{"id":"1","type":0,"channel_id":"c","author":{"id":"7"},"content":"hi"}"#
        ));
    }

    #[test]
    fn mention_matches_both_forms_only() {
        assert!(contains_bot_mention("hey <@123> there", "123"));
        assert!(contains_bot_mention("hey <@!123> there", "123"));
        assert!(!contains_bot_mention("hey <@1234> there", "123"));
        assert!(!contains_bot_mention("no mention", ""));
    }

    // ── snowflakes, recipients, chunks ──

    #[test]
    fn snowflake_validation_and_time() {
        assert!(is_snowflake("1"));
        assert!(is_snowflake("18446744073709551615"));
        assert!(!is_snowflake("18446744073709551616"), "overflows u64");
        assert!(
            is_decimal_id("18446744073709551616"),
            "but the schema admits it"
        );
        assert!(!is_snowflake(""));
        assert!(!is_snowflake("12a"));
        assert!(!is_snowflake("../x"));
        assert_eq!(snowflake_ms("0"), Some(DISCORD_EPOCH_MS));
    }

    #[test]
    fn recipient_falls_back_and_must_be_a_snowflake() {
        let ids = vec!["777".to_string()];
        assert_eq!(effective_recipient("555", &ids), Ok("555"));
        assert_eq!(effective_recipient("", &ids), Ok("777"));
        assert!(effective_recipient("", &[]).is_err());
        assert!(
            effective_recipient("../../users/@me", &ids).is_err(),
            "no path injection"
        );
        assert!(effective_recipient("555?x=1", &ids).is_err());
        assert!(effective_recipient("", &["99999999999999999999".to_string()]).is_err());
    }

    #[test]
    fn chunking_matches_the_built_in_channel() {
        assert!(chunk_text("", 2000).is_empty());
        assert_eq!(chunk_text("hello", 2000), vec!["hello"]);

        let body = "a".repeat(4500);
        let chunks = chunk_text(&body, 2000);
        assert_eq!(
            chunks.iter().map(|c| c.chars().count()).collect::<Vec<_>>(),
            vec![2000, 2000, 500]
        );
        assert_eq!(chunks.concat(), body);

        // A newline at least half way in wins.
        let body = format!("{}\n{}", "x".repeat(1500), "y".repeat(1500));
        let chunks = chunk_text(&body, 2000);
        assert_eq!(chunks[0], format!("{}\n", "x".repeat(1500)));
        assert_eq!(chunks[1], "y".repeat(1500));

        // An early newline loses to a later space.
        let body = format!(
            "{}\n{} {}",
            "x".repeat(10),
            "y".repeat(1800),
            "z".repeat(500)
        );
        let chunks = chunk_text(&body, 2000);
        assert!(chunks[0].ends_with(' '), "split after the space");
        assert_eq!(chunks.concat(), body);

        // Multibyte text is never split inside a character.
        let body = "é".repeat(2500);
        let chunks = chunk_text(&body, 2000);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks.concat(), body);
    }

    #[test]
    fn bot_id_from_token_decodes_first_segment() {
        assert_eq!(
            bot_user_id_from_token("MTIzNDU2Nzg5MDEyMzQ1Njc4.mock.mock").as_deref(),
            Some(BOT)
        );
        assert_eq!(
            bot_user_id_from_token("MTIzNDU2.x.y").as_deref(),
            Some("123456")
        );
        assert_eq!(
            bot_user_id_from_token("aGVsbG8.x.y"),
            None,
            "base64(\"hello\") is not an id"
        );
        assert_eq!(bot_user_id_from_token(""), None);
        assert_eq!(bot_user_id_from_token("!!!.x.y"), None);
    }

    // ── REST ──

    #[test]
    fn discovery_classification() {
        let body = br#"{"url":"wss://gateway.discord.gg","shards":1,"session_start_limit":{"total":1000,"remaining":998,"reset_after":14400000,"max_concurrency":1}}"#;
        assert_eq!(
            parse_gateway_bot(200, body, false),
            Discovery::Ready {
                url: GATEWAY.into(),
                remaining: Some(998),
                reset_after_ms: Some(14_400_000)
            }
        );
        assert_eq!(
            parse_gateway_bot(200, b"{}", false),
            Discovery::Failed { status: 200 }
        );
        assert_eq!(
            parse_gateway_bot(200, br#"{"url":"https://x"}"#, true),
            Discovery::Failed { status: 200 }
        );
        assert_eq!(parse_gateway_bot(401, b"", false), Discovery::Unauthorized);
        assert_eq!(
            parse_gateway_bot(429, br#"{"retry_after":1.5}"#, false),
            Discovery::RateLimited {
                retry_after_ms: 1500
            }
        );
        assert_eq!(
            parse_gateway_bot(502, b"<html>", false),
            Discovery::Failed { status: 502 }
        );
    }

    #[test]
    fn discovery_refuses_a_plaintext_gateway_unless_the_api_is_plaintext() {
        let body = br#"{"url":"ws://127.0.0.1:8765/gateway"}"#;
        assert_eq!(
            parse_gateway_bot(200, body, false),
            Discovery::Failed { status: 200 }
        );
        assert!(matches!(
            parse_gateway_bot(200, body, true),
            Discovery::Ready { .. }
        ));
    }

    #[test]
    fn retry_after_is_rounded_up_and_bounded() {
        assert_eq!(retry_after_ms(br#"{"retry_after":0.0011}"#), Some(2));
        assert_eq!(retry_after_ms(br#"{"retry_after":99999}"#), Some(3_600_000));
        assert_eq!(retry_after_ms(br#"{"retry_after":-1}"#), None);
        assert_eq!(retry_after_ms(b"nope"), None);
    }

    #[test]
    fn send_classification_names_status_and_discord_error_only() {
        assert_eq!(classify_send(200, b"{}"), SendOutcome::Delivered);
        assert_eq!(
            classify_send(429, br#"{"retry_after":0.5}"#),
            SendOutcome::RateLimited {
                retry_after_ms: 500
            }
        );
        let SendOutcome::Rejected(reason) = classify_send(
            403,
            br#"{"code":50013,"message":"Missing Permissions","extra":"do-not-echo"}"#,
        ) else {
            panic!("403 is a rejection");
        };
        assert!(
            reason.contains("403")
                && reason.contains("50013")
                && reason.contains("Missing Permissions")
        );
        assert!(!reason.contains("do-not-echo"));
        let SendOutcome::Rejected(reason) = classify_send(401, b"") else {
            panic!()
        };
        assert!(reason.contains("bot token"));
        let SendOutcome::Rejected(reason) =
            classify_send(404, br#"{"code":10003,"message":"Unknown\nChannel"}"#)
        else {
            panic!()
        };
        assert!(
            reason.contains("UnknownChannel"),
            "control characters are stripped: {reason}"
        );
    }

    // ── reply delivery ──

    /// A scripted transport: each post takes `post_ms` and answers from the
    /// script, then 200.
    struct Script {
        now: u64,
        post_ms: u64,
        answers: VecDeque<Result<(u16, Vec<u8>), String>>,
        posts: Vec<(u64, String)>,
    }

    impl Script {
        fn new(post_ms: u64, answers: Vec<Result<(u16, &[u8]), &str>>) -> Self {
            Self {
                now: 1_000,
                post_ms,
                answers: answers
                    .into_iter()
                    .map(|a| a.map(|(s, b)| (s, b.to_vec())).map_err(String::from))
                    .collect(),
                posts: Vec::new(),
            }
        }
    }

    impl ReplyTransport for Script {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn sleep_ms(&mut self, ms: u64) {
            self.now += ms;
        }
        fn post(&mut self, body: &Value) -> Result<(u16, Vec<u8>), String> {
            self.posts
                .push((self.now, body["content"].as_str().unwrap_or("").to_string()));
            self.now += self.post_ms;
            self.answers
                .pop_front()
                .unwrap_or(Ok((200, b"{}".to_vec())))
        }
    }

    fn parts(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("part {i}")).collect()
    }

    #[test]
    fn delivery_posts_every_part_in_order_half_a_second_apart() {
        let mut script = Script::new(100, vec![]);
        assert_eq!(deliver(&mut script, &parts(3)), Ok(()));
        let times: Vec<u64> = script.posts.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, vec![1_000, 1_600, 2_200]);
        assert_eq!(script.posts[2].1, "part 2");
    }

    #[test]
    fn delivery_retries_one_short_rate_limit() {
        let mut script = Script::new(10, vec![Ok((429, br#"{"retry_after":0.3}"#))]);
        assert_eq!(deliver(&mut script, &parts(1)), Ok(()));
        assert_eq!(script.posts.len(), 2);
        assert_eq!(
            script.posts[1].0 - script.posts[0].0,
            310,
            "waited retry_after"
        );

        // A second rate limit on the same part, or a long one, ends the send.
        let mut script = Script::new(
            10,
            vec![
                Ok((429, br#"{"retry_after":0.3}"#)),
                Ok((429, br#"{"retry_after":0.3}"#)),
            ],
        );
        assert!(deliver(&mut script, &parts(1))
            .unwrap_err()
            .contains("rate limited"));
        let mut script = Script::new(10, vec![Ok((429, br#"{"retry_after":5}"#))]);
        assert_eq!(
            deliver(&mut script, &parts(1)).unwrap_err(),
            "discord: rate limited for 5000 ms"
        );
        assert_eq!(script.posts.len(), 1);
    }

    #[test]
    fn delivery_reports_what_was_delivered_before_a_failure() {
        let mut script = Script::new(
            10,
            vec![
                Ok((200, b"{}")),
                Ok((403, br#"{"code":50013,"message":"Missing Permissions"}"#)),
            ],
        );
        let error = deliver(&mut script, &parts(3)).unwrap_err();
        assert!(
            error.contains("50013") && error.contains("after 1 of 3 parts were delivered"),
            "{error}"
        );
        assert_eq!(script.posts.len(), 2, "the third part is never posted");

        let mut script = Script::new(10, vec![Err("connection refused")]);
        assert_eq!(
            deliver(&mut script, &parts(2)).unwrap_err(),
            "discord: send request failed: connection refused"
        );
    }

    #[test]
    fn delivery_starts_no_request_after_the_budget() {
        // Each post takes 6 s: parts start at 0, 6.5 and 13 s; the fourth
        // would start at 19.5 s, past the 15 s budget.
        let mut script = Script::new(6_000, vec![]);
        let error = deliver(&mut script, &parts(5)).unwrap_err();
        assert!(
            error.contains("ran out of time") && error.contains("after 3 of 5"),
            "{error}"
        );
        assert_eq!(script.posts.len(), 3);
        assert!(script
            .posts
            .iter()
            .all(|(t, _)| t - 1_000 <= SEND_START_BUDGET_MS));

        // A rate-limit wait that would cross the budget is not taken.
        let mut script = Script::new(14_000, vec![Ok((429, br#"{"retry_after":1.5}"#))]);
        assert!(deliver(&mut script, &parts(1))
            .unwrap_err()
            .contains("rate limited"));
        assert_eq!(script.posts.len(), 1);
    }

    // ── channel checks ──

    fn channels(ids: &[&str]) -> DiscordConfig {
        DiscordConfig {
            channel_ids: ids.iter().map(|id| (*id).to_string()).collect(),
            ..DiscordConfig::default()
        }
    }

    /// Checks started by READY on a gateway with a session.
    fn checking(t: u64) -> (ChannelChecks, Gateway) {
        let (gw, _) = established(t);
        let mut checks = ChannelChecks::default();
        checks.on_identified(t, false);
        (checks, gw)
    }

    #[test]
    fn channel_check_classification() {
        assert_eq!(
            classify_channel(200, br#"{"id":"10","type":0}"#),
            ChannelAccess::Visible
        );
        assert_eq!(
            classify_channel(403, br#"{"code":50001,"message":"Missing Access"}"#),
            ChannelAccess::Hidden
        );
        assert_eq!(
            classify_channel(404, br#"{"code":10003,"message":"Unknown Channel"}"#),
            ChannelAccess::Unknown
        );
        assert_eq!(
            classify_channel(400, br#"{"code":50035,"message":"Invalid Form Body"}"#),
            ChannelAccess::Unknown,
            "an id that is not a snowflake"
        );
        assert_eq!(
            classify_channel(429, br#"{"retry_after":1.5}"#),
            ChannelAccess::RateLimited {
                retry_after_ms: 1500
            }
        );
        assert_eq!(
            classify_channel(429, b""),
            ChannelAccess::RateLimited {
                retry_after_ms: BACKOFF_CEILING_MS
            }
        );
        assert_eq!(
            classify_channel(401, b""),
            ChannelAccess::Failed { status: 401 }
        );
        assert_eq!(
            classify_channel(502, b"<html>"),
            ChannelAccess::Failed { status: 502 }
        );
    }

    #[test]
    fn channel_check_hints_name_the_fix_for_403_and_404_only() {
        assert!(ChannelAccess::Hidden
            .hint()
            .is_some_and(|hint| hint.contains("View Channel")));
        assert!(ChannelAccess::Unknown
            .hint()
            .is_some_and(|hint| hint.contains("channel_ids")));
        assert_eq!(ChannelAccess::Visible.hint(), None);
        assert_eq!(ChannelAccess::Failed { status: 0 }.hint(), None);
    }

    #[test]
    fn each_entry_is_checked_once_per_session() {
        let cfg = channels(&["10", "20", "30"]);
        let answer = |id: &str| match id {
            "10" => (200, r#"{"id":"10","type":0}"#),
            "20" => (403, r#"{"code":50001,"message":"Missing Access"}"#),
            _ => (404, r#"{"code":10003,"message":"Unknown Channel"}"#),
        };
        let (gw, _) = established(0);
        let mut checks = ChannelChecks::default();
        assert_eq!(checks.due(0, &cfg, &gw, true), None, "nothing before READY");
        checks.on_identified(0, false);
        let mut seen = Vec::new();
        for t in (0..60_000).step_by(250) {
            if let Some(id) = checks.due(t, &cfg, &gw, true) {
                let (status, body) = answer(id);
                let access = classify_channel(status, body.as_bytes());
                let report = checks.on_checked(t, id, &access);
                seen.push((id, access, report));
            }
        }
        assert_eq!(
            seen,
            vec![
                ("10", ChannelAccess::Visible, CheckReport::Quiet),
                ("20", ChannelAccess::Hidden, CheckReport::Unusable),
                ("30", ChannelAccess::Unknown, CheckReport::Unusable),
            ],
            "one check, so at most one warning, per entry"
        );
    }

    #[test]
    fn a_new_session_checks_again_and_a_resume_continues() {
        let cfg = channels(&["10", "20"]);
        let (mut checks, gw) = checking(0);
        assert_eq!(checks.due(0, &cfg, &gw, true), Some("10"));
        checks.on_checked(0, "10", &ChannelAccess::Hidden);
        // The connection drops and the session resumes: 10 is not checked
        // again.
        checks.on_identified(5_000, true);
        assert_eq!(checks.due(5_000, &cfg, &gw, true), Some("20"));
        checks.on_checked(5_000, "20", &ChannelAccess::Visible);
        assert_eq!(
            checks.due(60_000, &cfg, &gw, true),
            None,
            "every entry is checked"
        );
        // READY starts a new session, which checks every entry again.
        checks.on_identified(60_000, false);
        assert_eq!(checks.due(60_000, &cfg, &gw, true), Some("10"));
    }

    #[test]
    fn nothing_is_checked_between_a_disconnect_and_resumed() {
        let cfg = channels(&["10"]);
        let (mut checks, mut gw) = checking(0);
        gw.on_disconnect(10, Disconnect::Transport);
        assert_eq!(checks.due(2_000, &cfg, &gw, true), None, "no session");
        gw.on_connected(2_000, "wss://resume.discord.gg", true);
        gw.on_frame(2_000, &hello(40_000), &cfg);
        gw.on_handshake_sent(2_000);
        assert_eq!(
            checks.due(2_000, &cfg, &gw, true),
            None,
            "the resume has not completed"
        );
        assert_eq!(
            gw.on_frame(2_100, r#"{"op":0,"t":"RESUMED","s":2,"d":{}}"#, &cfg),
            FrameAction::Identified { resumed: true }
        );
        checks.on_identified(2_100, true);
        assert_eq!(checks.due(2_100, &cfg, &gw, true), Some("10"));
    }

    #[test]
    fn nothing_is_checked_while_gateway_events_or_messages_wait() {
        let cfg = channels(&["10"]);
        let (checks, gw) = checking(0);
        assert_eq!(checks.due(0, &cfg, &gw, false), None);
        assert_eq!(checks.due(0, &cfg, &gw, true), Some("10"));
    }

    #[test]
    fn channel_checks_are_spaced_and_wait_out_a_rate_limit() {
        let cfg = channels(&["10", "20"]);
        let (mut checks, gw) = checking(0);
        assert_eq!(checks.due(0, &cfg, &gw, true), Some("10"));
        assert_eq!(
            checks.on_checked(0, "10", &classify_channel(429, br#"{"retry_after":3}"#)),
            CheckReport::Quiet
        );
        assert_eq!(checks.due(2_999, &cfg, &gw, true), None);
        assert_eq!(
            checks.due(3_000, &cfg, &gw, true),
            Some("10"),
            "the same entry again"
        );
        checks.on_checked(3_000, "10", &ChannelAccess::Visible);
        assert_eq!(
            checks.due(3_000 + CHANNEL_CHECK_SPACING_MS - 1, &cfg, &gw, true),
            None
        );
        assert_eq!(
            checks.due(3_000 + CHANNEL_CHECK_SPACING_MS, &cfg, &gw, true),
            Some("20")
        );
        // A rate limit shorter than the spacing still waits the spacing.
        checks.on_checked(
            4_000,
            "20",
            &ChannelAccess::RateLimited { retry_after_ms: 1 },
        );
        assert_eq!(
            checks.due(4_000 + CHANNEL_CHECK_SPACING_MS - 1, &cfg, &gw, true),
            None
        );
        assert_eq!(
            checks.due(4_000 + CHANNEL_CHECK_SPACING_MS, &cfg, &gw, true),
            Some("20")
        );
    }

    #[test]
    fn a_ready_keeps_a_pending_rate_limit_wait() {
        let cfg = channels(&["10"]);
        let (mut checks, gw) = checking(0);
        checks.on_checked(
            0,
            "10",
            &ChannelAccess::RateLimited {
                retry_after_ms: 30_000,
            },
        );
        // The session is invalidated and a new one starts 8 s in.
        checks.on_identified(8_000, false);
        assert_eq!(checks.due(29_999, &cfg, &gw, true), None);
        assert_eq!(checks.due(30_000, &cfg, &gw, true), Some("10"));
    }

    #[test]
    fn a_check_without_a_response_is_retried_twice_then_reported() {
        let cfg = channels(&["10", "20"]);
        let (mut checks, gw) = checking(0);
        let failed = ChannelAccess::Failed { status: 0 };
        assert_eq!(checks.on_checked(0, "10", &failed), CheckReport::Quiet);
        assert_eq!(
            checks.due(CHANNEL_CHECK_RETRY_MS - 1, &cfg, &gw, true),
            None
        );
        let t = CHANNEL_CHECK_RETRY_MS;
        assert_eq!(checks.due(t, &cfg, &gw, true), Some("10"));
        let bad_gateway = ChannelAccess::Failed { status: 502 };
        assert_eq!(checks.on_checked(t, "10", &bad_gateway), CheckReport::Quiet);
        let t = t + 2 * CHANNEL_CHECK_RETRY_MS;
        assert_eq!(checks.due(t - 1, &cfg, &gw, true), None, "twice as long");
        assert_eq!(checks.due(t, &cfg, &gw, true), Some("10"));
        assert_eq!(checks.on_checked(t, "10", &failed), CheckReport::GaveUp);
        // Given up for this session; the next entry follows.
        let t = t + CHANNEL_CHECK_SPACING_MS;
        assert_eq!(checks.due(t, &cfg, &gw, true), Some("20"));
        checks.on_checked(t, "20", &ChannelAccess::Visible);
        assert_eq!(checks.due(t + 60_000, &cfg, &gw, true), None);
    }

    #[test]
    fn a_new_session_gives_a_failing_entry_its_retries_back() {
        let (mut checks, _) = checking(0);
        let failed = ChannelAccess::Failed { status: 0 };
        assert_eq!(checks.on_checked(0, "10", &failed), CheckReport::Quiet);
        checks.on_identified(1_000, false);
        assert_eq!(checks.on_checked(30_000, "10", &failed), CheckReport::Quiet);
        assert_eq!(checks.on_checked(90_000, "10", &failed), CheckReport::Quiet);
        assert_eq!(
            checks.on_checked(150_000, "10", &failed),
            CheckReport::GaveUp
        );
    }

    #[test]
    fn any_other_failure_is_reported_at_once() {
        let cfg = channels(&["10"]);
        let (mut checks, gw) = checking(0);
        assert_eq!(
            checks.on_checked(0, "10", &ChannelAccess::Failed { status: 401 }),
            CheckReport::GaveUp
        );
        assert_eq!(checks.due(60_000, &cfg, &gw, true), None);
    }

    #[test]
    fn channel_checks_follow_the_current_config() {
        let (mut checks, gw) = checking(0);
        assert_eq!(
            checks.due(0, &DiscordConfig::default(), &gw, true),
            None,
            "an empty list watches every channel"
        );
        let cfg = channels(&["10", "10"]);
        assert_eq!(checks.due(0, &cfg, &gw, true), Some("10"));
        checks.on_checked(0, "10", &ChannelAccess::Visible);
        assert_eq!(
            checks.due(60_000, &cfg, &gw, true),
            None,
            "a duplicate entry is checked once"
        );
        // An entry an edit adds is checked on a later call.
        assert_eq!(
            checks.due(60_000, &channels(&["10", "30"]), &gw, true),
            Some("30")
        );
    }

    // ── close codes ──

    #[test]
    fn close_classification() {
        assert_eq!(
            classify_close(Some(4004)),
            CloseClass::Fatal(FatalClose::AuthenticationFailed)
        );
        assert_eq!(
            classify_close(Some(4014)),
            CloseClass::Fatal(FatalClose::DisallowedIntents)
        );
        assert_eq!(
            classify_close(Some(4011)),
            CloseClass::Fatal(FatalClose::Sharding)
        );
        assert_eq!(classify_close(Some(4007)), CloseClass::NewSession);
        assert_eq!(classify_close(Some(4009)), CloseClass::NewSession);
        for code in [
            Some(1000),
            Some(1001),
            Some(1012),
            Some(4000),
            Some(4008),
            None,
        ] {
            assert_eq!(classify_close(code), CloseClass::Resume, "{code:?}");
        }
    }

    #[test]
    fn privileged_intent_names_and_hints() {
        assert_eq!(privileged_intents(DEFAULT_INTENTS), vec!["Message Content"]);
        assert_eq!(
            privileged_intents(INTENT_GUILD_MEMBERS | INTENT_GUILD_PRESENCES),
            vec!["Server Members", "Presence"]
        );
        assert!(ParkReason::DisallowedIntents
            .hint(DEFAULT_INTENTS)
            .contains("Message Content"));
        assert!(ParkReason::DisallowedIntents
            .hint(INTENT_GUILDS)
            .contains("mask 1"));
    }

    // ── state machine ──

    #[test]
    fn fresh_gateway_discovers_then_dials_on_a_later_call() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 1);
        assert_eq!(gw.next_step(0, &cfg), Step::Discover);
        gw.on_discovery(0, ready_discovery());
        assert_eq!(
            gw.next_step(0, &cfg),
            Step::Connect {
                url: GATEWAY.into(),
                resume: false
            }
        );
    }

    #[test]
    fn gateway_url_skips_discovery() {
        let cfg = DiscordConfig {
            gateway_url: Some("ws://127.0.0.1:8765/gateway".into()),
            ..DiscordConfig::default()
        };
        let gw = Gateway::new(0, BOT, 1);
        assert_eq!(
            gw.next_step(0, &cfg),
            Step::Connect {
                url: "ws://127.0.0.1:8765/gateway".into(),
                resume: false
            }
        );
    }

    #[test]
    fn hello_owes_an_identify_and_schedules_a_jittered_heartbeat() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 99);
        gw.on_discovery(0, ready_discovery());
        gw.on_connected(0, GATEWAY, false);
        let action = gw.on_frame(1_000, &hello(40_000), &cfg);
        assert_eq!(
            action,
            FrameAction::Handshake(Handshake::Identify {
                intents: DEFAULT_INTENTS
            })
        );
        assert!(gw.owed_handshake().is_some(), "owed until sent");
        // The first beat falls somewhere inside the first interval.
        assert_eq!(gw.heartbeat_step(999, true), Beat::Idle);
        let due = (1_000..=41_000)
            .find(|t| gw.heartbeat_step(*t, true) != Beat::Idle)
            .unwrap();
        assert!(due < 41_000, "jittered into the first interval, got {due}");
        assert!(matches!(gw.heartbeat_step(41_000, true), Beat::Send(_)));
        gw.on_handshake_sent(1_000);
        assert!(gw.owed_handshake().is_none());
    }

    #[test]
    fn hello_without_interval_uses_the_default() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_connected(0, GATEWAY, false);
        gw.on_frame(0, r#"{"op":10,"d":{}}"#, &cfg);
        assert!(matches!(
            gw.heartbeat_step(DEFAULT_HEARTBEAT_MS, true),
            Beat::Send(_)
        ));
    }

    #[test]
    fn a_connection_without_hello_or_session_is_dropped() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_connected(0, GATEWAY, false);
        assert!(!gw.handshake_overdue(HELLO_TIMEOUT_MS - 1));
        assert!(gw.handshake_overdue(HELLO_TIMEOUT_MS), "no Hello");

        gw.on_frame(5_000, &hello(40_000), &cfg);
        gw.on_handshake_sent(5_000);
        assert!(!gw.handshake_overdue(HELLO_TIMEOUT_MS), "Hello arrived");
        assert!(!gw.handshake_overdue(5_000 + SESSION_TIMEOUT_MS - 1));
        assert!(gw.handshake_overdue(5_000 + SESSION_TIMEOUT_MS), "no READY");

        gw.on_frame(6_000, &ready(1), &gw_cfg());
        assert!(!gw.handshake_overdue(u64::MAX), "established");
    }

    fn gw_cfg() -> DiscordConfig {
        DiscordConfig::default()
    }

    #[test]
    fn a_resume_that_never_completes_falls_back_to_identify() {
        let (mut gw, cfg) = established(0);
        gw.on_disconnect(10, Disconnect::Transport);
        gw.on_connected(2_000, "wss://resume.discord.gg", true);
        gw.on_frame(2_000, &hello(40_000), &cfg);
        gw.on_handshake_sent(2_000);
        assert!(gw.handshake_overdue(2_000 + SESSION_TIMEOUT_MS));
        gw.on_disconnect(2_000 + SESSION_TIMEOUT_MS, Disconnect::HandshakeTimeout);
        assert!(!gw.can_resume());
    }

    #[test]
    fn a_missing_hello_keeps_the_session() {
        let (mut gw, _) = established(0);
        gw.on_disconnect(10, Disconnect::Transport);
        gw.on_connected(2_000, "wss://resume.discord.gg", true);
        assert!(gw.handshake_overdue(2_000 + HELLO_TIMEOUT_MS));
        gw.on_disconnect(2_000 + HELLO_TIMEOUT_MS, Disconnect::HandshakeTimeout);
        assert!(gw.can_resume(), "the next connection resumes");
    }

    #[test]
    fn ready_establishes_a_resumable_session() {
        let (gw, _) = established(0);
        assert!(gw.identified() && gw.can_resume());
        assert_eq!(gw.bot_user_id(), BOT);
        assert_eq!(gw.health(true), Health::Healthy);
    }

    #[test]
    fn heartbeats_are_acknowledged_or_the_connection_is_a_zombie() {
        let (mut gw, cfg) = established(0);
        let Beat::Send(payload) = gw.heartbeat_step(40_000, true) else {
            panic!("first heartbeat is due by one interval");
        };
        assert!(payload.contains("\"d\":1"), "carries the last sequence");
        gw.on_heartbeat_sent(40_000);
        assert_eq!(gw.on_frame(40_100, r#"{"op":11}"#, &cfg), FrameAction::None);
        assert!(matches!(gw.heartbeat_step(80_000, true), Beat::Send(_)));
        gw.on_heartbeat_sent(80_000);
        // No ACK by the next beat, and every queued event was read.
        assert_eq!(
            gw.heartbeat_step(120_000, false),
            Beat::Idle,
            "the ACK may still be queued"
        );
        assert_eq!(gw.heartbeat_step(120_000, true), Beat::Zombie);
    }

    #[test]
    fn a_server_heartbeat_request_reschedules_the_next_beat() {
        let (mut gw, cfg) = established(0);
        let FrameAction::Send(beat) = gw.on_frame(5, r#"{"op":1,"d":null}"#, &cfg) else {
            panic!("op 1 asks for a heartbeat");
        };
        assert!(beat.contains("\"op\":1"));
        gw.on_heartbeat_sent(5);
        assert_eq!(
            gw.heartbeat_step(39_999, true),
            Beat::Idle,
            "the next beat is one interval out"
        );
        assert_eq!(
            gw.heartbeat_step(40_005, true),
            Beat::Zombie,
            "and that request awaits an ACK"
        );
    }

    #[test]
    fn a_dropped_connection_resumes_at_the_resume_url() {
        let (mut gw, cfg) = established(0);
        gw.on_disconnect(10, Disconnect::Closed(Some(1006)));
        assert!(gw.can_resume());
        assert_eq!(gw.next_step(10, &cfg), Step::Wait, "backoff first");
        assert_eq!(
            gw.next_step(10 + BACKOFF_FLOOR_MS, &cfg),
            Step::Connect {
                url: "wss://resume.discord.gg".into(),
                resume: true
            }
        );
        gw.on_connected(2_000, "wss://resume.discord.gg", true);
        assert_eq!(
            gw.on_frame(2_000, &hello(40_000), &cfg),
            FrameAction::Handshake(Handshake::Resume {
                session_id: "sess".into(),
                seq: 1
            })
        );
    }

    #[test]
    fn op7_reconnects_a_settled_session_at_once_and_backs_off_repeats() {
        let (mut gw, cfg) = established(0);
        let t = SESSION_SETTLED_MS;
        assert_eq!(
            gw.on_frame(t, r#"{"op":7,"d":null}"#, &cfg),
            FrameAction::Reconnect { keep_session: true }
        );
        gw.on_disconnect(t, Disconnect::ServerReconnect { keep_session: true });
        assert!(matches!(
            gw.next_step(t, &cfg),
            Step::Connect { resume: true, .. }
        ));
        // The gateway asks again right after the resume: back off, even though
        // RESUMED arrived.
        gw.on_connected(t + 1, "wss://resume.discord.gg", true);
        gw.on_frame(t + 1, &hello(40_000), &cfg);
        gw.on_handshake_sent(t + 1);
        assert_eq!(
            gw.on_frame(t + 2, r#"{"op":0,"t":"RESUMED","s":2,"d":{}}"#, &cfg),
            FrameAction::Identified { resumed: true }
        );
        gw.on_disconnect(t + 3, Disconnect::ServerReconnect { keep_session: true });
        assert_eq!(gw.next_step(t + 3, &cfg), Step::Wait);
        assert!(matches!(
            gw.next_step(t + 3 + BACKOFF_FLOOR_MS, &cfg),
            Step::Connect { .. }
        ));
    }

    #[test]
    fn invalid_session_resumable_or_not() {
        let (mut gw, cfg) = established(0);
        assert_eq!(
            gw.on_frame(5, r#"{"op":9,"d":true}"#, &cfg),
            FrameAction::Reconnect { keep_session: true }
        );
        assert!(gw.can_resume());
        let (mut gw, cfg) = established(0);
        assert_eq!(
            gw.on_frame(5, r#"{"op":9,"d":false}"#, &cfg),
            FrameAction::Reconnect {
                keep_session: false
            }
        );
        assert!(!gw.can_resume(), "a non-resumable invalid session is wiped");
        gw.on_disconnect(
            5,
            Disconnect::ServerReconnect {
                keep_session: false,
            },
        );
        assert_eq!(gw.next_step(5, &cfg), Step::Wait);
        assert_eq!(
            gw.next_step(5 + INVALID_SESSION_WAIT_MS, &cfg),
            Step::Discover
        );
    }

    #[test]
    fn identify_gate_spaces_identifies() {
        let (mut gw, cfg) = established(0);
        gw.on_disconnect(10, Disconnect::Closed(Some(4009)));
        assert!(!gw.can_resume(), "4009 needs a new session");
        assert_eq!(gw.next_step(10 + BACKOFF_FLOOR_MS, &cfg), Step::Discover);
        gw.on_discovery(1_100, ready_discovery());
        // Last IDENTIFY at t=0: the next waits until t=5000.
        assert_eq!(gw.next_step(1_100, &cfg), Step::Wait);
        assert!(matches!(
            gw.next_step(IDENTIFY_SPACING_MS, &cfg),
            Step::Connect { resume: false, .. }
        ));
    }

    #[test]
    fn identifies_are_capped_per_hour_even_without_discovery() {
        let cfg = DiscordConfig {
            gateway_url: Some("ws://127.0.0.1:8765/gateway".into()),
            ..DiscordConfig::default()
        };
        let mut gw = Gateway::new(0, BOT, 1);
        let mut t = 0;
        let mut identifies = 0;
        // Every session is closed with 4009 right after READY.
        while t < IDENTIFY_WINDOW_MS {
            match gw.next_step(t, &cfg) {
                Step::Connect { url, resume } => {
                    gw.on_connected(t, &url, resume);
                    gw.on_frame(t, &hello(40_000), &cfg);
                    gw.on_handshake_sent(t);
                    identifies += 1;
                    gw.on_frame(t, &ready(1), &cfg);
                    gw.on_disconnect(t, Disconnect::Closed(Some(4009)));
                }
                Step::Wait => {}
                other => panic!("unexpected {other:?}"),
            }
            t += 1_000;
        }
        assert_eq!(identifies, MAX_IDENTIFIES_PER_HOUR);
    }

    #[test]
    fn a_low_identify_budget_slows_identifies_and_an_empty_one_waits_for_reset() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_discovery(
            0,
            Discovery::Ready {
                url: "wss://g".into(),
                remaining: Some(50),
                reset_after_ms: Some(1),
            },
        );
        gw.on_connected(0, "wss://g", false);
        gw.on_frame(0, &hello(40_000), &cfg);
        gw.on_handshake_sent(0);
        gw.on_disconnect(10, Disconnect::Closed(Some(4009)));
        gw.on_discovery(2_000, ready_discovery());
        assert_eq!(gw.next_step(IDENTIFY_SPACING_MS, &cfg), Step::Wait);
        assert!(matches!(
            gw.next_step(LOW_BUDGET_IDENTIFY_SPACING_MS, &cfg),
            Step::Connect { .. }
        ));

        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_discovery(
            0,
            Discovery::Ready {
                url: "wss://g".into(),
                remaining: Some(0),
                reset_after_ms: Some(90_000),
            },
        );
        assert_eq!(gw.next_step(89_999, &cfg), Step::Wait);
        assert!(matches!(gw.next_step(90_000, &cfg), Step::Connect { .. }));
    }

    #[test]
    fn a_resume_is_not_held_by_the_identify_gate() {
        let (mut gw, cfg) = established(0);
        gw.on_disconnect(10, Disconnect::Transport);
        // Discovery says the daily budget is spent, but a resume spends none.
        gw.on_discovery(
            1_000,
            Discovery::Ready {
                url: GATEWAY.into(),
                remaining: Some(0),
                reset_after_ms: Some(3_600_000),
            },
        );
        assert!(matches!(
            gw.next_step(1_000, &cfg),
            Step::Connect { resume: true, .. }
        ));
    }

    #[test]
    fn fatal_close_parks_and_probes_on_a_doubling_schedule() {
        let (mut gw, cfg) = established(0);
        gw.on_disconnect(0, Disconnect::Closed(Some(4014)));
        assert_eq!(
            gw.phase(),
            &Phase::Parked {
                reason: ParkReason::DisallowedIntents,
                probe_at_ms: PARK_FIRST_PROBE_MS
            }
        );
        assert!(gw.stopped());
        assert_eq!(gw.health(true), Health::Unhealthy);
        assert_eq!(gw.next_step(PARK_FIRST_PROBE_MS - 1, &cfg), Step::Wait);
        assert_eq!(gw.next_step(PARK_FIRST_PROBE_MS, &cfg), Step::Discover);
        // A probe that fails keeps it parked, twice as long.
        gw.on_discovery(PARK_FIRST_PROBE_MS, Discovery::Failed { status: 0 });
        assert_eq!(
            gw.phase(),
            &Phase::Parked {
                reason: ParkReason::DisallowedIntents,
                probe_at_ms: PARK_FIRST_PROBE_MS * 3
            }
        );
        // A probe that succeeds dials again.
        gw.on_discovery(PARK_FIRST_PROBE_MS * 3, ready_discovery());
        assert_eq!(gw.phase().kind(), "dial");
    }

    #[test]
    fn a_parked_instance_with_a_configured_gateway_probes_by_dialing_it() {
        let cfg = DiscordConfig {
            gateway_url: Some("ws://127.0.0.1:8765/gateway".into()),
            ..DiscordConfig::default()
        };
        let (mut gw, _) = established(0);
        gw.on_disconnect(0, Disconnect::Closed(Some(4004)));
        assert_eq!(
            gw.next_step(PARK_FIRST_PROBE_MS, &cfg),
            Step::Connect {
                url: "ws://127.0.0.1:8765/gateway".into(),
                resume: false
            }
        );
    }

    #[test]
    fn a_rejected_token_stays_parked_without_spending_an_identify() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_discovery(0, Discovery::Unauthorized);
        assert!(matches!(
            gw.phase(),
            Phase::Parked {
                reason: ParkReason::InvalidToken,
                ..
            }
        ));
        let mut t = 0;
        for _ in 0..12 {
            let Phase::Parked { probe_at_ms, .. } = *gw.phase() else {
                panic!("stays parked")
            };
            assert!(probe_at_ms > t);
            t = probe_at_ms;
            assert_eq!(
                gw.next_step(t, &cfg),
                Step::Discover,
                "probes discovery, never dials"
            );
            gw.on_discovery(t, Discovery::Unauthorized);
        }
        let Phase::Parked { probe_at_ms, .. } = *gw.phase() else {
            panic!()
        };
        assert_eq!(
            probe_at_ms - t,
            PARK_MAX_PROBE_MS,
            "the probe delay is capped"
        );
    }

    #[test]
    fn oversize_wipes_the_session_and_parks_after_three_strikes() {
        let (mut gw, _) = established(0);
        gw.on_disconnect(1, Disconnect::Oversize);
        assert!(!gw.can_resume(), "resuming would replay the event");
        assert_eq!(
            gw.phase(),
            &Phase::Down {
                retry_at_ms: 1 + OVERSIZE_FLOOR_MS
            }
        );
        gw.on_disconnect(2, Disconnect::Oversize);
        gw.on_disconnect(3, Disconnect::Oversize);
        assert!(matches!(
            gw.phase(),
            Phase::Parked {
                reason: ParkReason::Oversize,
                ..
            }
        ));
    }

    #[test]
    fn a_stable_session_clears_strikes() {
        let (mut gw, cfg) = established(0);
        gw.on_disconnect(1, Disconnect::Oversize);
        gw.on_disconnect(2, Disconnect::Oversize);
        // Reconnect and stay up long enough.
        gw.on_discovery(40_000, ready_discovery());
        gw.on_connected(40_000, GATEWAY, false);
        gw.on_frame(40_000, &hello(40_000), &cfg);
        gw.on_handshake_sent(40_000);
        gw.on_frame(40_000, &ready(1), &cfg);
        gw.on_disconnect(40_000 + STABLE_SESSION_MS, Disconnect::Oversize);
        assert!(
            matches!(gw.phase(), Phase::Down { .. }),
            "strikes restarted at one"
        );
    }

    #[test]
    fn backoff_doubles_to_the_ceiling_and_resets_after_a_settled_session() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 1);
        let mut delays = Vec::new();
        for _ in 0..8 {
            gw.on_connect_failed(0, ConnectFailure::Transient, false);
            let Phase::Down { retry_at_ms } = *gw.phase() else {
                panic!()
            };
            delays.push(retry_at_ms);
        }
        assert_eq!(
            delays,
            vec![1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000]
        );
        // A session that drops at once keeps backing off.
        gw.on_discovery(0, ready_discovery());
        gw.on_connected(0, GATEWAY, false);
        gw.on_frame(0, &hello(40_000), &cfg);
        gw.on_frame(0, &ready(1), &cfg);
        gw.on_disconnect(1, Disconnect::Transport);
        assert_eq!(
            gw.phase(),
            &Phase::Down {
                retry_at_ms: 1 + BACKOFF_CEILING_MS
            }
        );
        // One that settles resets it.
        gw.on_connected(100_000, "wss://resume.discord.gg", true);
        gw.on_frame(100_000, &hello(40_000), &cfg);
        gw.on_frame(100_000, r#"{"op":0,"t":"RESUMED","s":2,"d":{}}"#, &cfg);
        gw.on_disconnect(100_000 + SESSION_SETTLED_MS, Disconnect::Transport);
        assert_eq!(
            gw.phase(),
            &Phase::Down {
                retry_at_ms: 100_000 + SESSION_SETTLED_MS + BACKOFF_FLOOR_MS
            }
        );
    }

    #[test]
    fn a_discovery_rate_limit_waits_at_least_as_long_as_asked() {
        let cfg = DiscordConfig::default();
        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_discovery(
            0,
            Discovery::RateLimited {
                retry_after_ms: 7_000,
            },
        );
        assert_eq!(gw.phase(), &Phase::Down { retry_at_ms: 7_000 });
        assert_eq!(gw.next_step(6_999, &cfg), Step::Wait);
        assert_eq!(gw.next_step(7_000, &cfg), Step::Discover);
    }

    #[test]
    fn dial_failures_are_classified() {
        let cfg = DiscordConfig::default();
        // The host refused the discovered gateway: the operator must grant it.
        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_discovery(0, ready_discovery());
        gw.on_connect_failed(0, ConnectFailure::DestinationDenied, false);
        assert_eq!(
            gw.phase(),
            &Phase::Misconfigured {
                reason: Misconfiguration::EgressDenied,
                retry_at_ms: MISCONFIGURED_RETRY_MS
            }
        );
        assert_eq!(gw.health(true), Health::Unhealthy);
        assert_eq!(
            gw.next_step(MISCONFIGURED_RETRY_MS, &cfg),
            Step::Discover,
            "retried once a minute"
        );

        // A refused resume host falls back to discovery with a new session.
        let (mut gw, cfg) = established(0);
        gw.on_disconnect(0, Disconnect::Transport);
        gw.on_connect_failed(1_000, ConnectFailure::DestinationDenied, true);
        assert!(!gw.can_resume());
        assert_eq!(gw.next_step(10_000, &cfg), Step::Discover);

        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_connect_failed(0, ConnectFailure::AccessDenied, false);
        assert!(matches!(
            gw.phase(),
            Phase::Misconfigured {
                reason: Misconfiguration::AccessDenied,
                ..
            }
        ));

        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_connect_failed(0, ConnectFailure::InvalidUrl, false);
        assert!(matches!(
            gw.phase(),
            Phase::Misconfigured {
                reason: Misconfiguration::InvalidGatewayUrl,
                ..
            }
        ));
    }

    #[test]
    fn health_comes_from_the_session_or_from_discord() {
        let mut gw = Gateway::new(0, BOT, 1);
        assert_eq!(gw.health(true), Health::AskDiscord, "no session yet");
        assert_eq!(gw.health(false), Health::Unhealthy, "config unreadable");
        gw.on_discovery(0, ready_discovery());
        gw.on_connected(0, GATEWAY, false);
        assert_eq!(gw.health(true), Health::AskDiscord, "handshake pending");

        let (mut gw, _) = established(0);
        assert_eq!(gw.health(true), Health::Healthy);
        assert_eq!(gw.health(false), Health::Unhealthy);
        gw.on_disconnect(1, Disconnect::Transport);
        assert_eq!(gw.health(true), Health::AskDiscord, "between sessions");
        gw.on_connect_failed(2, ConnectFailure::DestinationDenied, false);
        assert_eq!(gw.health(true), Health::Unhealthy, "refused");
    }

    #[test]
    fn messages_are_filtered_against_the_current_bot_id() {
        let (mut gw, cfg) = established(0);
        let own = format!(
            r#"{{"op":0,"t":"MESSAGE_CREATE","s":2,"d":{{"id":"5","type":0,"channel_id":"c","author":{{"id":"{BOT}"}},"content":"echo"}}}}"#
        );
        assert_eq!(gw.on_frame(1, &own, &cfg), FrameAction::None);
        let other = r#"{"op":0,"t":"MESSAGE_CREATE","s":3,"d":{"id":"6","type":0,"channel_id":"c","author":{"id":"7"},"content":"hi"}}"#;
        assert!(matches!(gw.on_frame(1, other, &cfg), FrameAction::Emit(m) if m.content == "hi"));
        // Sequence numbers are tracked from dispatches.
        let Beat::Send(beat) = gw.heartbeat_step(40_000, true) else {
            panic!()
        };
        assert!(beat.contains("\"d\":3"));
    }

    #[test]
    fn unknown_frames_are_ignored() {
        let (mut gw, cfg) = established(0);
        assert_eq!(gw.on_frame(1, r#"{"op":42}"#, &cfg), FrameAction::None);
        assert_eq!(gw.on_frame(1, "not json", &cfg), FrameAction::None);
        assert_eq!(
            gw.on_frame(1, r#"{"op":0,"t":"TYPING_START","s":4,"d":{}}"#, &cfg),
            FrameAction::None
        );
    }

    #[test]
    fn a_resume_url_must_not_downgrade_to_plaintext() {
        let cfg = DiscordConfig::default();
        let ready_with = |url: &str| {
            format!(
                r#"{{"op":0,"t":"READY","s":1,"d":{{"session_id":"s","resume_gateway_url":"{url}","user":{{"id":"1"}}}}}}"#
            )
        };
        // Over wss, a ws:// or non-WebSocket resume URL is ignored: rediscover.
        for url in ["ws://evil.example", "https://evil.example"] {
            let mut gw = Gateway::new(0, BOT, 1);
            gw.on_discovery(0, ready_discovery());
            gw.on_connected(0, GATEWAY, false);
            gw.on_frame(0, &hello(40_000), &cfg);
            gw.on_frame(0, &ready_with(url), &cfg);
            gw.on_disconnect(0, Disconnect::Transport);
            assert_eq!(
                gw.next_step(BACKOFF_FLOOR_MS, &cfg),
                Step::Discover,
                "{url}"
            );
        }
        // A plaintext connection (a local test gateway) may resume over ws.
        let mut gw = Gateway::new(0, BOT, 1);
        gw.on_connected(0, "ws://127.0.0.1:8765/gateway", false);
        gw.on_frame(0, &hello(40_000), &cfg);
        gw.on_frame(0, &ready_with("ws://127.0.0.1:8765/resume"), &cfg);
        gw.on_disconnect(0, Disconnect::Transport);
        assert_eq!(
            gw.next_step(BACKOFF_FLOOR_MS, &cfg),
            Step::Connect {
                url: "ws://127.0.0.1:8765/resume".into(),
                resume: true
            }
        );
    }
}
