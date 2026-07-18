//! Pure Bluesky / AT Protocol logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it maps an
//! `app.bsky.notification.listNotifications` entry to the fields the host's
//! inbound message needs, builds the XRPC request bodies (`createSession`,
//! `createRecord`, `updateSeen`), and encodes/decodes the reply-threading
//! strong refs. The `#[cfg(target_family = "wasm")]` component shim in `lib.rs`
//! does only the I/O (waki HTTP calls with a `Bearer` token) and reuses this
//! logic verbatim, so the interesting behavior is covered by a plain host
//! `cargo test`.

use serde::Deserialize;
use serde_json::{Value, json};

/// The plugin's config section (`[channels.bluesky.<alias>]` for a mirror, or
/// `[[plugins.entries.bluesky]].config` as a novel plugin). Field names match
/// the native `BlueskyConfig` snake_case keys so a mirror plugin can be fed the
/// native section verbatim; serde ignores the fields this plugin does not
/// use (`enabled`, `excluded_tools`). `service` is an optional override the
/// native config doesn't carry — it defaults to the public PDS.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BlueskyConfig {
    /// Bluesky handle / identifier, e.g. `"mybot.bsky.social"`. Sent as the
    /// `identifier` to `createSession`. Required to reach the API.
    #[serde(default)]
    pub handle: String,
    /// App-specific password (Bluesky Settings → App Passwords). Sent as the
    /// `password` to `createSession`.
    #[serde(default)]
    pub app_password: String,
    /// PDS / service origin. Overridable for a self-hosted PDS or a test mock;
    /// defaults to the public `https://bsky.social`.
    #[serde(default = "default_service")]
    pub service: String,
}

fn default_service() -> String {
    "https://bsky.social".to_string()
}

impl BlueskyConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// Service origin with any trailing slash trimmed, for consistent XRPC path
    /// joins. Falls back to the public PDS when unset (the struct `Default`
    /// leaves `service` empty; only `from_json` applies the serde default).
    pub fn base_url(&self) -> String {
        let s = self.service.trim().trim_end_matches('/');
        if s.is_empty() {
            "https://bsky.social".to_string()
        } else {
            s.to_string()
        }
    }

    /// Whether both credentials are present — the "not configured" sentinel the
    /// shim checks before making any call.
    pub fn has_credentials(&self) -> bool {
        !self.handle.trim().is_empty() && !self.app_password.is_empty()
    }
}

/// The authenticated session cached by the shim after `createSession` (or a
/// re-auth on a 401).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Session {
    pub access_jwt: String,
    pub did: String,
    pub handle: String,
}

/// A Bluesky notification mapped to the host inbound-message fields (the
/// `channel` is always `"bluesky"`, stamped by the host shim).
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

/// The parent + root strong refs decoded from a `reply_target`, used to thread a
/// reply post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRefs {
    pub parent_uri: String,
    pub parent_cid: String,
    pub root_uri: String,
    pub root_cid: String,
}

/// XRPC method paths (joined onto `BlueskyConfig::base_url` with `/xrpc/`).
pub const NSID_CREATE_SESSION: &str = "com.atproto.server.createSession";
pub const NSID_LIST_NOTIFICATIONS: &str = "app.bsky.notification.listNotifications";
pub const NSID_UPDATE_SEEN: &str = "app.bsky.notification.updateSeen";
pub const NSID_CREATE_RECORD: &str = "com.atproto.repo.createRecord";

/// A Bluesky post is capped at 300 grapheme clusters; we approximate with a
/// `char` count (mirrors the native channel).
pub const MAX_POST_CHARS: usize = 300;

/// Build the full XRPC URL for a method given the service base URL.
pub fn xrpc_url(base_url: &str, nsid: &str) -> String {
    format!("{}/xrpc/{}", base_url.trim_end_matches('/'), nsid)
}

/// Body for `com.atproto.server.createSession`.
pub fn build_create_session(identifier: &str, password: &str) -> Value {
    json!({ "identifier": identifier, "password": password })
}

/// Parse a `createSession` response into the cached [`Session`]. `accessJwt` and
/// `did` are required; `handle` is best-effort (used for `self_handle`).
pub fn parse_session(response: &Value) -> Option<Session> {
    let access_jwt = response.get("accessJwt").and_then(Value::as_str)?;
    let did = response.get("did").and_then(Value::as_str)?;
    if access_jwt.is_empty() || did.is_empty() {
        return None;
    }
    Some(Session {
        access_jwt: access_jwt.to_string(),
        did: did.to_string(),
        handle: response
            .get("handle")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

/// Extract the `notifications` array from a `listNotifications` response.
pub fn extract_notifications(response: &Value) -> Vec<Value> {
    response
        .get("notifications")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The `indexedAt` of a notification, or `""` when absent.
pub fn notification_indexed_at(notif: &Value) -> &str {
    notif.get("indexedAt").and_then(Value::as_str).unwrap_or("")
}

/// The lexicographically-latest `indexedAt` across a batch (AT Protocol emits
/// fixed-width RFC-3339 UTC timestamps, so lexical order == chronological
/// order). This is tracked as the poll cursor / `updateSeen` marker.
pub fn latest_indexed_at(notifs: &[Value]) -> Option<String> {
    notifs
        .iter()
        .map(notification_indexed_at)
        .filter(|s| !s.is_empty())
        .max()
        .map(ToString::to_string)
}

/// Encode a notification's parent + root strong refs into the `reply_target`
/// compound the shim round-trips into `send`: `parent_uri|parent_cid|root_uri|root_cid`.
pub fn encode_reply_target(parent_uri: &str, parent_cid: &str, root_uri: &str, root_cid: &str) -> String {
    format!("{parent_uri}|{parent_cid}|{root_uri}|{root_cid}")
}

/// Decode a `reply_target`/recipient into its parent + root strong refs.
///
/// Accepts three forms:
///   - `parent_uri|parent_cid|root_uri|root_cid` (this plugin's compound),
///   - `uri|cid` (the native channel's legacy 2-part form — parent == root),
///   - anything without a `|` (a bare recipient) → `None` (a top-level post).
pub fn decode_reply_target(reply_target: &str) -> Option<ReplyRefs> {
    if !reply_target.contains('|') {
        return None;
    }
    let parts: Vec<&str> = reply_target.split('|').collect();
    match parts.as_slice() {
        [uri, cid] if !uri.is_empty() && !cid.is_empty() => Some(ReplyRefs {
            parent_uri: (*uri).to_string(),
            parent_cid: (*cid).to_string(),
            root_uri: (*uri).to_string(),
            root_cid: (*cid).to_string(),
        }),
        [puri, pcid, ruri, rcid, ..] if !puri.is_empty() && !pcid.is_empty() => Some(ReplyRefs {
            parent_uri: (*puri).to_string(),
            parent_cid: (*pcid).to_string(),
            // Fall back to the parent when a root ref is blank.
            root_uri: if ruri.is_empty() { (*puri).to_string() } else { (*ruri).to_string() },
            root_cid: if rcid.is_empty() { (*pcid).to_string() } else { (*rcid).to_string() },
        }),
        _ => None,
    }
}

/// Map one `listNotifications` entry to an [`Inbound`]. Returns `None` for
/// notifications this plugin does not deliver, mirroring the native channel:
///   - a `reason` other than `mention` / `reply`,
///   - already-read notifications (`isRead == true`),
///   - the bot's own posts (`author.did == self_did`, the self-loop guard),
///   - empty-body posts.
///
/// The `reply_target` encodes the strong refs needed to thread the reply: the
/// notified post is the reply *parent*; the thread *root* comes from the post's
/// own `record.reply.root` when it is itself a reply, else the notified post is
/// the root.
pub fn parse_notification(notif: &Value, self_did: &str) -> Option<Inbound> {
    let reason = notif.get("reason").and_then(Value::as_str)?;
    if reason != "mention" && reason != "reply" {
        return None;
    }
    if notif.get("isRead").and_then(Value::as_bool) == Some(true) {
        return None;
    }

    let author = notif.get("author")?;
    let author_did = author.get("did").and_then(Value::as_str).unwrap_or("");
    if !self_did.is_empty() && author_did == self_did {
        return None;
    }

    let record = notif.get("record");
    let text = record
        .and_then(|r| r.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if text.is_empty() {
        return None;
    }

    let uri = notif.get("uri").and_then(Value::as_str)?.to_string();
    let cid = notif.get("cid").and_then(Value::as_str)?.to_string();
    let sender = author
        .get("handle")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let timestamp = iso8601_to_millis(notification_indexed_at(notif));

    // Thread root: a reply carries its thread root in `record.reply.root`; a
    // mention (or a top-level post) is its own root.
    let (root_uri, root_cid) = record
        .and_then(|r| r.get("reply"))
        .and_then(|r| r.get("root"))
        .and_then(|root| {
            let ru = root.get("uri").and_then(Value::as_str)?;
            let rc = root.get("cid").and_then(Value::as_str)?;
            if ru.is_empty() || rc.is_empty() {
                None
            } else {
                Some((ru.to_string(), rc.to_string()))
            }
        })
        .unwrap_or_else(|| (uri.clone(), cid.clone()));

    let reply_target = encode_reply_target(&uri, &cid, &root_uri, &root_cid);

    Some(Inbound {
        id: format!("bluesky_{cid}"),
        sender,
        reply_target,
        content: text.to_string(),
        channel_alias: None,
        timestamp,
        thread_ts: Some(root_uri),
    })
}

/// Truncate post text to the Bluesky character cap, appending an ellipsis when
/// it overflows (mirrors the native channel's 300-char clamp).
pub fn truncate_post(text: &str) -> String {
    if text.chars().count() > MAX_POST_CHARS {
        let truncated: String = text.chars().take(MAX_POST_CHARS - 3).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    }
}

/// Build the `com.atproto.repo.createRecord` body for an `app.bsky.feed.post`.
/// A `reply` block (parent + root strong refs) is included only when
/// `reply_target` decodes to refs (a threaded reply); a bare recipient produces
/// a top-level post.
pub fn build_send_body(did: &str, text: &str, reply_target: &str, created_at: &str) -> Value {
    let mut record = json!({
        "$type": "app.bsky.feed.post",
        "text": text,
        "createdAt": created_at,
    });
    if let Some(refs) = decode_reply_target(reply_target) {
        record["reply"] = json!({
            "root": { "uri": refs.root_uri, "cid": refs.root_cid },
            "parent": { "uri": refs.parent_uri, "cid": refs.parent_cid },
        });
    }
    json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": record,
    })
}

/// Body for `app.bsky.notification.updateSeen`.
pub fn build_update_seen(seen_at: &str) -> Value {
    json!({ "seenAt": seen_at })
}

// ── RFC-3339 (UTC) ⇄ Unix-millis, dependency-free ──────────────────────────
//
// Bluesky stamps `indexedAt` / `createdAt` as RFC-3339 UTC (e.g.
// `2026-01-15T10:00:00.000Z`). The host inbound `timestamp` is Unix
// milliseconds, and outbound posts need a `createdAt` string, so we convert
// both ways without pulling in `chrono`. Days ⇄ civil dates use Howard
// Hinnant's algorithms.

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse an RFC-3339 / ISO-8601 UTC timestamp into Unix epoch milliseconds.
/// Handles the `…Z` form Bluesky emits (with optional fractional seconds); a
/// trailing `+hh:mm` offset is ignored (treated as UTC). Returns `0` when the
/// string can't be parsed, so a malformed timestamp is inert.
pub fn iso8601_to_millis(s: &str) -> u64 {
    let Some((date, rest)) = s.split_once('T') else {
        return 0;
    };
    let mut dparts = date.split('-');
    let (Some(y), Some(m), Some(d)) = (
        dparts.next().and_then(|v| v.parse::<i64>().ok()),
        dparts.next().and_then(|v| v.parse::<i64>().ok()),
        dparts.next().and_then(|v| v.parse::<i64>().ok()),
    ) else {
        return 0;
    };

    // Strip the zone (`Z` or a `+hh:mm` offset — assume UTC) before parsing.
    let time = rest.trim_end_matches('Z');
    let time = time.split('+').next().unwrap_or(time);
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (time, None),
    };
    let mut tparts = hms.split(':');
    let hh = tparts.next().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let mm = tparts.next().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let ss = tparts.next().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);

    let ms = frac
        .map(|f| {
            let digits: String = f.chars().take_while(char::is_ascii_digit).take(3).collect();
            let mut n: u64 = digits.parse().unwrap_or(0);
            for _ in digits.len()..3 {
                n *= 10; // pad e.g. "1" → 100, "12" → 120
            }
            n
        })
        .unwrap_or(0);

    let secs = days_from_civil(y, m, d) * 86_400 + hh * 3_600 + mm * 60 + ss;
    if secs < 0 {
        return 0;
    }
    (secs as u64) * 1_000 + ms
}

/// Format Unix epoch milliseconds as an RFC-3339 UTC timestamp with millisecond
/// precision (e.g. `2026-01-15T10:00:00.000Z`), the shape Bluesky expects for a
/// post's `createdAt`.
pub fn millis_to_rfc3339(millis: u64) -> String {
    let secs = (millis / 1_000) as i64;
    let ms = millis % 1_000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3_600;
    let mm = (rem % 3_600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{ms:03}Z")
}
