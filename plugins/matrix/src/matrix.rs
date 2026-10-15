//! Pure Matrix protocol parsing and volatile session decisions. No credentials.

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};

pub const CHANNEL: &str = "matrix";
pub const MAX_BODY: usize = 512 * 1024;
pub const MAX_PENDING: usize = 64;
pub const MAX_ROOM_METADATA: usize = 256;
pub const MAX_TEXT: usize = 64 * 1024;
const MAX_ID: usize = 255;

fn default_reply_in_thread() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MatrixConfig {
    pub homeserver: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub allowed_rooms: Vec<String>,
    #[serde(default)]
    pub mention_only: bool,
    #[serde(default = "default_reply_in_thread")]
    pub reply_in_thread: bool,
}

impl MatrixConfig {
    pub fn from_public_json(input: &str) -> Result<Self, String> {
        if input.len() > MAX_TEXT {
            return Err("matrix: public config too large".into());
        }
        let cfg: Self = serde_json::from_str(input).map_err(|_| "matrix: invalid public config")?;
        if cfg.homeserver.len() > 2048
            || split_http_url(&cfg.homeserver).is_none()
            || cfg.homeserver.contains(['?', '#'])
            || cfg.user_id.as_deref().is_some_and(|id| !matrix_id(id, '@'))
            || cfg.allowed_rooms.len() > 256
            || cfg.allowed_rooms.iter().any(|id| !matrix_id(id, '!'))
        {
            return Err("matrix: invalid public config".into());
        }
        Ok(cfg)
    }
    pub fn homeserver(&self) -> &str {
        self.homeserver.trim_end_matches('/')
    }
    fn room_allowed(&self, room: &str) -> bool {
        self.allowed_rooms.is_empty() || self.allowed_rooms.iter().any(|id| id == room)
    }
}

pub struct HttpTarget<'a> {
    pub https: bool,
    pub authority: &'a str,
    pub path_with_query: &'a str,
}

pub fn split_http_url(url: &str) -> Option<HttpTarget<'_>> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else {
        (false, url.strip_prefix("http://")?)
    };
    let boundary = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..boundary];
    if authority.is_empty()
        || authority.contains(['@', '?', '#', '\\'])
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
        || url.contains(['#', '\\'])
    {
        return None;
    }
    Some(HttpTarget {
        https,
        authority,
        path_with_query: if boundary == rest.len() {
            "/"
        } else {
            &rest[boundary..]
        },
    })
}

pub fn matrix_id(id: &str, prefix: char) -> bool {
    let Some(rest) = id.strip_prefix(prefix) else {
        return false;
    };
    // Room IDs are opaque; v12 rooms no longer include a server name.
    id.len() <= MAX_ID
        && !rest.is_empty()
        && (prefix == '!'
            || rest
                .split_once(':')
                .is_some_and(|(local, server)| !local.is_empty() && !server.is_empty()))
        && !id.chars().any(|c| c.is_whitespace() || c.is_control())
}
fn event_id(id: &str) -> bool {
    id.starts_with('$')
        && id.len() > 1
        && id.len() <= MAX_ID
        && !id.chars().any(|c| c.is_whitespace() || c.is_control())
}
fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}
fn api_url(homeserver: &str, path: &str) -> String {
    format!(
        "{}/_matrix/client/v3/{path}",
        homeserver.trim_end_matches('/')
    )
}
pub fn whoami_url(homeserver: &str) -> String {
    api_url(homeserver, "account/whoami")
}
pub fn sync_url(homeserver: &str, since: Option<&str>) -> String {
    let base = api_url(homeserver, "sync?timeout=0");
    match since {
        Some(cursor) => format!("{base}&since={}", encode(cursor)),
        None => base,
    }
}
pub fn room_alias_url(homeserver: &str, alias: &str) -> String {
    api_url(homeserver, &format!("directory/room/{}", encode(alias)))
}
pub fn encryption_url(homeserver: &str, room: &str) -> String {
    api_url(
        homeserver,
        &format!("rooms/{}/state/m.room.encryption/", encode(room)),
    )
}
pub fn send_url(homeserver: &str, room: &str, transaction: u64) -> String {
    api_url(
        homeserver,
        &format!("rooms/{}/send/m.room.message/{transaction}", encode(room)),
    )
}
pub fn parse_whoami(value: &Value) -> Option<String> {
    value
        .get("user_id")?
        .as_str()
        .filter(|id| matrix_id(id, '@'))
        .map(str::to_string)
}
pub fn parse_room_id(value: &Value) -> Option<String> {
    value
        .get("room_id")?
        .as_str()
        .filter(|id| matrix_id(id, '!'))
        .map(str::to_string)
}

/// Only an authenticated response from the exact encryption-state endpoint qualifies.
pub fn require_unencrypted(status: u16, body: &[u8]) -> Result<(), String> {
    if status == 404
        && serde_json::from_slice::<Value>(body)
            .ok()
            .is_some_and(|value| {
                value.get("errcode").and_then(Value::as_str) == Some("M_NOT_FOUND")
            })
    {
        Ok(())
    } else {
        Err("matrix: encryption state present or uncertain; send refused".into())
    }
}

pub fn build_send_body(content: &str, thread_ts: Option<&str>, reply_in_thread: bool) -> Value {
    let mut body = json!({"msgtype": "m.text", "body": content});
    if let Some(anchor) = thread_ts.filter(|id| reply_in_thread && event_id(id)) {
        body["m.relates_to"] = json!({"rel_type": "m.thread", "event_id": anchor,
            "is_falling_back": true, "m.in_reply_to": {"event_id": anchor}});
    }
    body
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub timestamp: u64,
    pub thread_ts: Option<String>,
    pub interruption_scope_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Pending {
    message: Inbound,
    direct: bool,
    mentioned: bool,
}
impl Pending {
    pub fn deliver(mut self, cfg: &MatrixConfig, self_id: &str) -> Option<Inbound> {
        if self.message.sender == self_id
            || !cfg.room_allowed(&self.message.reply_target)
            || (cfg.mention_only && !self.direct && !self.mentioned)
        {
            return None;
        }
        self.message.thread_ts = self
            .message
            .interruption_scope_id
            .clone()
            .or_else(|| cfg.reply_in_thread.then(|| self.message.id.clone()));
        Some(self.message)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoomMetadata {
    direct: bool,
    joined_members: Option<u64>,
}

struct SyncBatch {
    cursor: String,
    rooms: HashMap<String, RoomMetadata>,
    pending: VecDeque<Pending>,
}

fn room_metadata<'a>(
    rooms: &'a mut HashMap<String, RoomMetadata>,
    id: &str,
) -> Result<&'a mut RoomMetadata, String> {
    if !rooms.contains_key(id) && rooms.len() >= MAX_ROOM_METADATA {
        return Err("matrix: room metadata limit exceeded".into());
    }
    Ok(rooms.entry(id.to_string()).or_default())
}

fn parse_sync(
    value: &Value,
    cfg: &MatrixConfig,
    self_id: &str,
    mut metadata: HashMap<String, RoomMetadata>,
    mut pending: VecDeque<Pending>,
    startup: bool,
) -> Result<SyncBatch, String> {
    let cursor = parse_cursor(value)?;
    if value.get("rooms").is_some_and(|v| !v.is_object())
        || value.pointer("/rooms/join").is_some_and(|v| !v.is_object())
        || value
            .pointer("/rooms/leave")
            .is_some_and(|v| !v.is_object())
        || value.get("account_data").is_some_and(|v| !v.is_object())
        || value
            .pointer("/account_data/events")
            .is_some_and(|v| !v.is_array())
    {
        return Err("matrix: invalid sync structure".into());
    }
    let departed = value.pointer("/rooms/leave").and_then(Value::as_object);
    if let Some(rooms) = departed {
        for (id, room) in rooms {
            if !matrix_id(id, '!') || !room.is_object() {
                return Err("matrix: invalid sync departure".into());
            }
            metadata.remove(id);
        }
    }
    pending.retain(|event| {
        cfg.room_allowed(&event.message.reply_target)
            && !departed.is_some_and(|rooms| rooms.contains_key(&event.message.reply_target))
    });
    if let Some(events) = value
        .pointer("/account_data/events")
        .and_then(Value::as_array)
    {
        for event in events.iter().filter(|event| event["type"] == "m.direct") {
            let content = event["content"]
                .as_object()
                .ok_or("matrix: invalid direct-room metadata")?;
            // m.direct is a replacement, not a delta; member counts are separate.
            for room in metadata.values_mut() {
                room.direct = false;
            }
            metadata.retain(|_, room| room.joined_members.is_some());
            for rooms in content.values() {
                for room in rooms
                    .as_array()
                    .ok_or("matrix: invalid direct-room metadata")?
                {
                    let id = room
                        .as_str()
                        .filter(|id| matrix_id(id, '!'))
                        .ok_or("matrix: invalid direct-room metadata")?;
                    if !departed.is_some_and(|rooms| rooms.contains_key(id)) {
                        room_metadata(&mut metadata, id)?.direct = true;
                    }
                }
            }
        }
    }
    if let Some(rooms) = value.pointer("/rooms/join").and_then(Value::as_object) {
        for (room_id, room) in rooms {
            if !room.is_object() {
                return Err("matrix: invalid sync room".into());
            }
            if !matrix_id(room_id, '!') {
                return Err("matrix: invalid sync room id".into());
            }
            if departed.is_some_and(|rooms| rooms.contains_key(room_id)) {
                return Err("matrix: conflicting sync membership".into());
            }
            if let Some(summary) = room.get("summary") {
                let summary = summary.as_object().ok_or("matrix: invalid room summary")?;
                if let Some(count) = summary.get("m.joined_member_count") {
                    room_metadata(&mut metadata, room_id)?.joined_members =
                        Some(count.as_u64().ok_or("matrix: invalid room member count")?);
                }
            }
            if let Some(timeline) = room.get("timeline") {
                let timeline = timeline
                    .as_object()
                    .ok_or("matrix: invalid sync timeline")?;
                let events = timeline
                    .get("events")
                    .and_then(Value::as_array)
                    .ok_or("matrix: invalid sync timeline")?;
                let limited = match timeline.get("limited") {
                    Some(value) => value
                        .as_bool()
                        .ok_or("matrix: invalid timeline limited flag")?,
                    None => false,
                };
                if !cfg.room_allowed(room_id) {
                    continue;
                }
                if !startup && limited {
                    return Err("matrix: incremental timeline gap; sync refused".into());
                }
                if startup {
                    continue;
                }
                let direct = metadata.get(room_id).is_some_and(|room| {
                    room.direct || room.joined_members.is_some_and(|count| count <= 2)
                });
                for event in events {
                    if let Some(message) = parse_event(room_id, event, self_id, direct) {
                        if pending.len() == MAX_PENDING {
                            return Err("matrix: sync queue limit exceeded".into());
                        }
                        pending.push_back(message);
                    }
                }
            }
        }
    }
    Ok(SyncBatch {
        cursor,
        rooms: metadata,
        pending,
    })
}

pub fn parse_cursor(value: &Value) -> Result<String, String> {
    value
        .get("next_batch")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .map(str::to_string)
        .ok_or_else(|| "matrix: invalid sync cursor".into())
}

fn parse_event(room: &str, event: &Value, self_id: &str, direct: bool) -> Option<Pending> {
    if event["type"] != "m.room.message" {
        return None;
    }
    let sender = event["sender"]
        .as_str()
        .filter(|id| matrix_id(id, '@') && *id != self_id)?;
    let content = &event["content"];
    if content["msgtype"] != "m.text" || content["m.relates_to"]["rel_type"] == "m.replace" {
        return None;
    }
    let body = content["body"].as_str()?.trim();
    if body.is_empty() || body.len() > MAX_TEXT {
        return None;
    }
    let id = event["event_id"].as_str().filter(|id| event_id(id))?;
    let root = if content["m.relates_to"]["rel_type"] == "m.thread" {
        Some(
            content["m.relates_to"]["event_id"]
                .as_str()
                .filter(|id| event_id(id))?
                .to_string(),
        )
    } else {
        None
    };
    let mentioned = body.contains(self_id)
        || content
            .pointer("/m.mentions/user_ids")
            .and_then(Value::as_array)
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(self_id)));
    Some(Pending {
        direct,
        mentioned,
        message: Inbound {
            id: id.to_string(),
            sender: sender.to_string(),
            reply_target: room.to_string(),
            content: body.to_string(),
            timestamp: event["origin_server_ts"].as_u64().unwrap_or(0),
            thread_ts: None,
            interruption_scope_id: root,
        },
    })
}

/// Only protocol provenance and authenticated public metadata survive a call.
pub struct Session {
    pub self_id: String,
    homeserver: String,
    invalidated: bool,
    bootstrapping: bool,
    pub since: Option<String>,
    pub pending: VecDeque<Pending>,
    pub rooms: HashMap<String, RoomMetadata>,
    pub sync_failed: bool,
}
impl Session {
    pub fn new(cfg: &MatrixConfig, self_id: String) -> Self {
        Self {
            self_id,
            homeserver: cfg.homeserver().to_string(),
            invalidated: false,
            bootstrapping: true,
            since: None,
            pending: VecDeque::new(),
            rooms: HashMap::new(),
            sync_failed: false,
        }
    }
    pub fn check_binding(&mut self, cfg: &MatrixConfig, authenticated: &str) -> Result<(), String> {
        if self.homeserver != cfg.homeserver()
            || self.self_id != authenticated
            || cfg.user_id.as_deref().is_some_and(|id| id != authenticated)
        {
            self.invalidated = true;
            self.bootstrapping = true;
            self.since = None;
            self.pending.clear();
            self.rooms.clear();
        }
        if self.invalidated {
            Err("matrix: binding changed; fresh configure required".into())
        } else {
            Ok(())
        }
    }
    pub fn ingest(&mut self, value: &Value, cfg: &MatrixConfig) -> Result<(), String> {
        let id = self.self_id.clone();
        self.check_binding(cfg, &id)?;
        // Admission is atomic: failed parsing keeps the cursor, queue and metadata.
        match parse_sync(
            value,
            cfg,
            &self.self_id,
            self.rooms.clone(),
            self.pending.clone(),
            self.bootstrapping,
        ) {
            Ok(batch) => {
                // Suppress cached catch-up through the first unchanged incremental cursor.
                if self.bootstrapping && self.since.as_ref() == Some(&batch.cursor) {
                    self.bootstrapping = false;
                }
                self.since = Some(batch.cursor);
                self.rooms = batch.rooms;
                self.pending = batch.pending;
                self.sync_failed = false;
                Ok(())
            }
            Err(error) => {
                self.sync_failed = true;
                Err(error)
            }
        }
    }
    pub fn next(&mut self, cfg: &MatrixConfig) -> Option<Inbound> {
        if self.invalidated {
            return None;
        }
        while let Some(pending) = self.pending.pop_front() {
            if let Some(message) = pending.deliver(cfg, &self.self_id) {
                return Some(message);
            }
        }
        None
    }
    pub fn healthy(&self) -> bool {
        !self.invalidated && !self.bootstrapping && !self.sync_failed && self.since.is_some()
    }
}
