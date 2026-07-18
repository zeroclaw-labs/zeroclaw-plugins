//! Pure Notion task-queue logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin. Notion is not a chat channel: it is a
//! task queue. The agent polls a Notion database for rows whose status is
//! `pending`, treats each row's input property as a prompt, and writes the
//! agent's answer back into a result property while flipping the status to
//! `done`. This module holds the JSON mapping/payload logic (database-schema
//! probing, pending-row → inbound mapping, and the property-update bodies) with
//! no I/O, so it is covered by a plain host `cargo test`. The
//! `#[cfg(target_family = "wasm")]` component shim in `lib.rs` does only the
//! HTTP (blocking `waki` `wasi:http` calls) and reuses this logic verbatim.

use std::fmt::Display;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer};
use serde_json::{json, Value};

/// Notion rich-text property content cap (characters). Results longer than this
/// are truncated before being written back.
pub const MAX_RESULT_LENGTH: usize = 2000;

/// Notion API version header value pinned by the native channel.
pub const NOTION_VERSION: &str = "2022-06-28";

/// Public Notion API origin (already includes the `/v1` version segment, so URL
/// builders append `/databases/...` and `/pages/...` directly).
pub const DEFAULT_API_BASE_URL: &str = "https://api.notion.com/v1";

/// The novel plugin's `[[plugins.entries]]` config map. The manifest omits
/// `provides` because current ZeroClaw has no canonical built-in Notion channel
/// family.
#[derive(Debug, Clone, Deserialize)]
pub struct NotionConfig {
    /// Notion internal-integration token. Sent as `Authorization: Bearer`.
    #[serde(default)]
    pub api_key: String,
    /// Target database id whose rows are the task queue.
    #[serde(default)]
    pub database_id: String,
    /// Seconds between polls (host-side loop cadence; informational here).
    #[serde(
        default = "default_poll_interval",
        deserialize_with = "deserialize_poll_interval"
    )]
    pub poll_interval_secs: u64,
    /// Name of the select/status property that holds the task state
    /// (`pending` / `running` / `done`).
    #[serde(default = "default_status_property")]
    pub status_property: String,
    /// Name of the title/rich-text property that holds the task prompt.
    #[serde(default = "default_input_property")]
    pub input_property: String,
    /// Name of the rich-text property the agent's answer is written back into.
    #[serde(default = "default_result_property")]
    pub result_property: String,
    /// Maximum tasks claimed (flipped to `running`) per poll tick.
    #[serde(
        default = "default_max_concurrent",
        deserialize_with = "deserialize_max_concurrent"
    )]
    pub max_concurrent: usize,
    /// On load, reset any rows stuck in `running` (from a prior crash) back to
    /// `pending` so they are re-dispatched.
    #[serde(
        default = "default_recover_stale",
        deserialize_with = "deserialize_recover_stale"
    )]
    pub recover_stale: bool,
    /// API origin override for a test mock or self-host. Not part of the native
    /// config; defaults to the public Notion API base.
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
}

fn default_poll_interval() -> u64 {
    5
}
fn default_status_property() -> String {
    "Status".to_string()
}
fn default_input_property() -> String {
    "Input".to_string()
}
fn default_result_property() -> String {
    "Result".to_string()
}
fn default_max_concurrent() -> usize {
    4
}
fn default_recover_stale() -> bool {
    true
}
fn default_api_base_url() -> String {
    DEFAULT_API_BASE_URL.to_string()
}

fn deserialize_poll_interval<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_or_native(deserializer, "poll_interval_secs", "a non-negative integer")
}

fn deserialize_max_concurrent<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_or_native(deserializer, "max_concurrent", "a non-negative integer")
}

fn deserialize_recover_stale<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_or_native(deserializer, "recover_stale", "true or false")
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrNative<T> {
    String(String),
    Native(T),
}

fn deserialize_string_or_native<'de, D, T>(
    deserializer: D,
    field: &str,
    expected: &str,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + FromStr,
    T::Err: Display,
{
    let value = StringOrNative::<T>::deserialize(deserializer).map_err(|_| {
        de::Error::custom(format!(
            "notion config field '{field}' must be {expected} or its string form"
        ))
    })?;
    match value {
        StringOrNative::Native(value) => Ok(value),
        StringOrNative::String(value) => value.parse().map_err(|error| {
            de::Error::custom(format!(
                "notion config field '{field}' must be {expected} or its string form; got {value:?}: {error}"
            ))
        }),
    }
}

impl Default for NotionConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            database_id: String::new(),
            poll_interval_secs: default_poll_interval(),
            status_property: default_status_property(),
            input_property: default_input_property(),
            result_property: default_result_property(),
            max_concurrent: default_max_concurrent(),
            recover_stale: default_recover_stale(),
            api_base_url: default_api_base_url(),
        }
    }
}

impl NotionConfig {
    /// Parse the JSON config string the host hands to `configure`. A withheld
    /// `"{}"` remains inert, while malformed JSON or invalid field values return
    /// an actionable error instead of silently replacing the whole config with
    /// defaults.
    pub fn from_json(config_json: &str) -> Result<Self, String> {
        serde_json::from_str(config_json)
            .map_err(|error| format!("notion config could not be parsed: {error}"))
    }

    /// Both the token and the target database are required to reach the API.
    pub fn has_credentials(&self) -> bool {
        !self.api_key.is_empty() && !self.database_id.is_empty()
    }
}

/// A pending Notion task row mapped to the host inbound-message fields (the
/// `channel` is always `"notion"`, stamped by the shim). `reply_target` is the
/// page id so the completion `send` PATCHes the right page.
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

// ── URL builders ──────────────────────────────────────────────────────────

/// `POST` target to query a database's rows.
pub fn query_url(base: &str, database_id: &str) -> String {
    format!(
        "{}/databases/{}/query",
        base.trim_end_matches('/'),
        database_id
    )
}

/// `GET` target to read a database (used to probe the status property type).
pub fn database_url(base: &str, database_id: &str) -> String {
    format!("{}/databases/{}", base.trim_end_matches('/'), database_id)
}

/// `PATCH` target to update a single page's properties.
pub fn page_url(base: &str, page_id: &str) -> String {
    format!("{}/pages/{}", base.trim_end_matches('/'), page_id)
}

// ── JSON mapping / payloads ────────────────────────────────────────────────

/// Probe a database-schema response for whether the status property is a
/// `status` type or a plain `select`. Defaults to `select` when the property or
/// its type is absent, matching the native channel.
pub fn detect_status_type(schema: &Value, status_property: &str) -> String {
    schema
        .get("properties")
        .and_then(|p| p.get(status_property))
        .and_then(|s| s.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("select")
        .to_string()
}

/// Build a Notion filter object selecting rows whose status equals `value`.
/// `status` and `select` property types use different filter keys.
pub fn build_status_filter(property: &str, status_type: &str, value: &str) -> Value {
    if status_type == "status" {
        json!({ "property": property, "status": { "equals": value } })
    } else {
        json!({ "property": property, "select": { "equals": value } })
    }
}

/// Build the property-update fragment that sets a status field to `value`.
pub fn build_status_payload(status_type: &str, value: &str) -> Value {
    if status_type == "status" {
        json!({ "status": { "name": value } })
    } else {
        json!({ "select": { "name": value } })
    }
}

/// Build a rich-text property fragment carrying `value`, truncated to the Notion
/// content cap.
pub fn build_rich_text_payload(value: &str) -> Value {
    json!({ "rich_text": [{ "text": { "content": truncate_result(value) } }] })
}

/// The `databases/{id}/query` request body filtering on a status value.
pub fn build_query_body(status_property: &str, status_type: &str, value: &str) -> Value {
    json!({ "filter": build_status_filter(status_property, status_type, value) })
}

/// The `pages/{id}` PATCH body that only flips the status property to `value`
/// (used to claim a task by moving it `pending` → `running`).
pub fn build_status_update_payload(status_property: &str, status_type: &str, value: &str) -> Value {
    json!({
        "properties": {
            status_property: build_status_payload(status_type, value),
        }
    })
}

/// The `pages/{id}` PATCH body that completes a task: write the answer into the
/// result property and set the status to `done`.
pub fn build_complete_payload(
    status_property: &str,
    result_property: &str,
    status_type: &str,
    content: &str,
) -> Value {
    json!({
        "properties": {
            status_property: build_status_payload(status_type, "done"),
            result_property: build_rich_text_payload(content),
        }
    })
}

/// The `pages/{id}` PATCH body that resets a crashed `running` row back to
/// `pending` with an explanatory note in the result property.
pub fn build_recover_payload(
    status_property: &str,
    result_property: &str,
    status_type: &str,
) -> Value {
    json!({
        "properties": {
            status_property: build_status_payload(status_type, "pending"),
            result_property: build_rich_text_payload(
                "Reset: poller restarted while task was running"
            ),
        }
    })
}

/// Extract plain text from a Notion `title` or `rich_text` property; anything
/// else (or a missing property) yields an empty string.
pub fn extract_text_from_property(prop: Option<&Value>) -> String {
    let Some(prop) = prop else {
        return String::new();
    };
    let array_key = match prop.get("type").and_then(Value::as_str).unwrap_or("") {
        "title" => "title",
        "rich_text" => "rich_text",
        _ => return String::new(),
    };
    prop.get(array_key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("plain_text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

/// Map a `databases/{id}/query` response into inbound task rows. Each result
/// page becomes an [`Inbound`] keyed on the page id, with the `input_property`'s
/// text as the prompt. Pages without an id are skipped; empty-content rows are
/// kept here and filtered by the caller (which never claims them). `timestamp`
/// is left `0` for the shim to stamp with the wall clock.
pub fn parse_pending(response: &Value, input_property: &str) -> Vec<Inbound> {
    response
        .get("results")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|page| {
                    let page_id = page.get("id").and_then(Value::as_str)?.to_string();
                    let content = extract_text_from_property(
                        page.get("properties").and_then(|p| p.get(input_property)),
                    );
                    Some(Inbound {
                        id: page_id.clone(),
                        sender: "notion".to_string(),
                        reply_target: page_id,
                        content,
                        channel_alias: None,
                        timestamp: 0,
                        thread_ts: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Truncate result text to fit within the Notion rich-text content cap, cutting
/// on a UTF-8 char boundary and appending a truncation marker.
pub fn truncate_result(value: &str) -> String {
    if value.len() <= MAX_RESULT_LENGTH {
        return value.to_string();
    }
    let cut = MAX_RESULT_LENGTH.saturating_sub(30);
    let end = floor_char_boundary(value, cut);
    format!("{}\n\n... [output truncated]", &value[..end])
}

/// Largest byte index `<= index` that lands on a UTF-8 char boundary (a local
/// stand-in for the unstable `str::floor_char_boundary`).
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut end = index;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}
