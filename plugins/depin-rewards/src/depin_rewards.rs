//! Pure core for `depin-rewards` (no wasm dependency).
//!
//! Host-tested with plain `cargo test`; the wasm component (src/lib.rs) reuses
//! this logic through a thin shim. Grown per TDD slice (PLAN-3):
//! - **Slice A** (this): `HttpClient` trait + `MockHttp` + error types.
//! - Later slices: config parsing, Relay fetch/parse, watch/summary, optional
//!   unsigned claim-tx builder.
//!
//! All HTTP goes through the [`HttpClient`] trait so the pure core is
//! network-free on the host (tests use [`MockHttp`]); the shim supplies a real
//! `waki` impl behind `#[cfg(target_family = "wasm")]`.

use std::cell::RefCell;
use std::collections::HashMap;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Transport / HTTP-level error from an [`HttpClient`] call.
#[derive(Clone, Debug)]
pub enum HttpError {
  /// Non-2xx HTTP status (code + response body / message).
  Status(u16, String),
  /// Transport failure (DNS, connection, TLS, timeout).
  Transport(String),
  /// Response body decode failure (malformed JSON, etc.).
  Decode(String),
  /// (Mock) No scripted response registered for the requested URL.
  NotRegistered(String),
}

/// Top-level error for the depin-rewards pure core. Specific + actionable —
/// never an opaque "failed".
///
/// `Rpc` carries a formatted message rather than wrapping
/// `palinurus_core::RpcError`, to keep this module substrate-free in the early
/// slices; refined when the claim-tx slice (G) adds the `palinurus-core` dep.
#[derive(Debug)]
pub enum RewardsError {
  Config(String),
  Http(HttpError),
  Relay(String),
  Parse(String),
  Telegram(String),
  Rpc(String),
  ClaimResolution(String),
  NotConfigured(String),
}

/// A recorded POST call: `(url, form fields)`. Factored out so the recorded-
/// calls list doesn't trip `clippy::type_complexity`.
pub type RecordedPost = (String, Vec<(String, String)>);

// ── HTTP client trait + host mock ────────────────────────────────────────────

/// Blocking HTTP client used by the pure core: a Bearer-auth GET and a
/// form-encoded POST (the two shapes depin-rewards needs — Relay REST reads
/// and Telegram `sendMessage`). No wasm dependency; the real `waki` impl lives
/// behind `#[cfg(target_family = "wasm")]` in the shim, host tests use
/// [`MockHttp`].
pub trait HttpClient {
  /// GET `url` with `Authorization: Bearer <bearer>`; returns the raw body.
  fn get(&self, url: &str, bearer: &str) -> Result<Vec<u8>, HttpError>;
  /// POST `url` form-encoded with `fields`; returns the raw body.
  fn post_form(&self, url: &str, fields: &[(String, String)]) -> Result<Vec<u8>, HttpError>;
}

/// Host-only [`HttpClient`] mock: serves scripted responses keyed by exact URL
/// and records every POST for later assertion. No network. Uses `RefCell`
/// (single-threaded) so the module compiles cleanly for `wasm32-wasip2` even
/// though the mock itself is only exercised in host tests.
pub struct MockHttp {
  gets: HashMap<String, Vec<u8>>,
  get_errs: HashMap<String, HttpError>,
  post_resp: HashMap<String, Vec<u8>>,
  posts: RefCell<Vec<RecordedPost>>,
}

impl Default for MockHttp {
  fn default() -> Self {
    Self {
      gets: HashMap::new(),
      get_errs: HashMap::new(),
      post_resp: HashMap::new(),
      posts: RefCell::new(Vec::new()),
    }
  }
}

impl MockHttp {
  pub fn new() -> Self {
    Self::default()
  }

  /// Register the body returned for a GET of exactly `url`.
  pub fn set_get(&mut self, url: String, body: Vec<u8>) {
    self.gets.insert(url, body);
  }

  /// Register the body returned for a POST to exactly `url`.
  pub fn set_post(&mut self, url: String, body: Vec<u8>) {
    self.post_resp.insert(url, body);
  }

  /// Register an error to return for a GET of exactly `url` (for testing the
  /// status-code → RewardsError mapping in `fetch_*`).
  pub fn set_get_err(&mut self, url: String, err: HttpError) {
    self.get_errs.insert(url, err);
  }

  /// Every recorded POST call `(url, fields)`, in call order.
  pub fn posts(&self) -> Vec<RecordedPost> {
    self.posts.borrow().clone()
  }
}

impl HttpClient for MockHttp {
  fn get(&self, url: &str, _bearer: &str) -> Result<Vec<u8>, HttpError> {
    if let Some(err) = self.get_errs.get(url) {
      return Err(err.clone());
    }
    self
      .gets
      .get(url)
      .cloned()
      .ok_or_else(|| HttpError::NotRegistered(url.to_string()))
  }

  fn post_form(&self, url: &str, fields: &[(String, String)]) -> Result<Vec<u8>, HttpError> {
    self
      .posts
      .borrow_mut()
      .push((url.to_string(), fields.to_vec()));
    self
      .post_resp
      .get(url)
      .cloned()
      .ok_or_else(|| HttpError::NotRegistered(url.to_string()))
  }
}

// ── Config (parsed from the flat `config_read` section) ─────────────────────

/// Plugin configuration parsed from the jailed `config_read` section (flat
/// `String → String`). Slice B covers the T0 fields (relay + hotspots +
/// telegram + cadence + network); the claim-tx fields (`rpc_endpoint`,
/// `rpc_api_key`, `claim_nonce_*`) land in slice G when the unsigned claim-tx
/// needs them.
pub struct RewardsConfig {
  /// Relay API bearer key (free Community plan signup). Required.
  pub relay_api_key: String,
  /// Relay API base URL (default `https://api.relaywireless.com/v1`).
  pub relay_base_url: String,
  /// Watched hotspot ids (ECC compact key / Solana asset id / UUID).
  /// JSON array of strings, ≥1 entry. Required.
  pub hotspots: Vec<String>,
  /// Telegram bot token (@BotFather). Required.
  pub telegram_bot_token: String,
  /// Telegram destination chat id. Required.
  pub telegram_chat_id: String,
  /// Polling cadence hint (minutes) for the SOP — informational, not enforced
  /// by the plugin. Default 120 (keeps a single hotspot under the 1k/mo
  /// Community quota with headroom).
  pub poll_interval_minutes: u32,
  /// Solana network — `"mainnet-beta"` or `"devnet"` (explorer URLs +
  /// claim-tx target). Default `mainnet-beta`.
  pub network: String,
}

impl std::fmt::Debug for RewardsConfig {
  // Custody: never print the credentials. relay_api_key + telegram_bot_token
  // are redacted (SPEC-3 §10 — secrets never echoed). The rest (base_url,
  // hotspot count, chat_id, cadence, network) are non-credentials and useful
  // for config debugging.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("RewardsConfig")
      .field("relay_api_key", &"<redacted>")
      .field("relay_base_url", &self.relay_base_url)
      .field("hotspots", &format!("[{} hotspot(s)]", self.hotspots.len()))
      .field("telegram_bot_token", &"<redacted>")
      .field("telegram_chat_id", &self.telegram_chat_id)
      .field("poll_interval_minutes", &self.poll_interval_minutes)
      .field("network", &self.network)
      .finish()
  }
}

impl RewardsConfig {
  /// Parse from a flat config section. Fails closed on: empty section, missing
  /// required keys, empty-valued required keys, malformed `hotspots` JSON,
  /// empty `hotspots` array, non-string `hotspots` entries, bad `network`,
  /// non-numeric `poll_interval_minutes`.
  pub fn from_section(section: &HashMap<String, String>) -> Result<Self, RewardsError> {
    if section.is_empty() {
      return Err(RewardsError::Config(
        "not configured: no config section received".to_string(),
      ));
    }

    let req = |key: &str| -> Result<String, RewardsError> {
      section
        .get(key)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| RewardsError::Config(format!("missing required key: {key}")))
    };

    let relay_api_key = req("relay_api_key")?;
    let telegram_bot_token = req("telegram_bot_token")?;
    let telegram_chat_id = req("telegram_chat_id")?;

    let hotspots_str = section.get("hotspots").map(|s| s.as_str()).unwrap_or("");
    if hotspots_str.trim().is_empty() {
      return Err(RewardsError::Config("missing required key: hotspots".to_string()));
    }
    let hotspots: Vec<String> = serde_json::from_str(hotspots_str).map_err(|e| {
      RewardsError::Config(format!("hotspots must be a JSON array of strings: {e}"))
    })?;
    if hotspots.is_empty() {
      return Err(RewardsError::Config("hotspots must have ≥1 entry".to_string()));
    }
    if hotspots.iter().any(|h| h.trim().is_empty()) {
      return Err(RewardsError::Config(
        "hotspots entries must be non-empty".to_string(),
      ));
    }

    let relay_base_url = section
      .get("relay_base_url")
      .map(|s| s.trim())
      .filter(|s| !s.is_empty())
      .unwrap_or("https://api.relaywireless.com/v1")
      .to_string();

    let poll_interval_minutes = match section.get("poll_interval_minutes").map(|s| s.trim()) {
      None | Some("") => 120,
      Some(s) => s.parse::<u32>().map_err(|e| {
        RewardsError::Config(format!("poll_interval_minutes must be a u32: {e}"))
      })?,
    };

    let network = match section.get("network").map(|s| s.trim()) {
      None | Some("") => "mainnet-beta".to_string(),
      Some(s) if s == "mainnet-beta" || s == "devnet" => s.to_string(),
      Some(other) => {
        return Err(RewardsError::Config(format!(
          "network must be 'mainnet-beta' or 'devnet', got '{other}'"
        )))
      }
    };

    Ok(RewardsConfig {
      relay_api_key,
      relay_base_url,
      hotspots,
      telegram_bot_token,
      telegram_chat_id,
      poll_interval_minutes,
      network,
    })
  }
}

/// Fail-closed guard: reject any hotspot id not in the configured allowlist.
/// Wired into every action's entry point (slice F) so a malicious message
/// cannot target an arbitrary hotspot.
pub fn enforce_hotspot_allowlist(cfg: &RewardsConfig, id: &str) -> Result<(), RewardsError> {
  if cfg.hotspots.iter().any(|h| h == id) {
    Ok(())
  } else {
    Err(RewardsError::Config(format!(
      "hotspot '{id}' not in configured allowlist"
    )))
  }
}

// ── HotspotInfo (Relay get-hotspot response) ────────────────────────────────

#[derive(serde::Deserialize)]
struct RawNetInfo {
  #[serde(default)]
  is_active: Option<bool>,
  #[serde(default)]
  location: Option<i64>,
}

#[derive(serde::Deserialize)]
struct RawMaker {
  #[serde(default)]
  name: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawHotspotInfo {
  owner: String,
  name: String,
  #[serde(default)]
  networks: Vec<String>,
  #[serde(default)]
  iot_info: Option<RawNetInfo>,
  #[serde(default)]
  mobile_info: Option<RawNetInfo>,
  #[serde(default)]
  maker: Option<RawMaker>,
}

/// The parsed Relay `GET /helium/l2/hotspots/:id` response — only the fields
/// the plugin consumes. Tolerant of missing `mobile_info` (iot-only hotspots)
/// and missing `maker`.
#[derive(Debug)]
pub struct HotspotInfo {
  pub owner: String,
  pub name: String,
  pub networks: Vec<String>,
  pub iot_is_active: Option<bool>,
  pub mobile_is_active: Option<bool>,
  pub iot_location: Option<i64>,
  pub maker_name: Option<String>,
}

impl HotspotInfo {
  pub fn parse(json: &[u8]) -> Result<Self, RewardsError> {
    let raw: RawHotspotInfo = serde_json::from_slice(json)
      .map_err(|e| RewardsError::Parse(format!("hotspot info: {e}")))?;
    Ok(HotspotInfo {
      owner: raw.owner,
      name: raw.name,
      networks: raw.networks,
      iot_is_active: raw.iot_info.as_ref().and_then(|i| i.is_active),
      mobile_is_active: raw.mobile_info.as_ref().and_then(|i| i.is_active),
      iot_location: raw.iot_info.as_ref().and_then(|i| i.location),
      maker_name: raw.maker.and_then(|m| m.name),
    })
  }

  /// Online/offline reduction across joined networks: `Some(true)` if ANY
  /// joined network reports active; `Some(false)` if all known networks
  /// inactive; `None` only if both unknown.
  pub fn is_active(&self) -> Option<bool> {
    match (self.iot_is_active, self.mobile_is_active) {
      (None, None) => None,
      (iot, mob) => Some(iot.unwrap_or(false) || mob.unwrap_or(false)),
    }
  }

  /// The network to read status/rewards from: iot preferred, else mobile.
  pub fn primary_network(&self) -> &'static str {
    if self.networks.iter().any(|n| n == "iot") {
      "iot"
    } else if self.networks.iter().any(|n| n == "mobile") {
      "mobile"
    } else {
      "iot"
    }
  }
}

// ── fetch + do_status ────────────────────────────────────────────────────────

/// Map an HTTP error from Relay to a specific `RewardsError::Relay` message
/// (404 → not found, 402 → quota, 429 → rate-limited, 5xx → server error).
fn map_relay_http(e: HttpError) -> RewardsError {
  match e {
    HttpError::Status(404, msg) => RewardsError::Relay(format!("hotspot not found: {msg}")),
    HttpError::Status(402, msg) => {
      RewardsError::Relay(format!("Relay quota exhausted: {msg}"))
    }
    HttpError::Status(429, msg) => {
      RewardsError::Relay(format!("Relay rate-limited (429): {msg}"))
    }
    HttpError::Status(c, msg) if (500..600).contains(&c) => {
      RewardsError::Relay(format!("Relay server error {c}: {msg}"))
    }
    HttpError::Status(c, msg) => RewardsError::Relay(format!("Relay HTTP {c}: {msg}")),
    other => RewardsError::Http(other),
  }
}

/// `GET {base}/helium/l2/hotspots/:id` → parsed [`HotspotInfo`]. HTTP status
/// codes map to specific Relay errors (404/402/429/5xx); other transport
/// errors pass through as `RewardsError::Http`.
pub fn fetch_hotspot(
  http: &dyn HttpClient,
  cfg: &RewardsConfig,
  id: &str,
) -> Result<HotspotInfo, RewardsError> {
  let url = format!("{}/helium/l2/hotspots/{}", cfg.relay_base_url, id);
  let bearer = format!("Bearer {}", cfg.relay_api_key);
  let body = http.get(&url, &bearer).map_err(map_relay_http)?;
  HotspotInfo::parse(&body)
}

/// A short `4…4` form of an address (owner pubkey) for the shaped output.
/// Char-based so it never panics on non-ASCII; the substantive
/// `palinurus_core::short_pubkey` reuse lands in slice G alongside the claim-tx
/// Pubkey handling.
fn short_addr(s: &str) -> String {
  let chars: Vec<char> = s.chars().collect();
  if chars.len() <= 8 {
    s.to_string()
  } else {
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
  }
}

/// Shape a status read into a ≤200-token summary (SPEC-3 §7).
fn shape_status(info: &HotspotInfo) -> String {
  let active = match info.is_active() {
    Some(true) => "ONLINE",
    Some(false) => "OFFLINE",
    None => "UNKNOWN",
  };
  let net = info.primary_network();
  let nets = if info.networks.is_empty() {
    "none".to_string()
  } else {
    info.networks.join(", ")
  };
  let mut s = format!(
    "✓ hotspot {} — {} ({})\n  owner: {}  networks: {}",
    info.name,
    active,
    net,
    short_addr(&info.owner),
    nets
  );
  if let Some(maker) = &info.maker_name {
    s.push_str(&format!("  maker: {maker}"));
  }
  s
}

/// The shaped result of an `execute` action. Grows per slice (C = status;
/// D adds rewards; E adds alerts_sent; G adds tx_b64 + explorer_url).
#[derive(Debug)]
pub struct RewardsOutput {
  pub is_active: Option<bool>,
  pub summary: String,
}

/// `action = "status"`: read one hotspot's online/offline now + shape. Fails
/// closed on (a) hotspot not in the configured allowlist, (b) Relay errors.
pub fn do_status(
  http: &dyn HttpClient,
  cfg: &RewardsConfig,
  id: &str,
) -> Result<RewardsOutput, RewardsError> {
  enforce_hotspot_allowlist(cfg, id)?;
  let info = fetch_hotspot(http, cfg, id)?;
  let summary = shape_status(&info);
  Ok(RewardsOutput {
    is_active: info.is_active(),
    summary,
  })
}
