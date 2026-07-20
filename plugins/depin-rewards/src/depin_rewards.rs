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
#[derive(Debug)]
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
  post_resp: HashMap<String, Vec<u8>>,
  posts: RefCell<Vec<RecordedPost>>,
}

impl Default for MockHttp {
  fn default() -> Self {
    Self {
      gets: HashMap::new(),
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

  /// Every recorded POST call `(url, fields)`, in call order.
  pub fn posts(&self) -> Vec<RecordedPost> {
    self.posts.borrow().clone()
  }
}

impl HttpClient for MockHttp {
  fn get(&self, url: &str, _bearer: &str) -> Result<Vec<u8>, HttpError> {
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
