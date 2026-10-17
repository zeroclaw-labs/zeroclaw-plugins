//! wasm-only [`HttpClient`] impl backed by `waki` (blocking `wasi:http`).
//!
//! Used by the WIT component shim (`src/lib.rs`) to give the shipped pure
//! rewards core a real network transport: Relay REST reads (Bearer GET) +
//! Telegram `sendMessage` (form POST). TLS is performed host-side via
//! `wasi:http`. Mirrors `palinurus_core::WakiRpc`.
//!
//! `#![cfg(target_family = "wasm")]` — waki is the wasm transport; host tests
//! use `MockHttp` (scripted) + the `--features demo` driver uses `ReqwestHttp`.
//! This module compiles only for the `wasm32-wasip2` component build, never for
//! `cargo test` — so the host test suite stays network-free.

#![cfg(target_family = "wasm")]

use crate::depin_rewards::{HttpError, HttpClient};

/// `waki`-backed [`HttpClient`]. Stateless — the URL + bearer are passed per
/// call (the pure core owns the Relay base URL + Telegram bot URL).
pub struct WakiHttp;

impl WakiHttp {
  pub fn new() -> Self {
    Self
  }
}

impl HttpClient for WakiHttp {
  fn get(&self, url: &str, bearer: &str) -> Result<Vec<u8>, HttpError> {
    let auth = format!("Bearer {bearer}");
    let resp = waki::Client::new()
      .get(url)
      .header("Authorization", auth.as_str())
      .send()
      .map_err(|e| HttpError::Transport(e.to_string()))?;
    let status = resp.status_code();
    let body = resp
      .body()
      .map_err(|e| HttpError::Transport(e.to_string()))?;
    if !(200..300).contains(&status) {
      return Err(HttpError::Status(
        status,
        String::from_utf8_lossy(&body).to_string(),
      ));
    }
    Ok(body)
  }

  fn post_form(&self, url: &str, fields: &[(String, String)]) -> Result<Vec<u8>, HttpError> {
    let resp = waki::Client::new()
      .post(url)
      .form(fields.iter())
      .send()
      .map_err(|e| HttpError::Transport(e.to_string()))?;
    let status = resp.status_code();
    let body = resp
      .body()
      .map_err(|e| HttpError::Transport(e.to_string()))?;
    if !(200..300).contains(&status) {
      return Err(HttpError::Status(
        status,
        String::from_utf8_lossy(&body).to_string(),
      ));
    }
    Ok(body)
  }
}