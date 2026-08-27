//! Host-only reqwest-backed [`HttpClient`] for the demo driver (`--features demo`).
//!
//! The rewards pure core takes a `&dyn HttpClient` (Bearer GET + form POST).
//! On the wasm component the real impl is `waki` (behind `#[cfg(target_family =
//! "wasm")]` in `lib.rs`); this is the host counterpart used by the demo binary
//! to exercise the *same* pure core against live Relay + Telegram on camera.
//! Blocking (matches the trait); rustls TLS (no OpenSSL system dep).

#![cfg(feature = "demo")]

use crate::depin_rewards::{HttpError, HttpClient};

/// reqwest-backed [`HttpClient`]. `Default` builds a blocking rustls client.
pub struct ReqwestHttp {
  client: reqwest::blocking::Client,
}

impl Default for ReqwestHttp {
  fn default() -> Self {
    Self {
      client: reqwest::blocking::Client::builder()
        .build()
        .expect("reqwest blocking client builds"),
    }
  }
}

impl HttpClient for ReqwestHttp {
  fn get(&self, url: &str, bearer: &str) -> Result<Vec<u8>, HttpError> {
    let resp = self
      .client
      .get(url)
      .header("Authorization", format!("Bearer {bearer}"))
      .send()
      .map_err(|e| HttpError::Transport(e.to_string()))?;
    let status = resp.status();
    let body = resp.bytes().map_err(|e| HttpError::Transport(e.to_string()))?;
    if !status.is_success() {
      return Err(HttpError::Status(
        status.as_u16(),
        String::from_utf8_lossy(&body).to_string(),
      ));
    }
    Ok(body.to_vec())
  }

  fn post_form(&self, url: &str, fields: &[(String, String)]) -> Result<Vec<u8>, HttpError> {
    let resp = self
      .client
      .post(url)
      .form(fields)
      .send()
      .map_err(|e| HttpError::Transport(e.to_string()))?;
    let status = resp.status();
    let body = resp.bytes().map_err(|e| HttpError::Transport(e.to_string()))?;
    if !status.is_success() {
      return Err(HttpError::Status(
        status.as_u16(),
        String::from_utf8_lossy(&body).to_string(),
      ));
    }
    Ok(body.to_vec())
  }
}