//! The real HTTP transport, backed by `waki` (blocking `wasi:http`).
//!
//! Compiled ONLY for the wasm component (`cfg(target_family = "wasm")`). On the
//! host it does not exist, so `cargo test` never pulls in `waki` and never opens
//! a socket. TLS is performed host-side by the ZeroClaw `wasi:http`
//! implementation; this code just hands over a request and reads the body.
//!
//! `http_client` is the only permission a plugin needs to use this. The URL —
//! including any API key — comes from the plugin's own `__config` section
//! (`config_read`), never hardcoded.

#![cfg(all(target_family = "wasm", feature = "http"))]

use std::time::Duration;

use crate::error::{CoreError, Result};
use crate::rpc::RpcTransport;

/// A `wasi:http` transport pointed at one RPC endpoint.
pub struct WakiTransport {
    url: String,
    connect_timeout: Duration,
}

impl WakiTransport {
    /// `url` is the full RPC endpoint, e.g. `https://api.mainnet-beta.solana.com`
    /// or a keyed provider URL read from config. Default connect timeout 10s.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout = Duration::from_secs(secs);
        self
    }
}

impl RpcTransport for WakiTransport {
    fn post_json(&self, body: &str) -> Result<String> {
        let resp = waki::Client::new()
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body.as_bytes().to_vec())
            .connect_timeout(self.connect_timeout)
            .send()
            .map_err(|e| CoreError::Transport(format!("request failed: {e}")))?;

        let status = resp.status_code();
        let bytes = resp
            .body()
            .map_err(|e| CoreError::Transport(format!("reading body failed: {e}")))?;
        let text = String::from_utf8(bytes)
            .map_err(|e| CoreError::Transport(format!("non-utf8 body: {e}")))?;

        if !(200..300).contains(&status) {
            // Include a short prefix of the body so an operator sees the RPC's
            // own error text, without flooding the agent context.
            let snippet: String = text.chars().take(200).collect();
            return Err(CoreError::Transport(format!("HTTP {status}: {snippet}")));
        }
        Ok(text)
    }
}
