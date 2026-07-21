//! Host-only reqwest-backed [`palinurus_core::Rpc`] for the demo driver (`--features demo`).
//!
//! `execute_t1` calls only `get_account_info` (to read the durable-nonce
//! account). The other three trait methods are unused by the T1 demo (no
//! blockhash fetch — the durable nonce is the blockhash; no submit — T1 is
//! unsigned; no signatures query) and return a clear "not used by the T1
//! demo" error so a future caller can't silently misuse them. Blocking +
//! rustls (no OpenSSL system dep); reuses the shared pure parse layer
//! (`rpc_request` / `rpc_result` / `parse_account_info`) from palinurus-core.

#![cfg(feature = "demo")]

use std::sync::atomic::{AtomicU64, Ordering};

use palinurus_core::rpc::{parse_account_info, rpc_request, rpc_result, AccountInfo, BlockhashInfo, Rpc, RpcError, TxSummary};
use palinurus_core::Pubkey;
use serde_json::Value;

/// reqwest-backed [`Rpc`]. `endpoint` is the Solana RPC URL (API key may be
/// embedded in the path for Helius/QuickNode, or sent as `Authorization: Bearer`
/// when `api_key` is `Some`).
pub struct ReqwestRpc {
  endpoint: String,
  api_key: Option<String>,
  id: AtomicU64,
  client: reqwest::blocking::Client,
}

impl ReqwestRpc {
  pub fn new(endpoint: String, api_key: Option<String>) -> Self {
    Self {
      endpoint,
      api_key,
      id: AtomicU64::new(0),
      client: reqwest::blocking::Client::builder().build().expect("reqwest client builds"),
    }
  }

  fn next_id(&self) -> u64 {
    self.id.fetch_add(1, Ordering::Relaxed) + 1
  }

  fn post_json(&self, req: &Value) -> Result<Value, RpcError> {
    let mut builder = self.client.post(&self.endpoint);
    if let Some(key) = &self.api_key {
      builder = builder.header("Authorization", format!("Bearer {key}"));
    }
    let resp = builder
      .json(req)
      .send()
      .map_err(|e| RpcError::Transport(e.to_string()))?;
    resp.json::<Value>().map_err(|e| RpcError::Json(e.to_string()))
  }
}

impl Rpc for ReqwestRpc {
  fn get_latest_blockhash(&self) -> Result<BlockhashInfo, RpcError> {
    Err(RpcError::Unexpected(
      "get_latest_blockhash not used by the T1 demo (execute_t1 uses a durable nonce)".to_string(),
    ))
  }
  fn get_account_info(&self, pubkey: &Pubkey) -> Result<Option<AccountInfo>, RpcError> {
    let req = rpc_request(
      self.next_id(),
      "getAccountInfo",
      serde_json::json!([pubkey.to_string(), { "encoding": "base64" }]),
    );
    let resp = self.post_json(&req)?;
    parse_account_info(rpc_result(&resp)?)
  }
  fn get_signatures_for_address(
    &self,
    _pubkey: &Pubkey,
    _limit: usize,
  ) -> Result<Vec<TxSummary>, RpcError> {
    Err(RpcError::Unexpected(
      "get_signatures_for_address not used by the T1 demo".to_string(),
    ))
  }
  fn send_transaction(&self, _tx: &[u8]) -> Result<String, RpcError> {
    Err(RpcError::Unexpected(
      "send_transaction not used by the T1 demo (execute_t1 returns UNSIGNED tx bytes)".to_string(),
    ))
  }
}