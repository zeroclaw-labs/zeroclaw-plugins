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

use base64::prelude::{BASE64_STANDARD, Engine as _};
use palinurus_core::rpc::{parse_account_info, parse_send_tx, rpc_request, rpc_result, AccountInfo, BlockhashInfo, Rpc, RpcError, TxSummary};
use palinurus_core::Pubkey;
use serde_json::Value;
use std::path::Path;

/// Read a Solana keypair JSON file (a 64-element `u8` array = 32 secret ||
/// 32 public) and return the 32-byte **secret** as base58 — the form
/// [`AttestConfig::from_section`] expects for `session_key`. Fail closed on a
/// malformed file (wrong length, non-array, non-numeric). The public half is
/// discarded (the identity guard re-derives it from the secret).
///
/// T2 demo only. The real plugin never loads a keypair file — it reads the
/// base58 session key from config. This helper exists so the on-camera demo
/// can reuse the operator's existing Solana CLI keypair file.
pub fn load_session_key_b58(path: &Path) -> Result<String, String> {
  let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
  let arr: Vec<u8> = serde_json::from_slice(&bytes)
    .map_err(|e| format!("keypair file is not a JSON u8 array: {e}"))?;
  if arr.len() != 64 {
    return Err(format!(
      "keypair file must be 64 bytes (32 secret || 32 public), got {}",
      arr.len()
    ));
  }
  let secret = &arr[0..32];
  Ok(bs58::encode(secret).into_string())
}

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
  fn send_transaction(&self, tx: &[u8]) -> Result<String, RpcError> {
    // T2 demo path: POST a JSON-RPC sendTransaction with the tx bytes
    // base64-encoded and return the result string (the tx signature). T1
    // never calls this (execute_t1 returns UNSIGNED tx bytes — the pure-core
    // tests assert 0 signatures; the no-submit invariant lives in the core,
    // not the Rpc impl).
    let tx_b64 = BASE64_STANDARD.encode(tx);
    let req = rpc_request(
      self.next_id(),
      "sendTransaction",
      serde_json::json!([tx_b64, { "encoding": "base64" }]),
    );
    let resp = self.post_json(&req)?;
    parse_send_tx(rpc_result(&resp)?)
  }
}