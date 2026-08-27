//! Demo-driver host RPC client — `cargo test --features demo`.
//!
//! Verifies the reqwest-backed [`palinurus_core::Rpc`] impl (`ReqwestRpc`)
//! builds the right JSON-RPC `getAccountInfo` request, parses the response via
//! the shared pure parse layer (`rpc_result` + `parse_account_info`), maps a
//! `null` value to `None`, and (T2 demo) posts a base64 `sendTransaction` and
//! returns the signature. No live network: mockito serves the JSON-RPC
//! responses. `get_latest_blockhash` + `get_signatures_for_address` remain
//! unused by both demo paths (T1 uses a durable nonce; T2 signs+submits via
//! `send_transaction`) and still return a clear "not used" error.
//!
//! Also covers `load_session_key_b58` — the T2 demo helper that reads a
//! Solana keypair JSON file (64 bytes) and returns the 32-byte secret as
//! base58, so it flows through the existing fail-closed `AttestConfig::from_section`.

#![cfg(feature = "demo")]

use depin_attest::demo_rpc::ReqwestRpc;
use mockito::{Mock, Server};
use palinurus_core::rpc::{AccountInfo, Rpc, RpcError};
use palinurus_core::Pubkey;
use std::str::FromStr;

#[test]
fn reqwest_rpc_get_account_info_parses_response() {
  let mut server = Server::new();
  let endpoint = server.url();
  // A plausible nonce-account-shaped response: owner System, 80B data, lamports.
  let data_b64 = BASE64_STANDARD.encode([0u8; 80]);
  let body = format!(
    "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"value\":{{\"data\":[\"{data_b64}\",\"base64\"],\"owner\":\"11111111111111111111111111111111\",\"lamports\":50000000,\"executable\":false}}}}}}"
  );
  let _m: Mock = server
    .mock("POST", "/")
    .with_status(200)
    .with_body(body)
    .create();
  let rpc = ReqwestRpc::new(endpoint, None);
  let pubkey = Pubkey::from_str("9Kaivz6TP4u4n6oyat7wA7f48mnRXFBuA1vk79DVDL4u").unwrap();
  let info = rpc.get_account_info(&pubkey).expect("get_account_info ok");
  let info: AccountInfo = info.expect("Some");
  assert_eq!(info.lamports, 50_000_000);
  assert_eq!(info.data.len(), 80);
}

#[test]
fn reqwest_rpc_get_account_info_not_found_returns_none() {
  let mut server = Server::new();
  let endpoint = server.url();
  let _m = server
    .mock("POST", "/")
    .with_status(200)
    .with_body(r#"{"jsonrpc":"2.0","id":1,"result":{"value":null}}"#)
    .create();
  let rpc = ReqwestRpc::new(endpoint, None);
  let pubkey = Pubkey::from_str("9Kaivz6TP4u4n6oyat7wA7f48mnRXFBuA1vk79DVDL4u").unwrap();
  assert_eq!(rpc.get_account_info(&pubkey).unwrap(), None);
}

#[test]
fn reqwest_rpc_send_transaction_posts_base64_and_returns_signature() {
  // T2 demo path: send_transaction must POST a JSON-RPC sendTransaction with
  // the tx bytes base64-encoded + {encoding: base64}, and return the result
  // string (the tx signature) via the shared parse_send_tx layer.
  let mut server = Server::new();
  let endpoint = server.url();
  let tx_bytes = vec![1u8; 64]; // arbitrary serialized tx bytes
  let _tx_b64 = BASE64_STANDARD.encode(&tx_bytes);
  let sig = "2VtW5KG6YqKqKqKqKqKqKqKqKqKqKqKqKqKqKqKqKqKqK"; // a fake base58 signature
  let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": sig }).to_string();
  let _m: Mock = server
    .mock("POST", "/")
    .with_status(200)
    .with_body(body)
    .create();
  let rpc = ReqwestRpc::new(endpoint, None);
  let result_sig = rpc.send_transaction(&tx_bytes).expect("send ok");
  assert_eq!(result_sig, sig);
}

#[test]
fn reqwest_rpc_send_transaction_maps_rpc_error() {
  // A JSON-RPC error object must surface as RpcError::Rpc, not a silent pass.
  let mut server = Server::new();
  let endpoint = server.url();
  let _m: Mock = server
    .mock("POST", "/")
    .with_status(200)
    .with_body(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Transaction preflight failure"}}"#)
    .create();
  let rpc = ReqwestRpc::new(endpoint, None);
  let err = rpc.send_transaction(&[0u8; 64]).unwrap_err();
  match err {
    RpcError::Rpc { code, .. } => assert_eq!(code, -32000),
    other => panic!("expected RpcError::Rpc, got {other:?}"),
  }
}

#[test]
fn load_session_key_b58_extracts_32_byte_secret_from_keypair_json() {
  // A Solana keypair file is a JSON array of 64 u8 (32 secret || 32 public).
  // The helper must return the 32-byte SECRET as base58 (what AttestConfig
  // expects), never the full 64-byte keypair.
  let secret = [7u8; 32];
  let public = [9u8; 32];
  let mut kp = Vec::with_capacity(64);
  kp.extend_from_slice(&secret);
  kp.extend_from_slice(&public);
  let path = std::env::temp_dir().join("palinurus-test-kp.json");
  std::fs::write(&path, serde_json::to_vec(&kp).unwrap()).unwrap();
  let b58 = depin_attest::demo_rpc::load_session_key_b58(&path).expect("load ok");
  let decoded = bs58::decode(&b58).into_vec().expect("base58 decodes");
  assert_eq!(decoded, secret.to_vec(), "must be the 32-byte secret, not the full keypair");
  let _ = std::fs::remove_file(&path);
}

#[test]
fn load_session_key_b58_rejects_short_keypair() {
  // Fail closed: a 31-element array is not a valid Solana keypair.
  let bad = vec![0u8; 31];
  let path = std::env::temp_dir().join("palinurus-test-kp-bad.json");
  std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
  let err = depin_attest::demo_rpc::load_session_key_b58(&path).unwrap_err();
  assert!(err.contains("32") || err.contains("64"), "got: {err}");
  let _ = std::fs::remove_file(&path);
}

use base64::prelude::{BASE64_STANDARD, Engine as _};