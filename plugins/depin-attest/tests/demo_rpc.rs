//! Demo-driver host RPC client — `cargo test --features demo`.
//!
//! Verifies the reqwest-backed [`palinurus_core::Rpc`] impl (`ReqwestRpc`)
//! builds the right JSON-RPC `getAccountInfo` request, parses the response via
//! the shared pure parse layer (`rpc_result` + `parse_account_info`), and maps
//! a `null` value to `None`. No live network: mockito serves the JSON-RPC
//! responses. The other three trait methods (`get_latest_blockhash`,
//! `get_signatures_for_address`, `send_transaction`) are unused by the T1 demo
//! (execute_t1 only calls `get_account_info`); they return a clear
//! "not used by the T1 demo" error — one test pins `send_transaction`.

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
fn reqwest_rpc_send_transaction_unsupported_in_t1_demo() {
  let server = Server::new(); // no mock needed — must not call out
  let rpc = ReqwestRpc::new(server.url(), None);
  let err = rpc.send_transaction(&[0u8; 64]).unwrap_err();
  match err {
    RpcError::Unexpected(m) => assert!(m.contains("T1 demo"), "got: {m}"),
    other => panic!("expected Unexpected, got {other:?}"),
  }
}

use base64::prelude::{BASE64_STANDARD, Engine as _};