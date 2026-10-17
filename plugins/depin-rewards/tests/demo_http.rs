//! Demo-driver host HTTP client — `cargo test --features demo`.
//!
//! Verifies the reqwest-backed [`HttpClient`] impl (`ReqwestHttp`) sends the
//! Bearer header on GET and encodes form fields on POST — the two shapes the
//! rewards pure core calls (Relay reads + Telegram `sendMessage`). No live
//! network: mockito serves the responses and asserts on the requests.

#![cfg(feature = "demo")]

use depin_rewards::demo_http::ReqwestHttp;
use depin_rewards::depin_rewards::{HttpError, HttpClient};
use mockito::{Matcher, Mock, Server};

#[test]
fn reqwest_get_sends_bearer_header_and_returns_body() {
  let mut server = Server::new();
  let url = format!("{}/helium/l2/hotspots/abc", server.url());
  let _m: Mock = server
    .mock("GET", "/helium/l2/hotspots/abc")
    .match_header("authorization", "Bearer test-relay-key")
    .with_status(200)
    .with_body(b"{\"ok\":true}".as_slice())
    .create();
  let http = ReqwestHttp::default();
  let body = http.get(&url, "test-relay-key").expect("GET ok");
  assert_eq!(body, b"{\"ok\":true}");
}

#[test]
fn reqwest_get_maps_non_2xx_to_status_error() {
  let mut server = Server::new();
  let url = format!("{}/x", server.url());
  let _m = server.mock("GET", "/x").with_status(404).with_body(b"nope").create();
  let http = ReqwestHttp::default();
  let err = http.get(&url, "k").unwrap_err();
  match err {
    HttpError::Status(404, msg) => assert_eq!(msg, "nope"),
    other => panic!("expected Status(404,..), got {other:?}"),
  }
}

#[test]
fn reqwest_post_form_encodes_fields_and_returns_body() {
  let mut server = Server::new();
  let url = format!("{}/sendMessage", server.url());
  let _m: Mock = server
    .mock("POST", "/sendMessage")
    .match_body(Matcher::UrlEncoded("chat_id".into(), "123".into()))
    .match_body(Matcher::UrlEncoded("text".into(), "hello world".into()))
    .with_status(200)
    .with_body(b"{\"ok\":true}")
    .create();
  let http = ReqwestHttp::default();
  let fields = vec![
    ("chat_id".to_string(), "123".to_string()),
    ("text".to_string(), "hello world".to_string()),
  ];
  let body = http.post_form(&url, &fields).expect("POST ok");
  assert_eq!(body, b"{\"ok\":true}");
}