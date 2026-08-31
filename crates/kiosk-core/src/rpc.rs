//! JSON-RPC transport seam — the pattern that makes every network-touching
//! plugin host-testable with no live network (a hard bounty requirement).
//!
//! The whole design is one small trait, [`RpcTransport`], with a single method:
//! "send one JSON-RPC call, give me back the `result` value." All of our client
//! logic (kiosk-watch, kiosk-attest) depends only on this trait, so:
//!
//!   * in production the wasm shim plugs in [`WakiTransport`] (real HTTPS via
//!     `waki`, gated behind `cfg(wasm)` + the `http` feature), and
//!   * in `cargo test` we plug in `MockTransport` and hand it canned responses.
//!
//! No `solana-sdk`, no async runtime — a plain blocking one-method trait.

use serde_json::{json, Value};

/// Errors the transport layer can produce. Callers map these into their own
/// fail-closed error types; nothing here ever panics.
#[derive(Debug, Clone, PartialEq)]
pub enum RpcError {
    /// The HTTP request itself failed (DNS, TLS, timeout, non-2xx).
    Transport(String),
    /// The body was not valid JSON, or not a JSON-RPC envelope.
    Decode(String),
    /// The node returned a JSON-RPC `error` object (code + message).
    Rpc { code: i64, message: String },
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RpcError::Transport(m) => write!(f, "rpc transport error: {m}"),
            RpcError::Decode(m) => write!(f, "rpc decode error: {m}"),
            RpcError::Rpc { code, message } => write!(f, "rpc error {code}: {message}"),
        }
    }
}

/// The seam. One method: perform a single JSON-RPC call and return the parsed
/// `result` value (or an [`RpcError`]). Implementors do the HTTP; this crate
/// owns the envelope shaping and response parsing so both implementations stay
/// trivial and identical in behaviour.
pub trait RpcTransport {
    /// Send the already-serialized JSON-RPC request body, return the raw
    /// response body as a string. This is the ONLY thing an implementor must
    /// do — everything else (building the request, parsing the envelope) is
    /// handled by [`RpcClient`].
    fn send(&self, request_body: &str) -> Result<String, RpcError>;
}

/// A reference to a transport is itself a transport, so a single transport can
/// be reused across several calls (e.g. a chain recovery AND a getAccountInfo
/// in one plugin invocation) without being consumed by the first `RpcClient`.
impl<T: RpcTransport + ?Sized> RpcTransport for &T {
    fn send(&self, request_body: &str) -> Result<String, RpcError> {
        (**self).send(request_body)
    }
}

/// A thin JSON-RPC client that wraps any [`RpcTransport`]. It builds the
/// standard `{jsonrpc, id, method, params}` envelope, calls the transport, and
/// unwraps `result` vs `error` — so callers write `client.call("getBalance",
/// json!([addr]))` and get back a clean `Value`.
pub struct RpcClient<T: RpcTransport> {
    transport: T,
}

impl<T: RpcTransport> RpcClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Make one JSON-RPC call. `params` is whatever the method expects
    /// (usually a JSON array). Returns the `result` value on success.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = build_request(method, params);
        let raw = self.transport.send(&body)?;
        parse_response(&raw)
    }
}

/// Build a JSON-RPC 2.0 request body. `id` is fixed to 1 — a plugin makes one
/// call per instance (fresh store per call), so a monotonic id buys nothing.
pub fn build_request(method: &str, params: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string()
}

/// Parse a JSON-RPC 2.0 response: return `result`, or surface a structured
/// `error`, or a decode error. Fail closed — an unexpected shape is an error,
/// never a silent empty value.
pub fn parse_response(raw: &str) -> Result<Value, RpcError> {
    let v: Value =
        serde_json::from_str(raw).map_err(|e| RpcError::Decode(format!("not JSON: {e}")))?;

    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        return Err(RpcError::Rpc { code, message });
    }

    match v.get("result") {
        Some(result) => Ok(result.clone()),
        None => Err(RpcError::Decode(
            "response has neither result nor error".into(),
        )),
    }
}

/// Production transport: real HTTPS via `waki` (blocking `wasi:http`). Only
/// compiled inside a wasm component AND when the `http` feature is on — a pure
/// plugin that imports no network never pulls this in. The RPC URL is supplied
/// by operator config (never hardcoded, per the bounty's trap #5).
#[cfg(all(target_family = "wasm", feature = "http"))]
pub struct WakiTransport {
    url: String,
}

#[cfg(all(target_family = "wasm", feature = "http"))]
impl WakiTransport {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

#[cfg(all(target_family = "wasm", feature = "http"))]
impl RpcTransport for WakiTransport {
    fn send(&self, request_body: &str) -> Result<String, RpcError> {
        let resp = waki::Client::new()
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(request_body.as_bytes().to_vec())
            .send()
            .map_err(|e| RpcError::Transport(format!("{e:?}")))?;
        let bytes = resp
            .body()
            .map_err(|e| RpcError::Transport(format!("read body: {e:?}")))?;
        String::from_utf8(bytes).map_err(|e| RpcError::Decode(format!("body not utf-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Test transport: records the last request it saw and returns a queued
    /// response. This is the whole reason the trait exists — deterministic,
    /// offline, inspectable.
    struct MockTransport {
        response: String,
        last_request: RefCell<Option<String>>,
    }

    impl MockTransport {
        fn returning(response: &str) -> Self {
            Self {
                response: response.to_string(),
                last_request: RefCell::new(None),
            }
        }
    }

    impl RpcTransport for MockTransport {
        fn send(&self, request_body: &str) -> Result<String, RpcError> {
            *self.last_request.borrow_mut() = Some(request_body.to_string());
            Ok(self.response.clone())
        }
    }

    #[test]
    fn builds_a_valid_jsonrpc_envelope() {
        let body = build_request("getSignatureStatuses", json!([["abc"]]));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "getSignatureStatuses");
        assert_eq!(v["params"][0][0], "abc");
    }

    #[test]
    fn client_unwraps_result() {
        let mock = MockTransport::returning(r#"{"jsonrpc":"2.0","id":1,"result":{"value":42}}"#);
        let client = RpcClient::new(mock);
        let out = client.call("getX", json!([])).unwrap();
        assert_eq!(out["value"], 42);
    }

    #[test]
    fn client_sends_the_method_the_caller_asked_for() {
        let mock = MockTransport::returning(r#"{"result":"ok"}"#);
        let client = RpcClient::new(mock);
        client.call("getBalance", json!(["wallet"])).unwrap();
        let sent = client.transport.last_request.borrow().clone().unwrap();
        assert!(sent.contains("\"method\":\"getBalance\""));
        assert!(sent.contains("wallet"));
    }

    #[test]
    fn surfaces_structured_rpc_errors() {
        let err = parse_response(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}"#,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RpcError::Rpc {
                code: -32602,
                message: "bad params".into()
            }
        );
    }

    #[test]
    fn fails_closed_on_garbage() {
        assert!(matches!(
            parse_response("not json"),
            Err(RpcError::Decode(_))
        ));
        // Neither result nor error present -> decode error, never a silent empty.
        assert!(matches!(
            parse_response(r#"{"jsonrpc":"2.0","id":1}"#),
            Err(RpcError::Decode(_))
        ));
    }

    #[test]
    fn result_can_be_any_shape() {
        // Solana returns arrays, objects, strings, nulls depending on method.
        for raw in [
            r#"{"result":[1,2,3]}"#,
            r#"{"result":"finalized"}"#,
            r#"{"result":null}"#,
        ] {
            assert!(parse_response(raw).is_ok(), "should accept {raw}");
        }
    }
}
