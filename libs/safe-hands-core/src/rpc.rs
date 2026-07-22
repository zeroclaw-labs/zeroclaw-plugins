//! RPC boundary: one trait, three implementations.
//!
//! `SolanaJsonRpcTransport` (waki, wasm-only) talks to a real endpoint;
//! `MockTransport` answers from canned envelopes so every host test runs
//! offline. The policy engine never sees HTTP — only this trait.

use serde_json::{json, Value};

/// Minimal JSON-RPC transport. Implementations must be deterministic given the
/// same request.
pub trait RpcTransport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

/// Build a JSON-RPC 2.0 request envelope.
pub fn envelope(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// Canned-answer transport for host tests. Answers are matched by method name;
/// a missing method is an error, never a guess.
#[derive(Default)]
pub struct MockTransport {
    pub responses: std::collections::HashMap<String, Value>,
    calls: std::cell::RefCell<Vec<(String, Value)>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, method: &str, response: Value) -> Self {
        self.responses.insert(method.to_string(), response);
        self
    }

    /// Return the exact method/params pairs observed by this mock.
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.calls.borrow().clone()
    }
}

impl RpcTransport for MockTransport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.calls
            .borrow_mut()
            .push((method.to_string(), params));
        self.responses
            .get(method)
            .cloned()
            .ok_or_else(|| format!("mock transport has no fixture for {method}"))
    }
}

/// Failing transport: every call errors. Used by fail-closed tests.
pub struct DownTransport;

impl RpcTransport for DownTransport {
    fn call(&self, method: &str, _params: Value) -> Result<Value, String> {
        Err(format!("endpoint unreachable during {method}"))
    }
}

/// Real JSON-RPC transport over wasi:http (blocking `waki` client).
/// Compiled only for the wasm component; host tests never link it.
#[cfg(target_family = "wasm")]
pub struct WakiTransport {
    pub url: String,
}

#[cfg(target_family = "wasm")]
impl WakiTransport {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

#[cfg(target_family = "wasm")]
impl RpcTransport for WakiTransport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = envelope(method, params);
        waki::Client::new()
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| format!("rpc transport error: {e}"))?
            .json::<Value>()
            .map_err(|e| format!("rpc response parse error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_answers_and_records() {
        let rpc = MockTransport::new().with("getBalance", json!({"result": {"value": 42}}));
        let out = rpc.call("getBalance", json!([])).expect("fixture");
        assert_eq!(out["result"]["value"], 42);
        assert_eq!(rpc.calls()[0], ("getBalance".to_string(), json!([])));
    }

    #[test]
    fn missing_fixture_is_error_not_guess() {
        let rpc = MockTransport::new();
        assert!(rpc.call("getBalance", json!([])).is_err());
    }

    #[test]
    fn down_transport_fails_closed() {
        assert!(DownTransport.call("getBalance", json!([])).is_err());
    }
}
