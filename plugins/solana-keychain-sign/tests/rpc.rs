//! Host-side integration tests for the [`rpc`] module. No wasm toolchain, no
//! network — every RPC is faked by [`MockTransport`] returning canned JSON.
//!
//! Coverage:
//!   - `getLatestBlockhash` happy path + error envelope.
//!   - `sendTransaction` happy path + RPC error envelope (preflight revert).
//!   - `get_signature_status` → None / Pending(processed) / Confirmed / Failed.
//!   - `submit_and_confirm` happy path (confirmed on first poll).
//!   - `submit_and_confirm` fails fast on a `Failed` status.
//!   - `submit_and_confirm` times out cleanly when status never advances.
//!   - `decode_signature_status` classification unit tests.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

use solana_keychain_sign::rpc::{
    self, Blockhash, Confirmation, RpcClient, RpcTransport, DEFAULT_CONFIRM_TIMEOUT_SECS,
};

// ── MockTransport ────────────────────────────────────────────────────────────

/// Scripted transport: caller queues one canned response per call (either an
/// `Ok(Value)` or an `Err(String)`). The URL passed to `post_json` is matched
/// against `expected_url` to assert the client is hitting the configured RPC.
#[derive(Default)]
struct MockTransport {
    expected_url: String,
    /// Pre-baked responses, popped FIFO. The test sets these up before
    /// driving the client.
    responses: RefCell<VecDeque<Result<Value, String>>>,
    /// Captured request bodies, in call order — tests assert the JSON-RPC
    /// envelope was built correctly.
    sent: RefCell<Vec<Value>>,
    call_count: AtomicUsize,
}

impl MockTransport {
    fn new(expected_url: &str) -> Self {
        Self {
            expected_url: expected_url.to_string(),
            responses: RefCell::new(VecDeque::new()),
            sent: RefCell::new(Vec::new()),
            call_count: AtomicUsize::new(0),
        }
    }

    fn push_ok(&self, v: Value) {
        self.responses.borrow_mut().push_back(Ok(v));
    }
    fn sent_bodies(&self) -> Vec<Value> {
        self.sent.borrow().clone()
    }

    fn calls(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl RpcTransport for &MockTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, String> {
        assert_eq!(url, self.expected_url, "client posted to wrong URL");
        self.sent.borrow_mut().push(body.clone());
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| panic!("MockTransport: post_json called with no queued response"))
    }
}

// Helper: build a client using `&MockTransport` as the transport and a tight
// poll interval so submit_and_confirm tests don't sleep.
fn client<'a>(mock_url: &'a str, mock: &'a MockTransport) -> RpcClient<&'a MockTransport> {
    RpcClient::new_full(mock_url, mock, DEFAULT_CONFIRM_TIMEOUT_SECS, 0)
}

// ── getLatestBlockhash ───────────────────────────────────────────────────────

#[test]
fn get_latest_blockhash_decodes_value_envelope() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "context": { "slot": 123, "apiVersion": "1.18.0" },
            "value": {
                "blockhash": "2AiiQZxYcNYbi7J7NxoyQmC5y7QXuG6v7Yx5Z9XqYoB",
                "lastValidBlockHeight": 222_222_222,
            }
        }
    }));
    let c = client("https://rpc.example", &m);
    let bh = c.get_latest_blockhash().expect("blockhash");
    assert_eq!(
        bh,
        Blockhash {
            blockhash: "2AiiQZxYcNYbi7J7NxoyQmC5y7QXuG6v7Yx5Z9XqYoB".to_string(),
            last_valid_block_height: 222_222_222,
        }
    );

    // Verify the request envelope shape.
    let sent = m.sent_bodies();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["method"], "getLatestBlockhash");
    assert_eq!(sent[0]["jsonrpc"], "2.0");
    assert_eq!(sent[0]["id"], 1);
}

#[test]
fn get_latest_blockhash_surfaces_rpc_error_envelope() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": -32601, "message": "Method not found" }
    }));
    let c = client("https://rpc.example", &m);
    let err = c.get_latest_blockhash().expect_err("should fail");
    assert!(
        err.contains("getLatestBlockhash rpc error"),
        "unexpected error: {err}"
    );
    assert!(err.contains("Method not found"));
}

#[test]
fn get_latest_blockhash_rejects_missing_value() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({ "jsonrpc": "2.0", "id": 1, "result": {} }));
    let c = client("https://rpc.example", &m);
    let err = c.get_latest_blockhash().expect_err("should fail");
    assert!(err.contains("missing result.value"));
}

// ── sendTransaction ──────────────────────────────────────────────────────────

#[test]
fn send_transaction_decodes_signature_and_pins_preflight_commitment() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": "5K6o7t2Yx9nQ8bBeqWkJmLh2o3mP9s1rVd8QjXv4rNqHrXq9pYm2Lh4Fq3Kv8nXy"
    }));
    let c = client("https://rpc.example", &m);
    let sig = c.send_transaction("AAABAA==").expect("signature");
    assert!(sig.starts_with("5K6o7t2Yx9nQ"));

    let sent = m.sent_bodies();
    assert_eq!(sent[0]["method"], "sendTransaction");
    // Preflight commitment pinned — see rpc.rs comment.
    assert_eq!(sent[0]["params"][1]["preflight_commitment"], "confirmed");
    assert_eq!(sent[0]["params"][1]["encoding"], "base64");
    assert_eq!(sent[0]["params"][1]["max_retries"], 0);
    assert_eq!(sent[0]["params"][0], "AAABAA==");
}

#[test]
fn send_transaction_surfaces_preflight_revert_as_error() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32003,
            "message": "Transaction simulation failed: Instruction fallback was not provided"
        }
    }));
    let c = client("https://rpc.example", &m);
    let err = c.send_transaction("AA==").expect_err("should fail");
    assert!(err.contains("sendTransaction rpc error"));
    assert!(err.contains("simulation failed"));
}

#[test]
fn send_transaction_rejects_non_string_result() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({ "jsonrpc": "2.0", "id": 1, "result": 42 }));
    let c = client("https://rpc.example", &m);
    let err = c.send_transaction("AA==").expect_err("should fail");
    assert!(err.contains("missing result string"));
}

// ── getSignatureStatuses ─────────────────────────────────────────────────────

#[test]
fn get_signature_status_none_when_rpc_returns_null_entry() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "context": { "slot": 999 },
            "value": [null]
        }
    }));
    let c = client("https://rpc.example", &m);
    assert_eq!(c.get_signature_status("sig").unwrap(), None);

    // Verify the request wrapped the sig in a single-element array.
    let sent = m.sent_bodies();
    assert_eq!(sent[0]["method"], "getSignatureStatuses");
    assert_eq!(sent[0]["params"][0], json!(["sig"]));
}

#[test]
fn get_signature_status_pending_when_only_processed() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "context": { "slot": 1001 },
            "value": [{
                "slot": 1000,
                "err": null,
                "confirmationStatus": "processed"
            }]
        }
    }));
    let c = client("https://rpc.example", &m);
    assert_eq!(
        c.get_signature_status("sig").unwrap(),
        Some(Confirmation::Pending { slot: 1000 })
    );
}

#[test]
fn get_signature_status_confirmed_at_confirmed_level() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "context": { "slot": 1005 },
            "value": [{
                "slot": 1000,
                "err": null,
                "confirmationStatus": "confirmed"
            }]
        }
    }));
    let c = client("https://rpc.example", &m);
    assert_eq!(
        c.get_signature_status("sig").unwrap(),
        Some(Confirmation::Confirmed {
            slot: 1000,
            level: "confirmed".to_string(),
        })
    );
}

#[test]
fn get_signature_status_confirmed_at_finalized_level() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "context": { "slot": 1010 },
            "value": [{
                "slot": 1000,
                "err": null,
                "confirmationStatus": "finalized"
            }]
        }
    }));
    let c = client("https://rpc.example", &m);
    match c.get_signature_status("sig").unwrap() {
        Some(Confirmation::Confirmed { level, .. }) => assert_eq!(level, "finalized"),
        other => panic!("expected Confirmed, got {other:?}"),
    }
}

#[test]
fn get_signature_status_failed_when_err_present() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "context": { "slot": 1005 },
            "value": [{
                "slot": 1000,
                "err": { "InstructionError": [0, "Custom(1)"] },
                "confirmationStatus": "confirmed"
            }]
        }
    }));
    let c = client("https://rpc.example", &m);
    match c.get_signature_status("sig").unwrap() {
        Some(Confirmation::Failed { err, .. }) => {
            assert!(err.contains("InstructionError"));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

// ── submit_and_confirm orchestration ─────────────────────────────────────────

#[test]
fn submit_and_confirm_returns_signature_on_first_confirmed_poll() {
    let m = MockTransport::new("https://rpc.example");
    // 1) sendTransaction → signature
    m.push_ok(json!({
        "jsonrpc": "2.0", "id": 1,
        "result": "SIGCONFIRMONFIRSTPOLL"
    }));
    // 2) getSignatureStatuses → confirmed immediately
    m.push_ok(json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "context": { "slot": 5 }, "value": [{
            "slot": 4, "err": null, "confirmationStatus": "confirmed"
        }]}
    }));

    let c = client("https://rpc.example", &m);
    let sig = c.submit_and_confirm("AA==").expect("should confirm");
    assert_eq!(sig, "SIGCONFIRMONFIRSTPOLL");
    assert_eq!(m.calls(), 2, "send + 1 status poll = 2 calls");
}

#[test]
fn submit_and_confirm_polls_until_confirmed() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({ "jsonrpc": "2.0", "id": 1, "result": "SIGPENDING" }));
    // First poll: processed (still pending).
    m.push_ok(
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": 5 }, "value": [{
            "slot": 4, "err": null, "confirmationStatus": "processed"
        }]}}),
    );
    // Second poll: still null (RPC hasn't seen it yet).
    m.push_ok(
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": 6 }, "value": [null]}}),
    );
    // Third poll: confirmed.
    m.push_ok(
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": 7 }, "value": [{
            "slot": 4, "err": null, "confirmationStatus": "confirmed"
        }]}}),
    );

    let c = client("https://rpc.example", &m);
    let sig = c.submit_and_confirm("AA==").expect("should confirm");
    assert_eq!(sig, "SIGPENDING");
    assert_eq!(m.calls(), 4, "send + 3 status polls");
}

#[test]
fn submit_and_confirm_fails_fast_on_transaction_error() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({ "jsonrpc": "2.0", "id": 1, "result": "SIGFAIL" }));
    m.push_ok(
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": 5 }, "value": [{
            "slot": 4, "err": { "InstructionError": [1, "InsufficientFunds"] },
            "confirmationStatus": "confirmed"
        }]}}),
    );

    let c = client("https://rpc.example", &m);
    let err = c
        .submit_and_confirm("AA==")
        .expect_err("should hard-stop on Failed");
    assert!(err.contains("transaction landed with error"));
    assert!(err.contains("InsufficientFunds"));
    assert_eq!(m.calls(), 2, "no further polling after Failed");
}

#[test]
fn submit_and_confirm_times_out_when_never_confirmed() {
    // A transport whose status polls always return null — the tx is "stuck".
    // With poll_interval=0 and confirm_timeout=1s the loop spins against the
    // clock; the deadline fires inside ~1s on any reasonable host. A queue
    // is the wrong tool here (50+ polls in 1s), so this test uses a tiny
    // inline transport that synthesizes its response from the method name.
    #[derive(Default)]
    struct StuckTransport;
    impl RpcTransport for StuckTransport {
        fn post_json(&self, _url: &str, body: &Value) -> Result<Value, String> {
            Ok(if body.get("method") == Some(&json!("sendTransaction")) {
                json!({ "jsonrpc": "2.0", "id": 1, "result": "SIGSTUCK" })
            } else {
                // getSignatureStatuses → signature never seen.
                json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": { "context": { "slot": 999 }, "value": [null] }
                })
            })
        }
    }

    let c = RpcClient::new_full("https://rpc.example", StuckTransport, 1, 0);
    let err = c.submit_and_confirm("AA==").expect_err("should time out");
    assert!(err.contains("timeout"), "unexpected error: {err}");
    assert!(err.contains("SIGSTUCK"));
}

#[test]
fn submit_and_confirm_propagates_send_transaction_error() {
    let m = MockTransport::new("https://rpc.example");
    m.push_ok(json!({
        "jsonrpc": "2.0", "id": 1,
        "error": { "code": -32003, "message": "blockhash not found" }
    }));
    let c = client("https://rpc.example", &m);
    let err = c
        .submit_and_confirm("AA==")
        .expect_err("send error should propagate");
    assert!(err.contains("sendTransaction rpc error"));
    assert!(err.contains("blockhash not found"));
    assert_eq!(m.calls(), 1, "no polling after send failure");
}

// ── decode_signature_status unit tests (no transport) ────────────────────────

#[test]
fn decode_null_entry_is_none() {
    assert_eq!(rpc::decode_signature_status(&json!(null)).unwrap(), None);
}

#[test]
fn decode_processed_is_pending() {
    let v = json!({ "slot": 1, "err": null, "confirmationStatus": "processed" });
    assert_eq!(
        rpc::decode_signature_status(&v).unwrap(),
        Some(Confirmation::Pending { slot: 1 })
    );
}

#[test]
fn decode_confirmed_is_confirmed() {
    let v = json!({ "slot": 2, "err": null, "confirmationStatus": "confirmed" });
    assert_eq!(
        rpc::decode_signature_status(&v).unwrap(),
        Some(Confirmation::Confirmed {
            slot: 2,
            level: "confirmed".to_string()
        })
    );
}

#[test]
fn decode_missing_err_is_treated_as_success() {
    // Some RPC responses omit `err` entirely; we must not panic.
    let v = json!({ "slot": 3, "confirmationStatus": "finalized" });
    assert!(matches!(
        rpc::decode_signature_status(&v).unwrap(),
        Some(Confirmation::Confirmed { level, .. }) if level == "finalized"
    ));
}

#[test]
fn decode_unknown_status_with_null_err_falls_back_to_pending() {
    let v = json!({ "slot": 4, "err": null, "confirmationStatus": "boy who knows" });
    assert_eq!(
        rpc::decode_signature_status(&v).unwrap(),
        Some(Confirmation::Pending { slot: 4 })
    );
}

#[test]
fn decode_err_object_is_failed() {
    let v = json!({ "slot": 5, "err": { "Custom": 1 }, "confirmationStatus": "confirmed" });
    match rpc::decode_signature_status(&v).unwrap() {
        Some(Confirmation::Failed { err, .. }) => assert!(err.contains("Custom")),
        other => panic!("expected Failed, got {other:?}"),
    }
}
