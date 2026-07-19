//! Host-run tests driving the exact code path the wasm `execute` runs,
//! with a mocked RPC — no live network, no wasm toolchain required.

use serde_json::{json, Value};
use solana_tx_inspect::logic;

fn sig() -> String {
    "5".repeat(80)
}

#[test]
fn success_path_reports_slot_status_fee() {
    let args = format!(r#"{{"signature": "{}"}}"#, sig());
    let (ok, out, err) = logic::run(&args, &|_u: &str, _b: &Value| {
        Ok(json!({"result": {"slot": 123, "blockTime": 0, "meta": {"err": null, "fee": 5000}}}))
    });
    assert!(ok, "err: {err:?}");
    assert!(out.contains("slot 123"));
    assert!(out.contains("success"));
    assert!(out.contains("0.000005000 SOL"));
}

#[test]
fn missing_transaction_is_a_clean_answer_not_an_error() {
    let args = format!(r#"{{"signature": "{}"}}"#, sig());
    let (ok, out, _) = logic::run(&args, &|_u: &str, _b: &Value| Ok(json!({"result": null})));
    assert!(ok);
    assert!(out.contains("not found"));
}

#[test]
fn failed_transaction_is_labelled() {
    let args = format!(r#"{{"signature": "{}"}}"#, sig());
    let (ok, out, _) = logic::run(&args, &|_u: &str, _b: &Value| {
        Ok(json!({"result": {"slot": 9, "meta": {"err": {"InstructionError": []}, "fee": 5000}}}))
    });
    assert!(ok);
    assert!(out.contains("FAILED"));
}

#[test]
fn malformed_signature_rejected_before_any_rpc_call() {
    let called = std::cell::Cell::new(false);
    let spy = |_u: &str, _b: &Value| {
        called.set(true);
        Ok(json!({"result": null}))
    };
    let (ok, _, err) = logic::run(r#"{"signature": "drop table; --"}"#, &spy);
    assert!(!ok);
    assert!(err.unwrap().contains("signature"));
    assert!(!called.get());
}

#[test]
fn rpc_transport_error_never_leaks_secret_url() {
    let secret = "https://rpc.example.com/?api-key=TOPSECRET";
    let args = format!(
        r#"{{"signature": "{}", "__config": {{"rpc_url": "{secret}"}}}}"#,
        sig()
    );
    let (ok, _, err) = logic::run(&args, &|_u: &str, _b: &Value| {
        Err(format!("could not reach {secret}: timeout"))
    });
    assert!(!ok);
    assert!(!err.unwrap().contains("TOPSECRET"));
}
