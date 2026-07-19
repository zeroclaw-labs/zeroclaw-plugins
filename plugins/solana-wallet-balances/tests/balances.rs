//! Host-run tests driving the exact code path the wasm `execute` runs,
//! with a mocked RPC — no live network, no wasm toolchain required.

use serde_json::{json, Value};
use solana_wallet_balances::logic;

const ADDR: &str = "4Nd1mYQZa6uqSdARgeTMBBUVRvV7hDBGsFLoAegzohqx";

/// Mock fetch returning canned responses per RPC method.
fn mock(sol_lamports: u64, tokens: Vec<Value>) -> impl Fn(&str, &Value) -> Result<Value, String> {
    move |_url, body| match body["method"].as_str().unwrap() {
        "getBalance" => Ok(json!({"result": {"context": {}, "value": sol_lamports}})),
        "getTokenAccountsByOwner" => Ok(json!({"result": {"value": tokens.clone()}})),
        m => Err(format!("unexpected method {m}")),
    }
}

fn token(mint: &str, amount: &str) -> Value {
    json!({"account": {"data": {"parsed": {"info": {
        "mint": mint, "tokenAmount": {"uiAmountString": amount}
    }}}}})
}

#[test]
fn happy_path_combines_sol_and_tokens() {
    let args = format!(r#"{{"address": "{ADDR}"}}"#);
    let (ok, out, err) = logic::run(&args, &mock(2_500_000_000, vec![token("MintA1111", "12.5")]));
    assert!(ok, "err: {err:?}");
    assert!(out.contains("2.500000000 SOL"));
    assert!(out.contains("MintA1111: 12.5"));
}

#[test]
fn missing_address_fails_closed_with_actionable_error() {
    let (ok, _, err) = logic::run("{}", &mock(0, vec![]));
    assert!(!ok);
    assert!(err.unwrap().contains("address"));
}

#[test]
fn malformed_address_rejected_before_any_rpc_call() {
    let called = std::cell::Cell::new(false);
    let spy = |_u: &str, _b: &Value| -> Result<Value, String> {
        called.set(true);
        Ok(json!({"result": null}))
    };
    let (ok, _, _) = logic::run(r#"{"address": "https://evil.example/exfil"}"#, &spy);
    assert!(!ok);
    assert!(!called.get(), "must not spend an RPC call on invalid input");
}

#[test]
fn rpc_error_surfaces_as_tool_failure_not_panic() {
    let (ok, _, err) = logic::run(
        &format!(r#"{{"address": "{ADDR}"}}"#),
        &|_u: &str, _b: &Value| Ok(json!({"error": {"message": "rate limited"}})),
    );
    assert!(!ok);
    assert!(err.unwrap().contains("rate limited"));
}

#[test]
fn transport_error_never_leaks_rpc_url_secret() {
    let secret_url = "https://rpc.example.com/?api-key=SECRET123";
    let args = format!(
        r#"{{"address": "{ADDR}", "__config": {{"rpc_url": "{secret_url}"}}}}"#
    );
    let (ok, _, err) = logic::run(&args, &|_u: &str, _b: &Value| {
        Err(format!("request to {secret_url} timed out"))
    });
    assert!(!ok);
    let msg = err.unwrap();
    assert!(!msg.contains("SECRET123"), "leaked secret: {msg}");
}

#[test]
fn config_jail_empty_map_uses_public_rpc() {
    let seen = std::cell::RefCell::new(String::new());
    let spy = |url: &str, body: &Value| {
        seen.borrow_mut().push_str(url);
        match body["method"].as_str().unwrap() {
            "getBalance" => Ok(json!({"result": {"value": 0}})),
            _ => Ok(json!({"result": {"value": []}})),
        }
    };
    let (ok, _, _) = logic::run(&format!(r#"{{"address": "{ADDR}"}}"#), &spy);
    assert!(ok);
    assert!(seen.borrow().contains("api.mainnet-beta.solana.com"));
}
