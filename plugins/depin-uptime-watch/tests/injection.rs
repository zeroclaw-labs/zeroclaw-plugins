use std::collections::HashMap;

use depin_uptime_watch::rpc::HttpClient;
use depin_uptime_watch::watch::{execute, parse_args_strict};
use depin_uptime_watch::{CoreError, CoreResult};
use serde_json::Value;

struct NoHttp;

impl HttpClient for NoHttp {
    fn post_json(&self, _url: &str, _body: &Value) -> CoreResult<Value> {
        Err(CoreError::msg("http must not be called for rejected input"))
    }
}

fn config() -> HashMap<String, String> {
    HashMap::from([
        ("rpc_url".to_string(), "https://rpc.test".to_string()),
        (
            "payer".to_string(),
            "4vJ9JU1bJJE96FWSFtTEWVHk49jq5DFLQgo5Scj1uW5g".to_string(),
        ),
    ])
}

#[test]
fn rejects_unknown_json_fields() {
    let err =
        parse_args_strict(r#"{"device_id":"device-7","max_age_secs":60,"destination":"attacker"}"#)
            .unwrap_err();

    assert!(err.contains("unknown field"));
}

#[test]
fn rejects_payer_and_private_key_in_args() {
    for field in ["payer", "private_key"] {
        let json = format!(r#"{{"device_id":"device-7","{field}":"malicious"}}"#);

        let err = parse_args_strict(&json).unwrap_err();
        assert!(err.contains("must come from config"), "{field}: {err}");
    }
}

#[test]
fn execute_rejects_payer_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","payer":"attacker"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("payer must come from config"));
}

#[test]
fn execute_rejects_private_key_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","private_key":"secret"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("private_key must come from config"));
}

#[test]
fn execute_rejects_unknown_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","max_age_secs":60,"rpc_url":"https://attacker"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("unknown field"));
}

#[test]
fn execute_rejects_reading_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","reading":1e99}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("unknown field"));
}

#[test]
fn execute_rejects_metric_field_before_rpc() {
    let err = execute(
        r#"{"device_id":"device-7","metric":"drain_wallet"}"#,
        &config(),
        &NoHttp,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("unknown field"));
}

/// Fail-closed when a malicious prompt tries to make the watcher move funds.
#[test]
fn execute_rejects_fund_movement_injection_before_rpc() {
    for json in [
        r#"{"device_id":"device-7","submit":true}"#,
        r#"{"device_id":"device-7","sendTransaction":true}"#,
        r#"{"device_id":"device-7","to":"attacker","amount":"all"}"#,
    ] {
        let err = execute(json, &config(), &NoHttp, 1_720_000_000).unwrap_err();
        assert!(
            err.contains("unknown field"),
            "expected unknown-field refusal for fund-move injection, got: {err}"
        );
    }
}

#[test]
fn plugin_sources_do_not_submit_transactions() {
    for source in [
        include_str!("../src/lib.rs"),
        include_str!("../src/watch.rs"),
        include_str!("../src/vendor/solana_core/rpc.rs"),
    ] {
        assert!(!source.contains("sendTransaction"));
        assert!(!source.contains("send_transaction"));
        // Trap 3: never dump raw program-account dumps into the model context.
        assert!(!source.contains("getProgramAccounts"));
    }
}
