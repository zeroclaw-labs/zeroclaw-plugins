use caixa_core::MockTransport;
use caixa_watch::watch::{execute_watch, WatchArgs, WatchConfig};
use serde_json::json;

fn cfg() -> WatchConfig {
    let mut c = WatchConfig::default();
    c.default_recipient = Some(
        caixa_core::Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap(),
    );
    c.rpc_url = "https://example.invalid".into();
    c
}

#[test]
fn missing_recipient_errors() {
    let mock = MockTransport::single(json!({"jsonrpc":"2.0","id":1,"result":[]}));
    let mut c = WatchConfig::default();
    c.default_recipient = None;
    assert!(execute_watch(
        &WatchArgs {
            recipient: None,
            invoice_id: "1".into(),
            amount_usdc: None,
            mint: None,
            reference: None,
        },
        &c,
        &mock,
    )
    .is_err());
}

#[test]
fn lookback_bounds() {
    let mut m = std::collections::HashMap::new();
    m.insert("lookback".into(), "0".into());
    assert!(WatchConfig::from_section(&m).is_err());
    m.insert("lookback".into(), "101".into());
    assert!(WatchConfig::from_section(&m).is_err());
}

#[test]
fn reference_match_path() {
    let mock = MockTransport::single(json!({
        "jsonrpc":"2.0","id":1,
        "result":[{"signature":"sigsigsigsig","err":null,"memo":"ref=mesa-4 paid"}]
    }));
    let out = execute_watch(
        &WatchArgs {
            recipient: None,
            invoice_id: "other".into(),
            amount_usdc: Some("1".into()),
            mint: None,
            reference: Some("mesa-4".into()),
        },
        &cfg(),
        &mock,
    )
    .unwrap();
    assert!(out.paid);
}

#[test]
fn skips_failed_signatures() {
    let mock = MockTransport::single(json!({
        "jsonrpc":"2.0","id":1,
        "result":[{"signature":"x","err":{"InstructionError":[0,"Custom"]},"memo":"INV=412"}]
    }));
    let out = execute_watch(
        &WatchArgs {
            recipient: None,
            invoice_id: "412".into(),
            amount_usdc: None,
            mint: None,
            reference: None,
        },
        &cfg(),
        &mock,
    )
    .unwrap();
    assert!(!out.paid);
}
