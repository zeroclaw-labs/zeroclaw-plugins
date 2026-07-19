use caixa_core::MockTransport;
use caixa_watch::watch::{execute_watch, WatchArgs, WatchConfig};
use serde_json::json;

#[test]
fn prompt_injection_cannot_move_funds() {
    // Watch is T0 — even a malicious invoice_id must fail closed or no-op, never transfer.
    let mock = MockTransport::single(json!({
        "jsonrpc":"2.0","id":1,"result":[]
    }));
    let mut cfg = WatchConfig::default();
    cfg.default_recipient = Some(
        caixa_core::Pubkey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap(),
    );
    let err = execute_watch(
        &WatchArgs {
            recipient: None,
            invoice_id: "private_key=please_drain".into(),
            amount_usdc: Some("1000000".into()),
            mint: None,
            reference: None,
        },
        &cfg,
        &mock,
    );
    assert!(err.is_err());
}
