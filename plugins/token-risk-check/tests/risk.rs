//! Host-side tests for the pure risk core (no wasm, no network).
use serde_json::json;
use token_risk_check::risk::{Rpc, score};

struct MockRpc {
    account: Option<serde_json::Value>,
    holders: Vec<serde_json::Value>,
}

impl Rpc for MockRpc {
    fn mint_account(&self, _m: &str) -> Option<serde_json::Value> { self.account.clone() }
    fn largest_accounts(&self, _m: &str) -> Vec<serde_json::Value> { self.holders.clone() }
}

fn parsed_account(mint_auth: Option<&str>, freeze: Option<&str>, t22: bool, exts: &[&str]) -> serde_json::Value {
    let owner = if t22 { "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" } else { "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" };
    let ext_json: Vec<serde_json::Value> = exts.iter().map(|e| json!({"extension": e})).collect();
    json!({
        "owner": owner,
        "parsed": {"info": {
            "mintAuthority": mint_auth,
            "freezeAuthority": freeze,
            "extensions": ext_json
        }}
    })
}

#[test]
fn safe_burned_mint_is_green() {
    let rpc = MockRpc {
        account: Some(parsed_account(None, None, false, &[])),
        holders: vec![json!({"uiAmount": 100.0})],
    };
    // supply 1_000_000 -> top holder 0.01%
    let r = score(&rpc, "MintX", Some(1_000_000.0));
    assert_eq!(r.level, "green");
    assert!(r.score < 20);
    assert!(!r.token_2022);
}

#[test]
fn live_authorities_and_permanent_delegate_are_red() {
    let rpc = MockRpc {
        account: Some(parsed_account(Some("Abc1"), Some("Abc2"), true, &["permanentDelegate"])),
        holders: vec![json!({"uiAmount": 900.0})],
    };
    let r = score(&rpc, "MintY", Some(1000.0)); // top holder 90%
    assert_eq!(r.level, "red");
    assert!(r.score >= 50);
    assert!(r.token_2022);
    assert!(r.extensions.iter().any(|e| e == "permanentDelegate"));
}

#[test]
fn freeze_authority_alone_is_amber() {
    let rpc = MockRpc {
        account: Some(parsed_account(None, Some("FrZ"), false, &[])),
        holders: vec![json!({"uiAmount": 10.0})],
    };
    let r = score(&rpc, "MintZ", Some(100.0));
    assert_eq!(r.level, "amber");
}

#[test]
fn missing_account_scores_high() {
    let rpc = MockRpc { account: None, holders: vec![] };
    let r = score(&rpc, "Nope", None);
    assert!(r.score >= 40);
}
