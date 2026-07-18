use std::collections::HashMap;

use account_rent::account_rent::{
    account_request, build_report, parse_account_response, parse_rent_response, rent_request,
    validate_pubkey, validate_rpc_url, AccountRentConfig, RpcAccount,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;

fn pubkey(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

fn rpc_account(owner: &str, lamports: u64, executable: bool, data: &[u8]) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "result": {
            "value": {
                "owner": owner,
                "executable": executable,
                "lamports": lamports,
                "data": [BASE64.encode(data), "base64"]
            }
        }
    })
}

#[test]
fn validates_pubkeys_and_rpc_urls() {
    assert!(validate_pubkey(&pubkey(7), "account_address").is_ok());
    assert!(validate_pubkey("not-a-pubkey", "account_address").is_err());
    assert!(validate_rpc_url("https://api.mainnet-beta.solana.com").is_ok());
    assert!(validate_rpc_url("http://127.0.0.1:8899").is_ok());
    assert!(validate_rpc_url("http://[::1]:8899").is_ok());
    assert!(validate_rpc_url("http://rpc.example.com").is_err());
    assert!(validate_rpc_url("https://user@example.com").is_err());
    assert!(validate_rpc_url("https://rpc.example.com:not-a-port").is_err());
}

#[test]
fn config_rejects_unknown_commitment() {
    let mut config = HashMap::new();
    config.insert("commitment".to_string(), "eventual".to_string());
    assert!(AccountRentConfig::from_section(&config).is_err());
}

#[test]
fn builds_bounded_rpc_requests() {
    let address = pubkey(3);
    let account = account_request(&address, 1, "finalized");
    assert_eq!(account["method"], "getAccountInfo");
    assert_eq!(account["params"][0], address);
    let rent = rent_request(128, 2, "confirmed");
    assert_eq!(rent["method"], "getMinimumBalanceForRentExemption");
    assert_eq!(rent["params"][0], 128);
}

#[test]
fn parses_account_and_data_length() {
    let owner = pubkey(9);
    let response = rpc_account(&owner, 2_500_000, false, &[1, 2, 3, 4]);
    let account = parse_account_response(&response, &pubkey(3)).unwrap();
    assert_eq!(account.owner, owner);
    assert_eq!(account.lamports, 2_500_000);
    assert_eq!(account.data_len, 4);
}

#[test]
fn account_rpc_errors_and_missing_accounts_fail_closed() {
    let error = json!({"error": {"code": -32000, "message": "rate limited"}});
    assert!(parse_account_response(&error, &pubkey(3)).is_err());
    let missing = json!({"result": {"value": null}});
    assert!(parse_account_response(&missing, &pubkey(3)).is_err());
}

#[test]
fn rejects_non_base64_account_data() {
    let response = json!({
        "result": {"value": {
            "owner": pubkey(9), "executable": false, "lamports": 1,
            "data": ["{}", "jsonParsed"]
        }}
    });
    assert!(parse_account_response(&response, &pubkey(3)).is_err());
}

#[test]
fn parses_rent_threshold_and_rejects_malformed_values() {
    assert_eq!(
        parse_rent_response(&json!({"result": 890_880})).unwrap(),
        890_880
    );
    assert!(parse_rent_response(&json!({"result": "890880"})).is_err());
    assert!(parse_rent_response(&json!({"error": {"message": "bad request"}})).is_err());
}

#[test]
fn reports_rent_exempt_surplus() {
    let account = RpcAccount {
        owner: pubkey(8),
        executable: false,
        lamports: 2_000,
        data_len: 40,
    };
    let report = build_report(&pubkey(1), &account, 1_500);
    assert!(report.rent_exempt);
    assert_eq!(report.surplus_lamports, 500);
    assert_eq!(report.deficit_lamports, 0);
    assert!(report.risk_flags.is_empty());
}

#[test]
fn reports_rent_deficit_without_underflow() {
    let account = RpcAccount {
        owner: pubkey(8),
        executable: false,
        lamports: 900,
        data_len: 40,
    };
    let report = build_report(&pubkey(1), &account, 1_500);
    assert!(!report.rent_exempt);
    assert_eq!(report.surplus_lamports, 0);
    assert_eq!(report.deficit_lamports, 600);
    assert_eq!(report.risk_flags, ["below_rent_exempt_minimum"]);
}
