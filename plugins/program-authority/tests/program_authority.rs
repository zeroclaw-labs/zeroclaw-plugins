use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use program_authority::program_authority::{
    build_report, inspect_program_account, parse_account_response, parse_programdata,
    validate_pubkey, validate_rpc_url, ProgramAuthorityConfig, ProgramLoader, RpcAccount,
    LEGACY_LOADER_V2, UPGRADEABLE_LOADER,
};
use serde_json::json;

fn pubkey(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

fn rpc_account(owner: &str, executable: bool, data: Vec<u8>) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "result": {
            "value": {
                "owner": owner,
                "executable": executable,
                "lamports": 1,
                "data": [BASE64.encode(data), "base64"]
            }
        }
    })
}

#[test]
fn validates_pubkeys_and_rpc_urls() {
    assert!(validate_pubkey(&pubkey(7), "program_id").is_ok());
    assert!(validate_pubkey("not-a-pubkey", "program_id").is_err());
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
    assert!(ProgramAuthorityConfig::from_section(&config).is_err());
}

#[test]
fn parses_base64_rpc_account() {
    let response = rpc_account(UPGRADEABLE_LOADER, true, vec![1, 2, 3]);
    let account = parse_account_response(&response, &pubkey(3)).unwrap();
    assert_eq!(account.owner, UPGRADEABLE_LOADER);
    assert!(account.executable);
    assert_eq!(account.data, vec![1, 2, 3]);
}

#[test]
fn rpc_error_fails_closed() {
    let response = json!({"error": {"code": -32000, "message": "rate limited"}});
    assert!(parse_account_response(&response, &pubkey(3)).is_err());
}

#[test]
fn extracts_programdata_address_from_program_state() {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend([9u8; 32]);
    let account = RpcAccount {
        owner: UPGRADEABLE_LOADER.to_string(),
        executable: true,
        lamports: 1,
        data,
    };
    assert_eq!(
        inspect_program_account(&account).unwrap(),
        ProgramLoader::Upgradeable {
            programdata_address: pubkey(9)
        }
    );
}

#[test]
fn malformed_program_state_is_rejected() {
    let account = RpcAccount {
        owner: UPGRADEABLE_LOADER.to_string(),
        executable: true,
        lamports: 1,
        data: vec![2, 0, 0, 0, 1],
    };
    assert!(inspect_program_account(&account).is_err());
}

#[test]
fn parses_mutable_programdata() {
    let mut data = 3u32.to_le_bytes().to_vec();
    data.extend(42u64.to_le_bytes());
    data.push(1);
    data.extend([5u8; 32]);
    let account = RpcAccount {
        owner: UPGRADEABLE_LOADER.to_string(),
        executable: false,
        lamports: 1,
        data,
    };
    let state = parse_programdata(&account).unwrap();
    assert_eq!(state.deployment_slot, 42);
    assert_eq!(state.upgrade_authority.as_deref(), Some(pubkey(5).as_str()));
}

#[test]
fn parses_immutable_programdata() {
    let mut data = 3u32.to_le_bytes().to_vec();
    data.extend(99u64.to_le_bytes());
    data.push(0);
    let account = RpcAccount {
        owner: UPGRADEABLE_LOADER.to_string(),
        executable: false,
        lamports: 1,
        data,
    };
    let state = parse_programdata(&account).unwrap();
    assert_eq!(state.deployment_slot, 99);
    assert_eq!(state.upgrade_authority, None);
}

#[test]
fn programdata_owner_must_match_loader() {
    let account = RpcAccount {
        owner: LEGACY_LOADER_V2.to_string(),
        executable: false,
        lamports: 1,
        data: vec![0; 45],
    };
    assert!(parse_programdata(&account).is_err());
}

#[test]
fn legacy_loader_is_reported_immutable() {
    let program_id = pubkey(4);
    let account = RpcAccount {
        owner: LEGACY_LOADER_V2.to_string(),
        executable: true,
        lamports: 1,
        data: vec![],
    };
    let loader = inspect_program_account(&account).unwrap();
    let report = build_report(&program_id, &account, &loader, None).unwrap();
    assert_eq!(report.upgradeable, Some(false));
    assert_eq!(report.immutable, Some(true));
    assert!(report.risk_flags.is_empty());
}
