#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;
#[allow(dead_code)]
#[path = "../src/pubkey.rs"]
mod pubkey;

use std::collections::HashMap;

use config::{
    Config, DEFAULT_CRITICAL_OUTFLOW_BPS, DEFAULT_LARGE_OUTFLOW_BPS, DEFAULT_MAX_INSTRUCTIONS,
    DEFAULT_MAX_TRANSACTIONS,
};
use pubkey::SPL_GOVERNANCE_PROGRAM_ID;

const GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const OWNER: &str = "9bxWkNf3BtJ6iehq9KbX9uCWMjem4TFiPZ19T2sYJHvQ";
const MINT: &str = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";

fn base() -> HashMap<String, String> {
    HashMap::from([
        (
            "rpc_url".into(),
            "https://rpc.example.test/path?key=x".into(),
        ),
        ("expected_genesis_hash".into(), GENESIS.into()),
    ])
}

#[test]
fn parses_required_values_and_safe_defaults() {
    let config = Config::from_section(&base()).unwrap();

    assert_eq!(config.rpc_url, "https://rpc.example.test/path?key=x");
    assert_eq!(config.expected_genesis_hash.to_string(), GENESIS);
    assert_eq!(
        config.governance_program_ids[0].to_string(),
        SPL_GOVERNANCE_PROGRAM_ID
    );
    assert!(config.allowed_destination_owners.is_empty());
    assert!(config.allowed_mints.is_empty());
    assert_eq!(config.max_transactions, DEFAULT_MAX_TRANSACTIONS);
    assert_eq!(config.max_instructions, DEFAULT_MAX_INSTRUCTIONS);
    assert_eq!(config.large_outflow_bps, DEFAULT_LARGE_OUTFLOW_BPS);
    assert_eq!(config.critical_outflow_bps, DEFAULT_CRITICAL_OUTFLOW_BPS);
}

#[test]
fn parses_explicit_policy_and_limits() {
    let mut values = base();
    values.insert("governance_program_ids".into(), OWNER.into());
    values.insert("allowed_destination_owners".into(), OWNER.into());
    values.insert("allowed_mints".into(), MINT.into());
    values.insert("max_transactions".into(), "64".into());
    values.insert("max_instructions".into(), "128".into());
    values.insert("large_outflow_bps".into(), "0".into());
    values.insert("critical_outflow_bps".into(), "10000".into());

    let config = Config::from_section(&values).unwrap();
    assert_eq!(config.governance_program_ids[0].to_string(), OWNER);
    assert_eq!(config.allowed_destination_owners[0].to_string(), OWNER);
    assert_eq!(config.allowed_mints[0].to_string(), MINT);
    assert_eq!(config.max_transactions, 64);
    assert_eq!(config.max_instructions, 128);
}

#[test]
fn explicit_empty_policy_trusts_nothing_but_empty_governance_is_error() {
    let mut values = base();
    values.insert("allowed_destination_owners".into(), "  ".into());
    values.insert("allowed_mints".into(), String::new());
    let config = Config::from_section(&values).unwrap();
    assert!(config.allowed_destination_owners.is_empty());
    assert!(config.allowed_mints.is_empty());

    values.insert("governance_program_ids".into(), String::new());
    assert!(Config::from_section(&values).is_err());
}

#[test]
fn rejects_missing_or_malformed_required_values() {
    let mut values = base();
    values.remove("rpc_url");
    assert!(Config::from_section(&values).is_err());

    for url in [
        "http://rpc.example.test",
        "HTTPS://rpc.example.test",
        "https://",
        "https://rpc.example.test/#fragment",
        "https://user@rpc.example.test",
        "https://rpc.example.test:0",
        " https://rpc.example.test",
    ] {
        let mut values = base();
        values.insert("rpc_url".into(), url.into());
        assert!(Config::from_section(&values).is_err(), "accepted {url}");
    }

    let mut values = base();
    values.insert("expected_genesis_hash".into(), "1111".into());
    assert!(Config::from_section(&values).is_err());
}

#[test]
fn rejects_malformed_csv_without_falling_back() {
    for csv in [
        "not-base58",
        &format!("{OWNER},"),
        &format!("{OWNER},{OWNER}"),
    ] {
        let mut values = base();
        values.insert("allowed_destination_owners".into(), csv.into());
        assert!(Config::from_section(&values).is_err(), "accepted {csv}");
    }
}

#[test]
fn enforces_numeric_syntax_bounds_and_threshold_order() {
    for (key, value) in [
        ("max_transactions", "0"),
        ("max_transactions", "65"),
        ("max_instructions", "129"),
        ("max_instructions", "+1"),
        ("large_outflow_bps", "10001"),
        ("critical_outflow_bps", " 9000"),
    ] {
        let mut values = base();
        values.insert(key.into(), value.into());
        assert!(
            Config::from_section(&values).is_err(),
            "accepted {key}={value}"
        );
    }

    let mut values = base();
    values.insert("large_outflow_bps".into(), "9001".into());
    values.insert("critical_outflow_bps".into(), "9000".into());
    assert!(Config::from_section(&values).is_err());

    let mut values = base();
    values.insert("allowed_mnit".into(), MINT.into());
    assert!(Config::from_section(&values).is_err());
}
