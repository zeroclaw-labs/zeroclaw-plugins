//! Fail-closed matrix for `config::Config::from_map` and `args::parse_call`.
//! Every case here is a safety invariant: unknown/misspelled config keys,
//! http `rpc_url`, threshold ordering, unknown arg fields, bad-length
//! base58, and model-injected `rpc_url` args must all be hard errors.

use std::collections::HashMap;

use liquidation_guard::args::parse_call;
use liquidation_guard::config::Config;

const VALID_PUBKEY: &str = "7u3HeHxYDLhnCoErrtycNokbQYbWGzLs6JSDqGAv5PfF";

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// -- config::Config::from_map -----------------------------------------------

#[test]
fn unknown_config_key_rejected() {
    let m = map(&[("bogus_key", "1")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("bogus_key"));
}

/// The upstream maintainer's own competitor-audit finding: a misspelling of
/// `max_repay_ui` must never silently fall back to the default.
#[test]
fn misspelled_max_amout_key_rejected() {
    let m = map(&[("max_amout", "10")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("max_amout"));
}

#[test]
fn wrong_type_value_rejected() {
    let m = map(&[("watch_pct", "not-a-number")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("watch_pct"));
}

#[test]
fn http_rpc_url_rejected() {
    let m = map(&[("rpc_url", "http://api.mainnet-beta.solana.com")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("rpc_url"));
}

#[test]
fn https_rpc_url_accepted() {
    let m = map(&[("rpc_url", "https://example.com")]);
    let cfg = Config::from_map(&m).expect("https rpc_url must be accepted");
    assert_eq!(cfg.rpc_url, "https://example.com");
}

#[test]
fn defaults_applied_when_keys_absent() {
    let cfg = Config::from_map(&HashMap::new()).expect("empty config must apply defaults");
    assert_eq!(cfg.wallet, None);
    assert_eq!(cfg.markets, vec![VALID_PUBKEY.to_string()]);
    assert_eq!(cfg.watch_pct, 25.0);
    assert_eq!(cfg.warn_pct, 15.0);
    assert_eq!(cfg.critical_pct, 7.0);
    assert_eq!(cfg.rpc_url, "https://api.mainnet-beta.solana.com");
    assert_eq!(cfg.max_repay_ui, None);
}

#[test]
fn threshold_ordering_violation_rejected() {
    // critical_pct (20) is not < warn_pct (15): violates the required
    // critical_pct < warn_pct < watch_pct ordering.
    let m = map(&[
        ("critical_pct", "20"),
        ("warn_pct", "15"),
        ("watch_pct", "25"),
    ]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("critical_pct") && err.contains("warn_pct") && err.contains("watch_pct"));
}

#[test]
fn threshold_out_of_range_rejected() {
    let m = map(&[("watch_pct", "150")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("watch_pct"));
}

#[test]
fn bad_length_base58_wallet_config_rejected() {
    let m = map(&[("wallet", "abc")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("wallet"));
}

#[test]
fn rescue_disabled_when_max_repay_ui_absent() {
    let cfg = Config::from_map(&HashMap::new()).unwrap();
    assert_eq!(cfg.max_repay_ui, None);
}

#[test]
fn max_repay_ui_present_enables_rescue() {
    let m = map(&[("max_repay_ui", "50")]);
    let cfg = Config::from_map(&m).unwrap();
    assert_eq!(cfg.max_repay_ui, Some(50.0));
}

#[test]
fn negative_max_repay_ui_rejected() {
    let m = map(&[("max_repay_ui", "-5")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("max_repay_ui"));
}

/// v11-deposit-encoder: `max_deposit_ui` mirrors `max_repay_ui` semantics
/// exactly (absent -> deposit disabled).
#[test]
fn deposit_disabled_when_max_deposit_ui_absent() {
    let cfg = Config::from_map(&HashMap::new()).unwrap();
    assert_eq!(cfg.max_deposit_ui, None);
}

#[test]
fn max_deposit_ui_present_enables_deposit() {
    let m = map(&[("max_deposit_ui", "50")]);
    let cfg = Config::from_map(&m).unwrap();
    assert_eq!(cfg.max_deposit_ui, Some(50.0));
}

#[test]
fn negative_max_deposit_ui_rejected() {
    let m = map(&[("max_deposit_ui", "-5")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("max_deposit_ui"));
}

#[test]
fn priority_fee_absent_defaults_to_off() {
    let cfg = Config::from_map(&HashMap::new()).unwrap();
    assert_eq!(cfg.priority_fee_microlamports, None);
}

#[test]
fn priority_fee_present_enables_feature() {
    let m = map(&[("priority_fee_microlamports", "10000")]);
    let cfg = Config::from_map(&m).unwrap();
    assert_eq!(cfg.priority_fee_microlamports, Some(10_000));
}

#[test]
fn priority_fee_zero_rejected() {
    let m = map(&[("priority_fee_microlamports", "0")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("priority_fee_microlamports"));
}

#[test]
fn priority_fee_fractional_rejected() {
    let m = map(&[("priority_fee_microlamports", "1.5")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("priority_fee_microlamports"));
}

#[test]
fn priority_fee_negative_rejected() {
    let m = map(&[("priority_fee_microlamports", "-1")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("priority_fee_microlamports"));
}

#[test]
fn nonce_account_absent_defaults_to_off() {
    let cfg = Config::from_map(&HashMap::new()).unwrap();
    assert_eq!(cfg.nonce_account, None);
}

#[test]
fn nonce_account_valid_base58_accepted() {
    let m = map(&[("nonce_account", VALID_PUBKEY)]);
    let cfg = Config::from_map(&m).unwrap();
    assert_eq!(cfg.nonce_account, Some(VALID_PUBKEY.to_string()));
}

#[test]
fn nonce_account_bad_base58_rejected() {
    let m = map(&[("nonce_account", "abc")]);
    let err = Config::from_map(&m).unwrap_err();
    assert!(err.contains("nonce_account"));
}

#[test]
fn comma_separated_markets_parsed() {
    let two = format!("{VALID_PUBKEY},{VALID_PUBKEY}");
    let m = map(&[("markets", two.as_str())]);
    let cfg = Config::from_map(&m).unwrap();
    assert_eq!(
        cfg.markets,
        vec![VALID_PUBKEY.to_string(), VALID_PUBKEY.to_string()]
    );
}

// -- args::parse_call ---------------------------------------------------------

#[test]
fn unknown_arg_field_rejected() {
    let raw = r#"{"action":"check","bogus":"x"}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("bogus"));
}

/// The model must never be able to redirect network traffic: an `rpc_url`
/// argument arrives structurally as an unknown field and is refused.
#[test]
fn injected_rpc_url_arg_rejected() {
    let raw = r#"{"action":"check","rpc_url":"https://evil.example"}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("rpc_url"));
}

#[test]
fn action_outside_enum_rejected() {
    let raw = r#"{"action":"nuke"}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("action"));
}

#[test]
fn bad_length_base58_arg_rejected() {
    let raw = r#"{"action":"check","wallet":"abc"}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("wallet"));
}

#[test]
fn valid_wallet_market_obligation_args_accepted() {
    let raw = format!(
        r#"{{"action":"check","wallet":"{p}","market":"{p}","obligation":"{p}"}}"#,
        p = VALID_PUBKEY
    );
    let parsed = parse_call(&raw).expect("valid 32-byte base58 fields must be accepted");
    assert_eq!(parsed.wallet.as_deref(), Some(VALID_PUBKEY));
    assert_eq!(parsed.market.as_deref(), Some(VALID_PUBKEY));
    assert_eq!(parsed.obligation.as_deref(), Some(VALID_PUBKEY));
}

#[test]
fn missing_config_defaults_to_empty_map() {
    let raw = r#"{"action":"check"}"#;
    let parsed = parse_call(raw).expect("missing __config must parse with defaults applied");
    assert_eq!(parsed.config.rpc_url, "https://api.mainnet-beta.solana.com");
    assert!(parsed.wallet.is_none());
}

#[test]
fn negative_repay_ui_amount_rejected() {
    let raw = r#"{"action":"rescue","repay_ui_amount":-1}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("repay_ui_amount"));
}

#[test]
fn zero_repay_ui_amount_rejected() {
    let raw = r#"{"action":"rescue","repay_ui_amount":0}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("repay_ui_amount"));
}

#[test]
fn positive_repay_ui_amount_accepted() {
    let raw = r#"{"action":"rescue","repay_ui_amount":12.5}"#;
    let parsed = parse_call(raw).unwrap();
    assert_eq!(parsed.repay_ui_amount, Some(12.5));
}

/// v11-deposit-encoder: `action":"deposit"` is a valid enum value.
#[test]
fn deposit_action_accepted() {
    let raw = r#"{"action":"deposit"}"#;
    let parsed = parse_call(raw).expect("deposit action must be accepted");
    assert!(matches!(
        parsed.action,
        liquidation_guard::args::Action::Deposit
    ));
}

#[test]
fn negative_deposit_ui_amount_rejected() {
    let raw = r#"{"action":"deposit","deposit_ui_amount":-1}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("deposit_ui_amount"));
}

#[test]
fn zero_deposit_ui_amount_rejected() {
    let raw = r#"{"action":"deposit","deposit_ui_amount":0}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("deposit_ui_amount"));
}

#[test]
fn positive_deposit_ui_amount_accepted() {
    let raw = r#"{"action":"deposit","deposit_ui_amount":12.5}"#;
    let parsed = parse_call(raw).unwrap();
    assert_eq!(parsed.deposit_ui_amount, Some(12.5));
}

#[test]
fn invalid_config_inside_args_propagates_key_name() {
    let raw = r#"{"action":"check","__config":{"max_amout":"10"}}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(err.contains("max_amout"));
}

/// Error strings are plain data naming the offending key, never the raw
/// payload — a secret-shaped value elsewhere in the payload must not leak
/// into the error message.
#[test]
fn error_never_echoes_raw_payload_value() {
    let raw = r#"{"action":"check","bogus_field":"topsecret123"}"#;
    let err = parse_call(raw).unwrap_err();
    assert!(!err.contains("topsecret123"));
    assert!(err.contains("bogus_field"));
}
