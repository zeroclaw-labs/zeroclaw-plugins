use std::collections::HashMap;

use caixa_charge::charge::{execute_charge, ChargeArgs, ChargeConfig};
use caixa_core::rpc::MockHttpGet;
use serde_json::json;

fn cfg_map(extra: &[(&str, &str)]) -> ChargeConfig {
    let mut m = HashMap::new();
    m.insert(
        "recipient".into(),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
    );
    for (k, v) in extra {
        m.insert((*k).into(), (*v).into());
    }
    ChargeConfig::from_section(&m).unwrap()
}

#[test]
fn both_amounts_rejected() {
    let http = MockHttpGet {
        body: json!({}),
    };
    let err = execute_charge(
        &ChargeArgs {
            amount_brl: Some(1.0),
            amount_usdc: Some("1".into()),
            recipient: None,
            invoice_id: "1".into(),
            memo_extra: None,
            message: None,
            mint: None,
            reference: None,
        },
        &cfg_map(&[]),
        Some(&http),
    )
    .unwrap_err();
    assert!(err.contains("OR"));
}

#[test]
fn missing_amount_rejected() {
    let http = MockHttpGet {
        body: json!({}),
    };
    assert!(execute_charge(
        &ChargeArgs {
            amount_brl: None,
            amount_usdc: None,
            recipient: None,
            invoice_id: "1".into(),
            memo_extra: None,
            message: None,
            mint: None,
            reference: None,
        },
        &cfg_map(&[]),
        Some(&http),
    )
    .is_err());
}

#[test]
fn max_usdc_enforced() {
    let http = MockHttpGet {
        body: json!({}),
    };
    let err = execute_charge(
        &ChargeArgs {
            amount_brl: None,
            amount_usdc: Some("50".into()),
            recipient: None,
            invoice_id: "1".into(),
            memo_extra: None,
            message: None,
            mint: None,
            reference: None,
        },
        &cfg_map(&[("max_usdc", "10")]),
        Some(&http),
    )
    .unwrap_err();
    assert!(err.contains("max_usdc"));
}

#[test]
fn empty_allowlist_rejected() {
    let mut m = HashMap::new();
    m.insert("allowed_mints".into(), ",".into());
    assert!(ChargeConfig::from_section(&m).is_err());
}

#[test]
fn mnemonic_in_message_rejected() {
    let http = MockHttpGet {
        body: json!({}),
    };
    let err = execute_charge(
        &ChargeArgs {
            amount_brl: None,
            amount_usdc: Some("1".into()),
            recipient: None,
            invoice_id: "1".into(),
            memo_extra: None,
            message: Some("seed phrase abandon art".into()),
            mint: None,
            reference: None,
        },
        &cfg_map(&[]),
        Some(&http),
    )
    .unwrap_err();
    assert!(err.contains("injection") || err.contains("secret"));
}
