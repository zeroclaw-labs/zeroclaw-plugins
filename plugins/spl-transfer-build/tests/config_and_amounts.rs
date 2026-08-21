mod common;

use std::collections::HashMap;

use serde_json::json;
use spl_transfer_build::transfer::{execute_component_input, TransferConfig, TransferOutput};

use common::{host_inject, valid_args, valid_config, MockTransport, MINT, OTHER_MINT, RECIPIENT};

#[test]
fn required_security_configuration_fails_closed() {
    let baseline = valid_config();
    for key in ["rpc_url", "sender_pubkey", "mint_allowlist", "max_amounts"] {
        let mut config = baseline.clone();
        config.remove(key);
        assert!(
            TransferConfig::from_section(&config).is_err(),
            "missing {key}"
        );
    }

    let mut empty = baseline.clone();
    empty.insert("mint_allowlist".to_string(), String::new());
    assert!(TransferConfig::from_section(&empty).is_err());

    let mut missing_cap = baseline.clone();
    missing_cap.insert("max_amounts".to_string(), format!("{OTHER_MINT}=1"));
    assert!(TransferConfig::from_section(&missing_cap).is_err());

    assert!(TransferConfig::from_section(&HashMap::new()).is_err());
}

#[test]
fn malformed_duplicate_and_insecure_configuration_is_rejected() {
    let baseline = valid_config();
    let mutations = [
        ("rpc_url", "http://rpc.example.invalid".to_string()),
        (
            "rpc_url",
            "https://user:secret@rpc.example.invalid".to_string(),
        ),
        ("mint_allowlist", format!("{MINT},{MINT}")),
        ("mint_allowlist", format!("{MINT},")),
        ("max_amounts", format!("{MINT}=1,{MINT}=2")),
        ("max_amounts", format!("{MINT}=1e3")),
        ("mint_aliases", format!("usdc={MINT},USDC={MINT}")),
        ("recipient_allowlist", format!("{RECIPIENT},{RECIPIENT}")),
        ("allow_token_2022", "yes".to_string()),
    ];
    for (key, value) in mutations {
        let mut config = baseline.clone();
        config.insert(key.to_string(), value);
        assert!(TransferConfig::from_section(&config).is_err(), "key {key}");
    }

    let mut unknown = baseline;
    unknown.insert("daily_cap".to_string(), "1".to_string());
    assert!(TransferConfig::from_section(&unknown).is_err());
}

#[test]
fn off_curve_recipients_require_explicit_operator_opt_in() {
    let sender = common::pubkey(common::SENDER);
    let pda_seed_mint = common::pubkey(OTHER_MINT);
    let off_curve = nanosol::pubkey::derive_associated_token_address(
        &sender,
        &pda_seed_mint,
        &nanosol::pubkey::LEGACY_TOKEN_PROGRAM_ID,
    )
    .expect("PDA fixture")
    .0;
    assert!(!off_curve.is_on_curve());

    let mut args = valid_args();
    args["recipient"] = json!(off_curve.to_string());
    let mut config = valid_config();
    config.insert("recipient_allowlist".to_string(), off_curve.to_string());
    let refused = execute_component_input(
        &host_inject(args.clone(), &config),
        &MockTransport::valid(6),
    );
    assert!(!refused.success);
    assert!(refused
        .error
        .as_deref()
        .is_some_and(|error| error.contains("off-curve")));

    config.insert("allow_off_curve_recipients".to_string(), "true".to_string());
    let accepted = execute_component_input(&host_inject(args, &config), &MockTransport::valid(6));
    assert!(accepted.success, "{:?}", accepted.error);
}

#[test]
fn exact_amounts_cover_zero_two_six_and_nine_decimals_without_floats() {
    let cases = [
        (0, "1", "1"),
        (2, "0.01", "0.01"),
        (6, "0.000001", "0.000001"),
        (9, "1.230000000", "1.23"),
    ];
    for (decimals, amount, canonical) in cases {
        let mut args = valid_args();
        args["amount"] = json!(amount);
        args.as_object_mut().expect("object").remove("memo");
        args.as_object_mut().expect("object").remove("invoice_id");
        let transport = MockTransport::valid(decimals);
        let result = execute_component_input(&host_inject(args, &valid_config()), &transport);
        assert!(result.success, "{decimals}: {:?}", result.error);
        let output: TransferOutput = serde_json::from_str(&result.output).expect("output");
        assert!(output.summary.starts_with(&format!("SEND {canonical} ")));
        assert_eq!(transport.methods().len(), 3);
    }
}

#[test]
fn maximum_one_raw_unit_and_just_above_cap_are_exact() {
    let mut config = valid_config();
    config.insert("max_amounts".to_string(), format!("{MINT}=25.01"));
    let accepted = execute_component_input(
        &host_inject(valid_args(), &config),
        &MockTransport::valid(6),
    );
    assert!(accepted.success, "{:?}", accepted.error);

    let mut above = valid_args();
    above["amount"] = json!("25.010001");
    let transport = MockTransport::valid(6);
    let refused = execute_component_input(&host_inject(above, &config), &transport);
    assert!(!refused.success);
    assert_eq!(
        refused.error.as_deref(),
        Some("amount exceeds the operator-configured maximum")
    );
    assert_eq!(transport.methods(), vec!["getAccountInfo"]);
}

#[test]
fn invalid_amount_forms_refuse_deterministically() {
    for amount in [
        "0",
        "0.000000",
        "1.0000001",
        "18446744073709551616",
        "1e2",
        "+1",
        "-1",
        " 1",
        "1 ",
        ".1",
        "1.",
        "NaN",
    ] {
        let mut args = valid_args();
        args["amount"] = json!(amount);
        let result = execute_component_input(
            &host_inject(args, &valid_config()),
            &MockTransport::valid(6),
        );
        assert!(!result.success, "accepted {amount}");
        assert!(result.output.is_empty());
    }
}
