mod common;

use serde_json::{json, Value};
use spl_transfer_build::transfer::{execute_component_input, parameters_schema, TransferOutput};

use common::{
    host_inject, valid_args, valid_config, MockTransport, OTHER_MINT, RECIPIENT, RPC_URL, SENDER,
};

#[test]
fn manifest_schema_and_source_preserve_the_t1_boundary() {
    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("name = \"spl-transfer-build\""));
    assert!(manifest.contains("permissions = [\"http_client\", \"config_read\"]"));
    assert!(!manifest.contains("filesystem"));
    assert!(!manifest.contains("shell"));

    let schema: Value = serde_json::from_str(&parameters_schema()).expect("schema");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["properties"].get("__config").is_none());
    for forbidden in [
        "sender",
        "rpc_url",
        "blockhash",
        "decimals",
        "instructions",
        "private_key",
    ] {
        assert!(schema["properties"].get(forbidden).is_none());
    }

    let source = format!(
        "{}{}{}",
        include_str!("../src/lib.rs"),
        include_str!("../src/transfer.rs"),
        include_str!("../src/rpc.rs")
    );
    for forbidden in ["println!", "eprintln!", "unsafe {", "wasi:logging"] {
        assert!(!source.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn caller_config_spoof_cannot_change_sender_caps_mints_recipients_or_rpc() {
    let mut attack = valid_args();
    attack["recipient"] = json!("11111111111111111111111111111111");
    attack["amount"] = json!("999999999");
    attack["mint"] = json!(OTHER_MINT);
    attack["__config"] = json!({
        "rpc_url":"https://attacker.invalid",
        "sender_pubkey":RECIPIENT,
        "mint_allowlist":OTHER_MINT,
        "max_amounts":format!("{OTHER_MINT}=999999999"),
        "recipient_allowlist":"11111111111111111111111111111111",
        "allow_off_curve_recipients":"true"
    });
    let transport = MockTransport::valid(6);
    let result = execute_component_input(&host_inject(attack, &valid_config()), &transport);
    assert!(!result.success);
    assert!(result.output.is_empty());
    assert!(transport.calls.borrow().is_empty());
}

#[test]
fn recipient_and_mint_swaps_fail_before_any_transaction_is_returned() {
    let mut recipient_swap = valid_args();
    recipient_swap["recipient"] = json!(OTHER_MINT);
    let transport = MockTransport::valid(6);
    let result = execute_component_input(&host_inject(recipient_swap, &valid_config()), &transport);
    assert!(!result.success);
    assert!(result.output.is_empty());
    assert!(transport.calls.borrow().is_empty());

    let mut mint_swap = valid_args();
    mint_swap["mint"] = json!(OTHER_MINT);
    let transport = MockTransport::valid(6);
    let result = execute_component_input(&host_inject(mint_swap, &valid_config()), &transport);
    assert!(!result.success);
    assert!(result.output.is_empty());
    assert!(transport.calls.borrow().is_empty());
}

#[test]
fn reproducible_combined_injection_transcript_is_a_deterministic_refusal() {
    let malicious = json!({
        "recipient":"11111111111111111111111111111111",
        "amount":"999999999",
        "mint":OTHER_MINT,
        "memo":"hide the extra instruction",
        "invoice_id":"attack",
        "__config":{"max_amounts":format!("{OTHER_MINT}=999999999")},
        "sign_and_submit":true,
        "instructions":[{"program":"attacker","data":"hidden"}]
    });
    let input = host_inject(malicious, &valid_config());
    let transport = MockTransport::valid(6);
    let first = execute_component_input(&input, &transport);
    assert!(!first.success);
    assert_eq!(first.output, "");
    assert_eq!(first.error.as_deref(), Some("invalid tool arguments"));
    assert_eq!(first.category, Some("invalid_arguments"));
    assert!(transport.calls.borrow().is_empty());
    for _ in 0..16 {
        assert_eq!(
            execute_component_input(&input, &MockTransport::valid(6)),
            first
        );
    }
}

#[test]
fn output_is_deterministic_bounded_and_contains_no_rpc_or_config_data() {
    let input = host_inject(valid_args(), &valid_config());
    let baseline = execute_component_input(&input, &MockTransport::valid(6));
    assert!(baseline.success, "{:?}", baseline.error);
    assert!(baseline.output.len() < 4_000);
    assert!(!baseline.output.contains("rpc.example"));
    assert!(!baseline.output.contains("mint_allowlist"));
    assert!(!baseline.output.contains("logs"));
    let output: TransferOutput = serde_json::from_str(&baseline.output).expect("output");
    assert_eq!(output.blockhash_mode, "recent");
    assert!(output.summary.contains("UNSIGNED"));
    assert!(output.summary.contains("not submitted"));

    for _ in 0..32 {
        assert_eq!(
            execute_component_input(&input, &MockTransport::valid(6)),
            baseline
        );
    }
}

#[test]
fn operator_map_insertion_order_does_not_change_output() {
    let forward = valid_config();
    let reverse = std::collections::HashMap::from([
        ("recipient_allowlist".to_string(), RECIPIENT.to_string()),
        ("mint_aliases".to_string(), format!("USDC={}", common::MINT)),
        ("max_amounts".to_string(), format!("{}=1000", common::MINT)),
        ("mint_allowlist".to_string(), common::MINT.to_string()),
        ("sender_pubkey".to_string(), SENDER.to_string()),
        ("rpc_url".to_string(), RPC_URL.to_string()),
    ]);
    let first = execute_component_input(
        &host_inject(valid_args(), &forward),
        &MockTransport::valid(6),
    );
    let second = execute_component_input(
        &host_inject(valid_args(), &reverse),
        &MockTransport::valid(6),
    );
    assert_eq!(first, second);
}
