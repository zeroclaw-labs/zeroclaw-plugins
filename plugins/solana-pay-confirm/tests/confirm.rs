//! The verdict paths: what a confirmed payment reports, what an unpaid invoice
//! reports, and the wire shapes that must both verify.

mod common;

use std::collections::HashMap;

use common::{
    fixture_reference, host_inject, output, pubkey, signature, signature_entry,
    token_2022_mint_result, token_balance, valid_args, valid_config, MockRpc, SettledTransfer,
    AMOUNT, DECIMALS, INVOICE, MINT, RAW_AMOUNT, RECIPIENT, RPC_URL, SLOT,
};
use nanosol::{
    instruction::TokenProgram,
    message::MessageVersion,
    rpc::{MAX_RPC_RESPONSE_BYTES, MAX_TRANSACTION_RESPONSE_BYTES},
};
use serde_json::{json, Value};
use solana_pay_confirm::confirm::{
    execute_component_input, MAX_SIGNATURES_SCANNED, MAX_TOOL_OUTPUT_BYTES,
};

/// The happy-path output budget. Well under the 4000-byte hard ceiling and
/// close to the ~200-token target the whole submission holds itself to.
const OUTPUT_BUDGET_BYTES: usize = 1_200;

fn run(mock: &MockRpc, config: &HashMap<String, String>) -> Value {
    let response = execute_component_input(&host_inject(valid_args(), config), mock);
    output(&response)
}

#[test]
fn confirmed_payment_reports_verified_fields_within_the_output_budget() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mock = MockRpc::paid(&settled);
    let response = execute_component_input(&host_inject(valid_args(), &valid_config()), &mock);
    let value = output(&response);

    assert_eq!(value["paid"], true);
    assert_eq!(value["signature"], settled.signature().to_string());
    assert_eq!(value["slot"], SLOT);
    assert_eq!(value["confirmation_status"], "finalized");
    assert_eq!(value["mint"], MINT);
    assert_eq!(value["recipient"], RECIPIENT);
    assert_eq!(value["reference"], fixture_reference().to_string());
    assert_eq!(value["expected_raw"], RAW_AMOUNT.to_string());
    assert_eq!(value["received_raw"], RAW_AMOUNT.to_string());
    assert_eq!(value["received_ui"], AMOUNT);
    assert_eq!(value["match_count"], 1);
    assert_eq!(value.get("reason"), None);

    let summary = value["summary"].as_str().expect("summary");
    // The alias is shown with the mint it resolved to, so a misleading alias
    // cannot stand in for the asset that was actually received.
    assert!(
        summary.starts_with("CONFIRMED 1.5 USDC (EPjF…Dt1v) received by "),
        "unexpected summary: {summary}"
    );
    assert!(summary.contains("finalized"));
    assert!(summary.contains(&settled.signature().to_string()));
    assert!(summary.contains("invoice '412'"));
    assert!(!summary.contains("WARNING"));

    assert!(
        response.output.len() < OUTPUT_BUDGET_BYTES,
        "output is {} bytes, above the {OUTPUT_BUDGET_BYTES}-byte budget",
        response.output.len()
    );
    assert!(response.output.len() < MAX_TOOL_OUTPUT_BYTES);

    // Exactly three reads: the mint, the reference scan, one candidate.
    assert_eq!(
        mock.methods(),
        vec![
            "getAccountInfo".to_string(),
            "getSignaturesForAddress".to_string(),
            "getTransaction".to_string()
        ]
    );
    assert!(mock.endpoints().iter().all(|endpoint| endpoint == RPC_URL));
}

#[test]
fn the_same_call_returns_the_same_verdict_every_time() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mock = MockRpc::paid(&settled);
    let input = host_inject(valid_args(), &valid_config());

    let first = execute_component_input(&input, &mock);
    let second = execute_component_input(&input, &mock);
    // No cursor, no stored state: the reference is a pure function of the
    // invoice, so the verdict is byte-identical on every run.
    assert_eq!(first, second);
    assert_eq!(output(&first)["paid"], true);
}

#[test]
fn legacy_messages_and_plain_transfers_both_confirm() {
    for (version, checked) in [
        (MessageVersion::Legacy, true),
        (MessageVersion::V0, false),
        (MessageVersion::Legacy, false),
    ] {
        let mut settled = SettledTransfer::paying(fixture_reference());
        settled.version = version;
        settled.checked = checked;
        let value = run(&MockRpc::paid(&settled), &valid_config());
        assert_eq!(
            value["paid"], true,
            "version {version:?} checked {checked} did not confirm: {value}"
        );
        assert_eq!(value["received_raw"], RAW_AMOUNT.to_string());
    }
}

#[test]
fn an_unpaid_invoice_is_a_successful_verdict_rather_than_a_refusal() {
    let response = execute_component_input(
        &host_inject(valid_args(), &valid_config()),
        &MockRpc::unpaid(),
    );
    let value = output(&response);

    assert_eq!(value["paid"], false);
    assert_eq!(value["match_count"], 0);
    assert_eq!(value.get("signature"), None);
    assert_eq!(value.get("received_raw"), None);
    assert_eq!(value["reference"], fixture_reference().to_string());
    assert_eq!(value["expected_raw"], RAW_AMOUNT.to_string());
    let reason = value["reason"].as_str().expect("reason");
    assert!(
        reason.contains("no transaction referencing this invoice was found"),
        "unexpected reason: {reason}"
    );
    assert!(value["summary"]
        .as_str()
        .expect("summary")
        .starts_with("NOT PAID: no settled transfer of 1.5 USDC (EPjF…Dt1v)"));
}

#[test]
fn a_double_payment_is_confirmed_and_flagged_with_the_settling_transfer() {
    let reference = fixture_reference();
    let first = SettledTransfer::paying(reference);
    let mut second = SettledTransfer::paying(reference);
    second.signature_byte = 0x22;

    // The endpoint returns newest first.
    let mock = MockRpc {
        mint: Some(common::mint_result(DECIMALS)),
        signatures: json!([
            signature_entry(&second.signature(), "finalized", SLOT + 40, false),
            signature_entry(&first.signature(), "finalized", SLOT, false)
        ]),
        transactions: HashMap::from([
            (
                second.signature().to_string(),
                second.result_with_balances(
                    json!([token_balance(
                        second.destination_index(),
                        pubkey(MINT),
                        pubkey(RECIPIENT),
                        RAW_AMOUNT,
                        DECIMALS,
                        TokenProgram::Legacy.id()
                    )]),
                    json!([token_balance(
                        second.destination_index(),
                        pubkey(MINT),
                        pubkey(RECIPIENT),
                        RAW_AMOUNT * 2,
                        DECIMALS,
                        TokenProgram::Legacy.id()
                    )]),
                    Value::Null,
                ),
            ),
            (first.signature().to_string(), first.result(RAW_AMOUNT)),
        ]),
        ..MockRpc::default()
    };
    // The newest entry reports a later slot, so its record must agree.
    let mut mock = mock;
    if let Some(record) = mock.transactions.get_mut(&second.signature().to_string()) {
        record["slot"] = json!(SLOT + 40);
    }

    let value = run(&mock, &valid_config());
    assert_eq!(value["paid"], true);
    assert_eq!(value["match_count"], 2);
    // The oldest verified transfer is the one that settled the invoice, and it
    // stays the reported signature when a later duplicate arrives.
    assert_eq!(value["signature"], first.signature().to_string());
    assert_eq!(value["slot"], SLOT);
    let summary = value["summary"].as_str().expect("summary");
    assert!(
        summary.contains("WARNING 2 settled transfers match this invoice"),
        "double payment was not flagged: {summary}"
    );
}

#[test]
fn the_scan_window_and_commitment_come_from_operator_config() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mock = MockRpc::paid(&settled);
    run(&mock, &valid_config());

    let scan = mock.call_bodies("getSignaturesForAddress");
    assert_eq!(scan.len(), 1);
    assert_eq!(scan[0]["params"][0], fixture_reference().to_string());
    assert_eq!(scan[0]["params"][1]["limit"], 10);
    assert_eq!(scan[0]["params"][1]["commitment"], "finalized");

    let fetch = mock.call_bodies("getTransaction");
    assert_eq!(fetch[0]["params"][1]["encoding"], "base64");
    assert_eq!(fetch[0]["params"][1]["commitment"], "finalized");
    assert_eq!(fetch[0]["params"][1]["maxSupportedTransactionVersion"], 0);

    // A weaker commitment and a narrower window are both operator choices.
    let mut config = valid_config();
    config.insert("min_commitment".to_string(), "confirmed".to_string());
    config.insert("max_signatures_scanned".to_string(), "3".to_string());
    let settled = SettledTransfer::paying(fixture_reference());
    let mock = MockRpc::paid_with(&settled, RAW_AMOUNT, "confirmed");
    assert_eq!(run(&mock, &config)["paid"], true);
    let scan = mock.call_bodies("getSignaturesForAddress");
    assert_eq!(scan[0]["params"][1]["limit"], 3);
    assert_eq!(scan[0]["params"][1]["commitment"], "confirmed");
}

#[test]
fn every_read_is_bounded_by_a_response_ceiling() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mock = MockRpc::paid(&settled);
    run(&mock, &valid_config());

    for call in mock.calls.borrow().iter() {
        let expected = if call.method() == "getTransaction" {
            MAX_TRANSACTION_RESPONSE_BYTES
        } else {
            MAX_RPC_RESPONSE_BYTES
        };
        assert_eq!(
            call.maximum_bytes,
            expected,
            "{} was not bounded",
            call.method()
        );
    }
}

#[test]
fn an_extension_free_token_2022_payment_confirms_only_when_enabled() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.token_program = TokenProgram::Token2022;
    let mut mock = MockRpc::paid(&settled);
    mock.mint = Some(token_2022_mint_result(DECIMALS, &[]));

    // Default policy refuses Token-2022 outright.
    let response = execute_component_input(&host_inject(valid_args(), &valid_config()), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("token_2022_policy"));

    let mut config = valid_config();
    config.insert("allow_token_2022".to_string(), "true".to_string());
    let value = run(&mock, &config);
    assert_eq!(value["paid"], true);
    assert_eq!(value["received_raw"], RAW_AMOUNT.to_string());
}

#[test]
fn the_scan_window_is_bounded_by_code_not_only_by_config() {
    let reference = fixture_reference();
    let settled = SettledTransfer::paying(reference);
    let mut config = valid_config();
    config.insert(
        "max_signatures_scanned".to_string(),
        (MAX_SIGNATURES_SCANNED + 1).to_string(),
    );
    let response = execute_component_input(
        &host_inject(valid_args(), &config),
        &MockRpc::paid(&settled),
    );
    assert!(!response.success);
    assert_eq!(response.category, Some("invalid_config"));

    // At the ceiling the window is honoured exactly.
    config.insert(
        "max_signatures_scanned".to_string(),
        MAX_SIGNATURES_SCANNED.to_string(),
    );
    let mock = MockRpc::paid(&settled);
    assert_eq!(run(&mock, &config)["paid"], true);
    assert_eq!(
        mock.call_bodies("getSignaturesForAddress")[0]["params"][1]["limit"],
        MAX_SIGNATURES_SCANNED
    );
}

#[test]
fn an_invoice_that_is_not_yet_paid_still_reports_the_reference_it_derived() {
    // An operator can hand this reference to a wallet or explorer and see the
    // same thing the tool looked for, without the tool ever accepting one.
    let value = run(&MockRpc::unpaid(), &valid_config());
    let reference = value["reference"].as_str().expect("reference");
    assert_eq!(reference, fixture_reference().to_string());
    assert_ne!(reference, signature(1).to_string());
    assert!(value["summary"]
        .as_str()
        .expect("summary")
        .contains(INVOICE));
}
