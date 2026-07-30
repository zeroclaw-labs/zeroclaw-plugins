//! Adversarial fixtures. Each one is a transaction that a naive confirmer would
//! accept, or that an attacker would like accepted, and each must fail closed.

mod common;

use std::collections::HashMap;

use common::{
    fixture_reference, host_inject, mint_result, output, pubkey, signature_entry,
    token_2022_mint_result, token_balance, valid_args, valid_config, MockRpc, SettledTransfer,
    DECIMALS, MINT, OTHER_MINT, OTHER_RECIPIENT, RAW_AMOUNT, RECIPIENT, RPC_URL, RPC_URL_SECONDARY,
    SLOT,
};
use nanosol::{instruction::TokenProgram, pubkey::Pubkey};
use serde_json::{json, Value};
use solana_pay_confirm::{confirm::execute_component_input, rpc::TransportError};

fn verdict(mock: &MockRpc, config: &HashMap<String, String>) -> Value {
    output(&execute_component_input(
        &host_inject(valid_args(), config),
        mock,
    ))
}

/// Assert a candidate transaction does not confirm the invoice, and that the
/// stated reason is the expected one.
fn assert_not_paid(mock: &MockRpc, expected_reason: &str) {
    let value = verdict(mock, &valid_config());
    assert_eq!(
        value["paid"], false,
        "a hostile candidate was accepted: {value}"
    );
    assert_eq!(value["match_count"], 0);
    assert_eq!(value.get("signature"), None);
    let reason = value["reason"].as_str().expect("reason");
    assert!(
        reason.contains(expected_reason),
        "expected reason containing {expected_reason:?}, got {reason:?}"
    );
}

fn mock_for(settled: &SettledTransfer) -> MockRpc {
    MockRpc::paid(settled)
}

#[test]
fn a_transfer_of_a_different_mint_to_the_same_account_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    let honest_destination = settled.destination();
    settled.mint = pubkey(OTHER_MINT);
    // Keep the destination the invoice expects, so only the mint differs.
    settled.destination_override = Some(honest_destination);
    assert_not_paid(&mock_for(&settled), "moves a different mint");
}

#[test]
fn a_transfer_to_a_different_recipient_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.recipient = pubkey(OTHER_RECIPIENT);
    assert_not_paid(
        &mock_for(&settled),
        "pays a different associated token account",
    );
}

#[test]
fn an_amount_short_by_one_base_unit_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.amount = RAW_AMOUNT - 1;
    let mut mock = MockRpc::paid_with(&settled, RAW_AMOUNT - 1, "finalized");
    mock.mint = Some(mint_result(DECIMALS));
    assert_not_paid(&mock, "amount differs from the invoice");
}

#[test]
fn an_amount_over_by_one_base_unit_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.amount = RAW_AMOUNT + 1;
    assert_not_paid(
        &MockRpc::paid_with(&settled, RAW_AMOUNT + 1, "finalized"),
        "amount differs from the invoice",
    );
}

#[test]
fn a_transfer_asserting_the_wrong_decimals_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    // The instruction claims 9 decimals; the mint account says 6.
    settled.decimals = 9;
    assert_not_paid(
        &mock_for(&settled),
        "asserts decimals the mint does not have",
    );
}

#[test]
fn a_reference_that_is_not_in_the_transfer_instruction_is_refused() {
    let reference = fixture_reference();
    let mut settled = SettledTransfer::paying(reference);
    // Present in the transaction, attached to an unrelated instruction. This is
    // the case a "reference appears somewhere in the transaction" check accepts.
    settled.reference_in_transfer = None;
    settled.reference_elsewhere = Some(reference);
    assert_not_paid(
        &mock_for(&settled),
        "not a read-only account of the transfer instruction",
    );
}

#[test]
fn a_reference_attached_with_write_privileges_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.reference_writable = true;
    assert_not_paid(
        &mock_for(&settled),
        "not a read-only account of the transfer instruction",
    );
}

#[test]
fn a_transaction_with_no_reference_at_all_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.reference_in_transfer = None;
    assert_not_paid(
        &mock_for(&settled),
        "not a read-only account of the transfer instruction",
    );
}

#[test]
fn a_failed_transaction_never_confirms_an_invoice() {
    let settled = SettledTransfer::paying(fixture_reference());

    // Reported as failed in the signature list: rejected without a second read.
    let mut listed_failure = MockRpc::paid(&settled);
    listed_failure.signatures = json!([signature_entry(
        &settled.signature(),
        "finalized",
        SLOT,
        true
    )]);
    assert_not_paid(&listed_failure, "failed on chain");
    assert!(!listed_failure
        .methods()
        .contains(&"getTransaction".to_string()));

    // Reported as failed only in the transaction metadata.
    let mut metadata_failure = MockRpc::paid(&settled);
    metadata_failure.transactions.insert(
        settled.signature().to_string(),
        settled.result_with_balances(
            json!([]),
            json!([token_balance(
                settled.destination_index(),
                pubkey(MINT),
                pubkey(RECIPIENT),
                RAW_AMOUNT,
                DECIMALS,
                TokenProgram::Legacy.id()
            )]),
            json!({"InstructionError": [1, "Custom"]}),
        ),
    );
    assert_not_paid(&metadata_failure, "failed on chain");
}

#[test]
fn a_candidate_below_the_required_commitment_never_confirms() {
    let settled = SettledTransfer::paying(fixture_reference());
    for status in ["processed", "confirmed"] {
        let mock = MockRpc::paid_with(&settled, RAW_AMOUNT, status);
        assert_not_paid(&mock, "has not reached the required commitment level");
        assert!(
            !mock.methods().contains(&"getTransaction".to_string()),
            "a candidate below commitment must not cost a transaction read"
        );
    }

    // A missing status is unknown, not "good enough".
    let mut unknown = MockRpc::paid(&settled);
    unknown.signatures = json!([{
        "signature": settled.signature().to_string(),
        "slot": SLOT,
        "err": Value::Null
    }]);
    assert_not_paid(&unknown, "has not reached the required commitment level");
}

#[test]
fn a_token_2022_fee_shortfall_is_refused_even_though_the_instruction_amount_is_right() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.token_program = TokenProgram::Token2022;
    // The instruction transfers exactly what the invoice asked for...
    assert_eq!(settled.amount, RAW_AMOUNT);
    // ...but a transfer fee means less arrives. A bytes-only confirmer that
    // trusted the instruction amount would report this invoice as paid.
    let mut mock = MockRpc::paid_with(&settled, RAW_AMOUNT - 7_500, "finalized");
    mock.mint = Some(token_2022_mint_result(DECIMALS, &[]));

    let mut config = valid_config();
    config.insert("allow_token_2022".to_string(), "true".to_string());
    let value = verdict(&mock, &config);
    assert_eq!(
        value["paid"], false,
        "a fee shortfall was accepted: {value}"
    );
    let reason = value["reason"].as_str().expect("reason");
    assert!(
        reason.contains("amount received differs from the amount requested"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn a_balance_delta_larger_than_the_invoice_is_refused() {
    let settled = SettledTransfer::paying(fixture_reference());
    assert_not_paid(
        &MockRpc::paid_with(&settled, RAW_AMOUNT + 1, "finalized"),
        "amount received differs from the amount requested",
    );
}

#[test]
fn an_existing_destination_account_confirms_on_its_increase_not_its_total() {
    let settled = SettledTransfer::paying(fixture_reference());
    let index = settled.destination_index();
    let balance = |raw| {
        json!([token_balance(
            index,
            pubkey(MINT),
            pubkey(RECIPIENT),
            raw,
            DECIMALS,
            TokenProgram::Legacy.id()
        )])
    };
    let mut mock = MockRpc::paid(&settled);
    mock.transactions.insert(
        settled.signature().to_string(),
        settled.result_with_balances(
            balance(10_000_000),
            balance(10_000_000 + RAW_AMOUNT),
            Value::Null,
        ),
    );
    let value = verdict(&mock, &valid_config());
    assert_eq!(value["paid"], true, "{value}");
    assert_eq!(value["received_raw"], RAW_AMOUNT.to_string());

    // A total that happens to equal the invoice amount, with no increase, is not
    // a payment.
    let mut mock = MockRpc::paid(&settled);
    mock.transactions.insert(
        settled.signature().to_string(),
        settled.result_with_balances(balance(RAW_AMOUNT), balance(RAW_AMOUNT), Value::Null),
    );
    assert_not_paid(&mock, "destination balance did not increase");
}

#[test]
fn a_missing_or_mismatched_balance_record_is_refused() {
    let settled = SettledTransfer::paying(fixture_reference());
    let index = settled.destination_index();

    let mut missing = MockRpc::paid(&settled);
    missing.transactions.insert(
        settled.signature().to_string(),
        settled.result_with_balances(json!([]), json!([]), Value::Null),
    );
    assert_not_paid(&missing, "no post-transfer balance for the destination");

    // A balance record for the right account but the wrong mint.
    let mut wrong_mint = MockRpc::paid(&settled);
    wrong_mint.transactions.insert(
        settled.signature().to_string(),
        settled.result_with_balances(
            json!([]),
            json!([token_balance(
                index,
                pubkey(OTHER_MINT),
                pubkey(RECIPIENT),
                RAW_AMOUNT,
                DECIMALS,
                TokenProgram::Legacy.id()
            )]),
            Value::Null,
        ),
    );
    assert_not_paid(&wrong_mint, "moves a different mint");

    // A balance record whose owner is not the invoice recipient.
    let mut wrong_owner = MockRpc::paid(&settled);
    wrong_owner.transactions.insert(
        settled.signature().to_string(),
        settled.result_with_balances(
            json!([]),
            json!([token_balance(
                index,
                pubkey(MINT),
                pubkey(OTHER_RECIPIENT),
                RAW_AMOUNT,
                DECIMALS,
                TokenProgram::Legacy.id()
            )]),
            Value::Null,
        ),
    );
    assert_not_paid(&wrong_owner, "pays a different associated token account");

    // A balance for a different account index does not stand in for the
    // destination's.
    let mut wrong_index = MockRpc::paid(&settled);
    wrong_index.transactions.insert(
        settled.signature().to_string(),
        settled.result_with_balances(
            json!([]),
            json!([token_balance(
                index + 1,
                pubkey(MINT),
                pubkey(RECIPIENT),
                RAW_AMOUNT,
                DECIMALS,
                TokenProgram::Legacy.id()
            )]),
            Value::Null,
        ),
    );
    assert_not_paid(&wrong_index, "no post-transfer balance for the destination");
}

#[test]
fn more_than_one_transfer_instruction_is_refused() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.second_transfer = true;
    assert_not_paid(
        &MockRpc::paid_with(&settled, RAW_AMOUNT * 2, "finalized"),
        "more than one token transfer instruction",
    );
}

#[test]
fn a_transaction_with_no_transfer_at_all_is_refused() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mut mock = MockRpc::paid(&settled);
    // A record whose bytes are not a transaction at all.
    mock.transactions.insert(
        settled.signature().to_string(),
        json!({
            "slot": SLOT,
            "transaction": ["AQID", "base64"],
            "meta": {"err": Value::Null, "preTokenBalances": [], "postTokenBalances": []}
        }),
    );
    assert_not_paid(&mock, "outside the supported message subset");
}

#[test]
fn inconsistent_slots_for_one_signature_are_refused() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mut mock = MockRpc::paid(&settled);
    if let Some(record) = mock.transactions.get_mut(&settled.signature().to_string()) {
        record["slot"] = json!(SLOT + 1);
    }
    assert_not_paid(&mock, "inconsistent slots");
}

#[test]
fn a_second_endpoint_that_disagrees_makes_the_call_refuse() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mut config = valid_config();
    config.insert(
        "rpc_url_secondary".to_string(),
        RPC_URL_SECONDARY.to_string(),
    );

    // Agreement: both endpoints are read, and the verdict stands.
    let agreeing = MockRpc::paid(&settled).with_secondary(HashMap::from([(
        settled.signature().to_string(),
        settled.result(RAW_AMOUNT),
    )]));
    let value = verdict(&agreeing, &config);
    assert_eq!(value["paid"], true);
    let endpoints = agreeing.endpoints();
    assert!(endpoints.iter().any(|endpoint| endpoint == RPC_URL));
    assert!(endpoints
        .iter()
        .any(|endpoint| endpoint == RPC_URL_SECONDARY));

    // Disagreement about the amount received: refuse rather than pick a winner.
    let mut lying = SettledTransfer::paying(fixture_reference());
    lying.amount = RAW_AMOUNT * 10;
    let disagreeing = MockRpc::paid(&settled).with_secondary(HashMap::from([(
        settled.signature().to_string(),
        lying.result(RAW_AMOUNT * 10),
    )]));
    let response = execute_component_input(&host_inject(valid_args(), &config), &disagreeing);
    assert!(!response.success, "endpoint disagreement was tolerated");
    assert_eq!(response.category, Some("endpoint_disagreement"));

    // A signature the second endpoint has never seen is also disagreement: one
    // of the two is either lying or lagging, and neither is a basis to confirm.
    let silent = MockRpc::paid(&settled).with_secondary(HashMap::new());
    let response = execute_component_input(&host_inject(valid_args(), &config), &silent);
    assert!(!response.success);
    assert_eq!(response.category, Some("endpoint_disagreement"));
}

#[test]
fn transport_and_endpoint_faults_are_refusals_not_verdicts() {
    let settled = SettledTransfer::paying(fixture_reference());
    for error in [
        TransportError::Unavailable,
        TransportError::HttpStatus(503),
        TransportError::ResponseTooLarge,
        TransportError::InvalidUtf8,
    ] {
        let mut mock = MockRpc::paid(&settled);
        mock.transport_error = Some(error.clone());
        let response = execute_component_input(&host_inject(valid_args(), &valid_config()), &mock);
        assert!(
            !response.success,
            "a transport fault must never become a paid or unpaid verdict"
        );
        assert_eq!(response.category, Some("rpc_failure"));
    }

    // A malformed envelope is a refusal, and no endpoint prose reaches output.
    let mut malformed = MockRpc::paid(&settled);
    malformed.raw_override = Some(
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32011, "message": "internal detail"}})
            .to_string(),
    );
    let response = execute_component_input(&host_inject(valid_args(), &valid_config()), &malformed);
    assert!(!response.success);
    let error = response.error.expect("error");
    assert!(
        !error.contains("internal detail"),
        "endpoint prose leaked: {error}"
    );
}

#[test]
fn a_mint_the_endpoint_cannot_produce_is_a_refusal() {
    let settled = SettledTransfer::paying(fixture_reference());
    let mut mock = MockRpc::paid(&settled);
    mock.mint = None; // getAccountInfo returns a null value
    let response = execute_component_input(&host_inject(valid_args(), &valid_config()), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("rpc_failure"));
}

#[test]
fn an_extension_bearing_token_2022_mint_is_refused_even_when_token_2022_is_enabled() {
    let mut settled = SettledTransfer::paying(fixture_reference());
    settled.token_program = TokenProgram::Token2022;
    let mut mock = MockRpc::paid(&settled);
    // TransferFeeConfig: the extension that makes received differ from sent.
    mock.mint = Some(token_2022_mint_result(DECIMALS, &[(1, 108)]));

    let mut config = valid_config();
    config.insert("allow_token_2022".to_string(), "true".to_string());
    let response = execute_component_input(&host_inject(valid_args(), &config), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("token_2022_policy"));
}

#[test]
fn a_spam_transaction_on_the_reference_does_not_hide_the_real_payment() {
    // Anyone can attach a reference key to their own transaction. Scanning every
    // candidate rather than only the newest is what keeps that from hiding a
    // real payment inside the window.
    let reference = fixture_reference();
    let real = SettledTransfer::paying(reference);
    let mut spam = SettledTransfer::paying(reference);
    spam.signature_byte = 0x33;
    spam.amount = 1;
    spam.recipient = pubkey(OTHER_RECIPIENT);

    let mock = MockRpc {
        mint: Some(mint_result(DECIMALS)),
        signatures: json!([
            signature_entry(&spam.signature(), "finalized", SLOT, false),
            signature_entry(&real.signature(), "finalized", SLOT, false)
        ]),
        transactions: HashMap::from([
            (spam.signature().to_string(), spam.result(1)),
            (real.signature().to_string(), real.result(RAW_AMOUNT)),
        ]),
        ..MockRpc::default()
    };
    let value = verdict(&mock, &valid_config());
    assert_eq!(value["paid"], true, "{value}");
    assert_eq!(value["match_count"], 1);
    assert_eq!(value["signature"], real.signature().to_string());
}

#[test]
fn a_wrong_invoice_derives_a_different_reference_and_finds_nothing() {
    // The same settled payment, queried with a different amount: the derived
    // reference changes, so the scan looks somewhere else entirely. This is why
    // the tool cannot be talked into confirming terms that were never requested.
    let settled = SettledTransfer::paying(fixture_reference());
    let mock = MockRpc::paid(&settled);
    let mut args = valid_args();
    args["amount"] = json!("1.4");

    let value = output(&execute_component_input(
        &host_inject(args, &valid_config()),
        &mock,
    ));
    assert_eq!(value["paid"], false);
    assert_ne!(value["reference"], fixture_reference().to_string());
    let scanned: Pubkey = mock.call_bodies("getSignaturesForAddress")[0]["params"][0]
        .as_str()
        .expect("scanned reference")
        .parse()
        .expect("reference public key");
    assert_ne!(scanned, fixture_reference());
}
