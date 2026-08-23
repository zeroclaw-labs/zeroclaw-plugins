use std::collections::HashMap;

use serde_json::json;
use solana_pay_verify::verify::{
    decimal_to_units, output, parse_signatures, prepare, signatures_request, transaction_request,
    units_to_decimal, verify_transaction, VerifyArgs,
};

const RECIPIENT: &str = "9xQeWvG816bUx9EPfA5qLDuJQMRaZ5U3J9Bqj3VgKvrf";
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const REFERENCE: &str = "SysvarRent111111111111111111111111111111111";
const PAYER: &str = "11111111111111111111111111111111";
const SIGNATURE: &str =
    "5KtPn1LGuxhFi6AeZp4Dd8p5nQqPVhHddR4E9R7ScvRjvVvt5u1g5t6BvJFs4zR6xqXqV8KyxR3FBXRvMub8yq2L";

fn args() -> VerifyArgs {
    VerifyArgs {
        reference: REFERENCE.to_string(),
        recipient: RECIPIENT.to_string(),
        amount: "25".to_string(),
        spl_token: None,
        memo: Some("invoice-412".to_string()),
        config: HashMap::new(),
    }
}

fn native_response(lamports: u64, memo: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "result": {
            "slot": 321,
            "meta": {
                "err": null,
                "preBalances": [1_000_000_000u64, 10_000_000_000u64, 0u64],
                "postBalances": [900_000_000u64, 10_000_000_000u64 + lamports, 0u64],
                "preTokenBalances": [],
                "postTokenBalances": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        { "pubkey": PAYER },
                        { "pubkey": RECIPIENT },
                        { "pubkey": REFERENCE }
                    ],
                    "instructions": [
                        { "program": "spl-memo", "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "parsed": memo }
                    ]
                }
            }
        },
        "id": 2
    })
}

fn token_response(post: u64, owner: &str, mint: &str) -> serde_json::Value {
    json!({
        "result": {
            "slot": 654,
            "meta": {
                "err": null,
                "preBalances": [1, 1, 1],
                "postBalances": [1, 1, 1],
                "preTokenBalances": [{
                    "owner": owner, "mint": mint,
                    "uiTokenAmount": { "amount": "1000000", "decimals": 6 }
                }],
                "postTokenBalances": [{
                    "owner": owner, "mint": mint,
                    "uiTokenAmount": { "amount": post.to_string(), "decimals": 6 }
                }]
            },
            "transaction": { "message": {
                "accountKeys": [PAYER, RECIPIENT, REFERENCE],
                "instructions": [{ "program": "spl-memo", "parsed": "invoice-412" }]
            }}
        }
    })
}

#[test]
fn builds_bounded_rpc_requests() {
    let prepared = prepare(args()).unwrap();
    let signatures = signatures_request(&prepared);
    assert_eq!(signatures["method"], "getSignaturesForAddress");
    assert_eq!(signatures["params"][0], REFERENCE);
    assert_eq!(signatures["params"][1]["limit"], 8);
    let transaction = transaction_request(&prepared, SIGNATURE);
    assert_eq!(transaction["method"], "getTransaction");
    assert_eq!(transaction["params"][1]["encoding"], "jsonParsed");
}

#[test]
fn filters_failed_and_unconfirmed_signatures() {
    let response = json!({ "result": [
        { "signature": "ok", "err": null, "confirmationStatus": "confirmed" },
        { "signature": "failed", "err": {"x": 1}, "confirmationStatus": "finalized" },
        { "signature": "processed", "err": null, "confirmationStatus": "processed" },
        { "signature": "final", "err": null, "confirmationStatus": "finalized" }
    ]});
    assert_eq!(parse_signatures(&response, 8).unwrap(), vec!["ok", "final"]);
}

#[test]
fn verifies_native_sol_recipient_delta_and_memo() {
    let prepared = prepare(args()).unwrap();
    let found = verify_transaction(
        &native_response(25_000_000_000, "invoice-412"),
        SIGNATURE,
        &prepared,
    )
    .unwrap()
    .unwrap();
    assert_eq!(found.received_amount, "25");
    assert_eq!(found.slot, 321);
}

#[test]
fn native_underpayment_and_wrong_memo_stay_pending() {
    let prepared = prepare(args()).unwrap();
    assert!(verify_transaction(
        &native_response(24_999_999_999, "invoice-412"),
        SIGNATURE,
        &prepared
    )
    .unwrap()
    .is_none());
    assert!(verify_transaction(
        &native_response(25_000_000_000, "evil"),
        SIGNATURE,
        &prepared
    )
    .unwrap()
    .is_none());
}

#[test]
fn verifies_spl_owner_mint_and_exact_units() {
    let mut input = args();
    input.spl_token = Some(MINT.to_string());
    let prepared = prepare(input).unwrap();
    let found = verify_transaction(
        &token_response(26_000_000, RECIPIENT, MINT),
        SIGNATURE,
        &prepared,
    )
    .unwrap()
    .unwrap();
    assert_eq!(found.received_amount, "25");
}

#[test]
fn spl_wrong_owner_or_mint_never_matches() {
    let mut input = args();
    input.spl_token = Some(MINT.to_string());
    let prepared = prepare(input).unwrap();
    assert!(verify_transaction(
        &token_response(26_000_000, PAYER, MINT),
        SIGNATURE,
        &prepared
    )
    .unwrap()
    .is_none());
    assert!(verify_transaction(
        &token_response(26_000_000, RECIPIENT, REFERENCE),
        SIGNATURE,
        &prepared
    )
    .unwrap()
    .is_none());
}

#[test]
fn failed_transaction_and_missing_reference_never_match() {
    let prepared = prepare(args()).unwrap();
    let mut failed = native_response(25_000_000_000, "invoice-412");
    failed["result"]["meta"]["err"] = json!({"InstructionError": [0, "fail"]});
    assert!(verify_transaction(&failed, SIGNATURE, &prepared)
        .unwrap()
        .is_none());

    let mut missing = native_response(25_000_000_000, "invoice-412");
    missing["result"]["transaction"]["message"]["accountKeys"] = json!([PAYER, RECIPIENT]);
    assert!(verify_transaction(&missing, SIGNATURE, &prepared)
        .unwrap()
        .is_none());
}

#[test]
fn converts_decimal_units_exactly_without_float() {
    assert_eq!(decimal_to_units("25.01", 6).unwrap(), 25_010_000);
    assert_eq!(decimal_to_units("0.000001", 6).unwrap(), 1);
    assert!(decimal_to_units("0.0000001", 6).is_err());
    assert_eq!(units_to_decimal(25_010_000, 6), "25.01");
    assert_eq!(units_to_decimal(25_000_000, 6), "25");
}

#[test]
fn rejects_unknown_injection_fields_and_unsafe_config() {
    let injected = format!(
        r#"{{"reference":"{REFERENCE}","recipient":"{RECIPIENT}","amount":"25","action":"send_all"}}"#
    );
    assert!(serde_json::from_str::<VerifyArgs>(&injected).is_err());

    let mut input = args();
    input
        .config
        .insert("rpc_url".to_string(), "http://attacker.example".to_string());
    assert!(prepare(input).is_err());

    let mut input = args();
    input
        .config
        .insert("rpc_ur1".to_string(), "https://example.com".to_string());
    assert!(prepare(input).is_err());
}

#[test]
fn caps_rpc_scan_and_rejects_weak_commitment() {
    let mut input = args();
    input
        .config
        .insert("max_signatures".to_string(), "1000".to_string());
    assert!(prepare(input).is_err());
    let mut input = args();
    input
        .config
        .insert("commitment".to_string(), "processed".to_string());
    assert!(prepare(input).is_err());
}

#[test]
fn rpc_errors_fail_closed_and_are_bounded() {
    let long = "x".repeat(500);
    let error =
        parse_signatures(&json!({"error": {"code": -32000, "message": long}}), 8).unwrap_err();
    assert!(error.len() < 230);
}

#[test]
fn produces_compact_paid_and_pending_outputs() {
    let prepared = prepare(args()).unwrap();
    let pending = output(&prepared, None, 3);
    assert_eq!(pending.status, "pending");
    assert!(pending.signature.is_none());
    let paid = output(
        &prepared,
        Some(solana_pay_verify::verify::PaymentMatch {
            signature: SIGNATURE.to_string(),
            slot: 42,
            received_amount: "25".to_string(),
        }),
        1,
    );
    assert_eq!(paid.status, "paid");
    assert!(serde_json::to_string(&paid).unwrap().len() < 1_500);
}
