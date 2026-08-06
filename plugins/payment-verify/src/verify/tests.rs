//! Host tests for the payment verifier. RPC is mocked; zero network.

use super::*;
use safe_hands_core::crypto::{ata_address, TOKEN_PROGRAM};
use safe_hands_core::invoice::derive_reference;
use safe_hands_core::rpc::{DownTransport, MockTransport};
use safe_hands_core::solana_pubkey::Pubkey;

fn key(seed: u8) -> Pubkey {
    Pubkey::new_from_array([seed; 32])
}

const MERCHANT: u8 = 11;
const MINT: u8 = 22;
const PAYER: u8 = 33;
const DECIMALS: u8 = 6;
const AMOUNT: u64 = 25_000_000;

fn reference() -> String {
    derive_reference(&key(MERCHANT), "ORDER-1", "salt")
        .unwrap()
        .to_string()
}

fn ata(owner: u8) -> String {
    ata_address(
        &key(owner),
        &parse_pubkey(TOKEN_PROGRAM).unwrap(),
        &key(MINT),
    )
    .to_string()
}

fn mint_account() -> Value {
    let mut data = vec![0u8; 82];
    data[44] = DECIMALS;
    data[45] = 1;
    json!({"result": {"value": {
        "owner": TOKEN_PROGRAM,
        "data": [safe_hands_core::codec::base64_encode(&data), "base64"]
    }}})
}

fn balance(index: u64, owner: &str, amount: u64) -> Value {
    json!({
        "accountIndex": index,
        "mint": key(MINT).to_string(),
        "owner": owner,
        "uiTokenAmount": {"amount": amount.to_string(), "decimals": DECIMALS}
    })
}

fn paid_tx(amount: u64) -> Value {
    let payer = key(PAYER).to_string();
    json!({"result": {
        "slot": 500,
        "blockTime": 1_700_000_000,
        "meta": {
            "err": null,
            "preTokenBalances": [balance(1, &payer, 100_000_000), balance(2, &key(MERCHANT).to_string(), 0)],
            "postTokenBalances": [
                balance(1, &payer, 100_000_000 - amount),
                balance(2, &key(MERCHANT).to_string(), amount)
            ],
            "innerInstructions": []
        },
        "transaction": {"message": {
            "header": {"numRequiredSignatures": 1},
            "accountKeys": [
                {"pubkey": payer, "signer": true, "writable": true},
                {"pubkey": ata(PAYER), "signer": false, "writable": true},
                {"pubkey": ata(MERCHANT), "signer": false, "writable": true},
                {"pubkey": reference(), "signer": false, "writable": false}
            ],
            "instructions": [{
                "program": "spl-token",
                "programId": TOKEN_PROGRAM,
                "parsed": {"type": "transferChecked", "info": {
                    "authority": payer,
                    "source": ata(PAYER),
                    "destination": ata(MERCHANT),
                    "mint": key(MINT).to_string(),
                    "tokenAmount": {"amount": amount.to_string(), "decimals": DECIMALS}
                }}
            }]
        }}
    }})
}

fn rpc(tx: Option<Value>) -> MockTransport {
    let signatures = match &tx {
        Some(_) => json!({"result": [{"signature": "SIG1", "err": null}]}),
        None => json!({"result": []}),
    };
    let mock = MockTransport::new()
        .with("getAccountInfo", mint_account())
        .with("getSignaturesForAddress", signatures);
    match tx {
        Some(tx) => mock.with("getTransaction", tx),
        None => mock,
    }
}

fn args(extra: Value) -> String {
    let mut base = json!({
        "order_id": "ORDER-1",
        "amount_raw": AMOUNT.to_string(),
        "__config": {
            "merchant_owner": key(MERCHANT).to_string(),
            "invoice_salt": "salt",
            "default_mint": key(MINT).to_string()
        }
    });
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            base.insert(k.clone(), v.clone());
        }
    }
    base.to_string()
}

fn output(out: &ExecuteOutput) -> Value {
    assert!(out.success, "expected success, got {:?}", out.error);
    serde_json::from_str(&out.output).expect("output is json")
}

#[test]
fn an_exact_payment_reports_paid_with_both_amounts() {
    let out = run(
        &args(json!({})),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
    );
    let value = output(&out);
    assert_eq!(value["status"], "PAID");
    assert_eq!(value["observed_amount_raw"], AMOUNT.to_string());
    assert_eq!(value["requested_amount_raw"], AMOUNT.to_string());
    assert_eq!(value["observed_amount_display"], "25");
    assert_eq!(value["signature"], "SIG1");
    assert_eq!(value["commitment"], "finalized");
    assert_eq!(value["payer_owner_evidence"], key(PAYER).to_string());
}

#[test]
fn a_reported_payer_is_never_presented_as_an_approved_refund_destination() {
    let out = run(
        &args(json!({})),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
    );
    let value = output(&out);
    // The field name itself must not read like an authorization.
    assert!(value.get("refund_to").is_none());
    assert!(value.get("payer_owner_evidence").is_some());
    let authorization = value["refund_authorization"].as_str().unwrap();
    assert!(
        authorization.contains("allowed_recipients"),
        "{authorization}"
    );
    assert!(value["next_step"]
        .as_str()
        .unwrap()
        .contains("does not authorize"));
}

#[test]
fn an_unpaid_invoice_is_reported_as_unpaid_not_as_an_error() {
    let out = run(&args(json!({})), Some(&rpc(None)), Some(&rpc(None)));
    assert_eq!(output(&out)["status"], "UNPAID");
}

#[test]
fn checking_an_unpaid_order_is_how_an_invoice_is_issued() {
    // Nothing is stored, so there is no separate "create" step: the payment
    // link for an unpaid order is re-derived on every check.
    let out = run(&args(json!({})), Some(&rpc(None)), Some(&rpc(None)));
    let value = output(&out);
    assert_eq!(value["status"], "UNPAID");
    let url = value["payment_url"].as_str().expect("payment link");
    assert_eq!(
        url,
        format!(
            "solana:{}?amount=25&spl-token={}&reference={}",
            key(MERCHANT),
            key(MINT),
            reference()
        )
    );
    assert!(value["next_step"].as_str().unwrap().contains("out-of-band"));
}

#[test]
fn the_same_order_always_re_derives_the_same_link() {
    let first = output(&run(&args(json!({})), Some(&rpc(None)), Some(&rpc(None))));
    let second = output(&run(&args(json!({})), Some(&rpc(None)), Some(&rpc(None))));
    assert_eq!(first["payment_url"], second["payment_url"]);
    assert_eq!(first["reference"], second["reference"]);
}

#[test]
fn untrusted_label_text_cannot_break_out_of_the_payment_link() {
    let out = run(
        &args(json!({"label": "Bar&reference=attacker"})),
        Some(&rpc(None)),
        Some(&rpc(None)),
    );
    let url = output(&out)["payment_url"].as_str().unwrap().to_string();
    assert!(url.contains("%26reference%3Dattacker"), "{url}");
    assert_eq!(
        url.matches("reference=").count(),
        1,
        "only the real reference parameter may appear: {url}"
    );
}

#[test]
fn a_paid_order_still_reports_the_link_it_was_paid_against() {
    let out = run(
        &args(json!({})),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
    );
    let value = output(&out);
    assert_eq!(value["status"], "PAID");
    assert!(value["payment_url"].as_str().is_some());
}

#[test]
fn amount_mismatches_are_reported_with_both_numbers() {
    for (paid, status) in [
        (AMOUNT - 1_000_000, "UNDERPAID"),
        (AMOUNT + 1_000_000, "OVERPAID"),
    ] {
        let out = run(
            &args(json!({})),
            Some(&rpc(Some(paid_tx(paid)))),
            Some(&rpc(Some(paid_tx(paid)))),
        );
        let value = output(&out);
        assert_eq!(value["status"], status);
        assert_eq!(value["observed_amount_raw"], paid.to_string());
        assert_eq!(value["requested_amount_raw"], AMOUNT.to_string());
    }
}

#[test]
fn a_payment_after_expiry_is_late() {
    let out = run(
        &args(json!({"expiry_unix": 1_699_999_999i64})),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
    );
    assert_eq!(output(&out)["status"], "LATE");
}

#[test]
fn a_single_endpoint_is_not_evidence() {
    let good = rpc(Some(paid_tx(AMOUNT)));
    let out = run(&args(json!({})), Some(&good), None);
    assert!(!out.success);
    assert!(out.error.unwrap().contains("two independent RPC endpoints"));
}

#[test]
fn disagreeing_endpoints_cannot_mark_an_invoice_paid() {
    let out = run(
        &args(json!({})),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
        Some(&rpc(None)),
    );
    let value = output(&out);
    assert_eq!(value["status"], "UNKNOWN");
    assert_eq!(value["rpc_agreement"], "not established");
    assert!(value["reason"].as_str().unwrap().contains("disagree"));
    assert!(value.get("payer_owner_evidence").is_none());
}

#[test]
fn a_dead_endpoint_is_unknown_and_says_so_rather_than_claiming_unpaid() {
    let out = run(
        &args(json!({})),
        Some(&DownTransport),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
    );
    let value = output(&out);
    assert_eq!(value["status"], "UNKNOWN");
    assert!(
        value["next_step"]
            .as_str()
            .unwrap()
            .contains("not proof of non-payment"),
        "an operator must not read UNKNOWN as UNPAID"
    );
}

#[test]
fn a_review_verdict_lists_its_signatures_and_forbids_a_refund() {
    // Same payer address, but the transfer authority is a delegate.
    let mut tx = paid_tx(AMOUNT);
    tx["result"]["transaction"]["message"]["instructions"][0]["parsed"]["info"]["authority"] =
        json!(key(77).to_string());
    let out = run(
        &args(json!({})),
        Some(&rpc(Some(tx.clone()))),
        Some(&rpc(Some(tx))),
    );
    let value = output(&out);
    assert_eq!(value["status"], "REVIEW");
    assert_eq!(value["signatures"], json!(["SIG1"]));
    assert!(value["reason"].as_str().unwrap().contains("delegated"));
    assert!(value["next_step"].as_str().unwrap().contains("No refund"));
}

#[test]
fn a_prompt_cannot_verify_against_another_merchant() {
    let out = run(
        &args(json!({"merchant_owner": key(99).to_string()})),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
    );
    assert_eq!(output(&out)["reference"], reference());
}

#[test]
fn a_caller_supplied_mint_is_ignored_entirely() {
    // Regression from a live run: the model invented a mint address and passed
    // it. A merchant settles in one configured currency; if the LLM could pick
    // the mint, an injection could invoice a customer in a lookalike token.
    let out = run(
        &args(json!({"mint": key(99).to_string(), "default_mint": key(99).to_string()})),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
        Some(&rpc(Some(paid_tx(AMOUNT)))),
    );
    let value = output(&out);
    assert_eq!(
        value["mint"],
        key(MINT).to_string(),
        "the configured settlement mint must win over any argument"
    );
    assert_eq!(value["status"], "PAID");
}

#[test]
fn no_configured_mint_fails_closed() {
    let out = run(
        &json!({
            "order_id": "ORDER-1",
            "amount_raw": AMOUNT.to_string(),
            "__config": {"merchant_owner": key(MERCHANT).to_string(), "invoice_salt": "salt"}
        })
        .to_string(),
        Some(&rpc(None)),
        Some(&rpc(None)),
    );
    assert!(!out.success);
    assert!(out.error.unwrap().contains("no default_mint"));
}

#[test]
fn missing_configuration_fails_closed() {
    let out = run(
        &json!({"order_id": "A", "amount_raw": "1", "mint": key(MINT).to_string()}).to_string(),
        Some(&rpc(None)),
        Some(&rpc(None)),
    );
    assert!(!out.success);
    assert!(out.error.unwrap().contains("no merchant_owner"));
}

#[test]
fn malformed_arguments_are_refused() {
    for extra in [json!({"amount_raw": "0"}), json!({"amount_raw": "25.5"})] {
        let out = run(&args(extra.clone()), Some(&rpc(None)), Some(&rpc(None)));
        assert!(!out.success, "expected refusal for {extra}");
    }
}
