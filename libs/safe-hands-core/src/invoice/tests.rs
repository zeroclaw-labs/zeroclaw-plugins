//! Deterministic invoice fixtures. Every case in the rejection table of
//! `docs/INVOICE-SPEC.md` has a test here. All offline: RPC is mocked, so a
//! plain `cargo test` proves the contract with zero network.

use super::*;
use crate::crypto::{ata_address, TOKEN_2022_PROGRAM};
use crate::rpc::{DownTransport, MockTransport};

fn key(seed: u8) -> Pubkey {
    Pubkey::new_from_array([seed; 32])
}

const MERCHANT: u8 = 11;
const MINT: u8 = 22;
const PAYER: u8 = 33;
const OTHER: u8 = 44;
const DELEGATE: u8 = 55;
const FEE_PAYER: u8 = 66;
const DECIMALS: u8 = 6;
const AMOUNT: u64 = 25_000_000; // 25 USDC

fn merchant_ata() -> String {
    ata_address(
        &key(MERCHANT),
        &parse_pubkey(TOKEN_PROGRAM).unwrap(),
        &key(MINT),
    )
    .to_string()
}

fn payer_ata(owner: u8) -> String {
    ata_address(
        &key(owner),
        &parse_pubkey(TOKEN_PROGRAM).unwrap(),
        &key(MINT),
    )
    .to_string()
}

fn reference() -> String {
    derive_reference(&key(MERCHANT), "ORDER-1", "salt")
        .unwrap()
        .to_string()
}

fn expectation() -> PaymentExpectation {
    PaymentExpectation {
        merchant_owner: key(MERCHANT).to_string(),
        mint: key(MINT).to_string(),
        reference: reference(),
        requested_amount_raw: AMOUNT,
        expiry_unix: None,
    }
}

/// A valid 82-byte classic SPL Mint account owned by the given program.
fn mint_account(decimals: u8, owner: &str) -> Value {
    let mut data = vec![0u8; 82];
    data[44] = decimals;
    data[45] = 1;
    json!({"result": {"value": {
        "owner": owner,
        "data": [crate::codec::base64_encode(&data), "base64"]
    }}})
}

fn balance(index: u64, mint_key: u8, owner: &str, amount: u64) -> Value {
    json!({
        "accountIndex": index,
        "mint": key(mint_key).to_string(),
        "owner": owner,
        "uiTokenAmount": {"amount": amount.to_string(), "decimals": DECIMALS}
    })
}

/// Builds a `getTransaction` jsonParsed envelope. Defaults describe a clean,
/// owner-signed, exact-amount payment; each test perturbs one thing.
struct Tx {
    signers: Vec<String>,
    keys: Vec<String>,
    pre: Vec<Value>,
    post: Vec<Value>,
    authority: String,
    destination: String,
    err: Value,
    block_time: i64,
    include_reference: bool,
}

impl Default for Tx {
    fn default() -> Self {
        let payer = key(PAYER).to_string();
        Self {
            signers: vec![payer.clone()],
            keys: vec![payer_ata(PAYER), merchant_ata()],
            pre: vec![
                balance(1, MINT, &payer, 100_000_000),
                balance(2, MINT, &key(MERCHANT).to_string(), 0),
            ],
            post: vec![
                balance(1, MINT, &payer, 100_000_000 - AMOUNT),
                balance(2, MINT, &key(MERCHANT).to_string(), AMOUNT),
            ],
            authority: payer,
            destination: merchant_ata(),
            err: Value::Null,
            block_time: 1_700_000_000,
            include_reference: true,
        }
    }
}

impl Tx {
    fn build(&self) -> Value {
        // accountKeys: signers first (Solana requires this), then the rest.
        let mut account_keys: Vec<Value> = Vec::new();
        for signer in &self.signers {
            account_keys.push(json!({"pubkey": signer, "signer": true, "writable": true}));
        }
        for k in &self.keys {
            account_keys.push(json!({"pubkey": k, "signer": false, "writable": true}));
        }
        if self.include_reference {
            account_keys.push(json!({"pubkey": reference(), "signer": false, "writable": false}));
        }
        json!({"result": {
            "slot": 500,
            "blockTime": self.block_time,
            "meta": {
                "err": self.err,
                "preTokenBalances": self.pre,
                "postTokenBalances": self.post,
                "innerInstructions": []
            },
            "transaction": {"message": {
                "header": {"numRequiredSignatures": self.signers.len()},
                "accountKeys": account_keys,
                "instructions": [{
                    "program": "spl-token",
                    "programId": TOKEN_PROGRAM,
                    "parsed": {"type": "transferChecked", "info": {
                        "authority": self.authority,
                        "source": payer_ata(PAYER),
                        "destination": self.destination,
                        "mint": key(MINT).to_string(),
                        "tokenAmount": {"amount": AMOUNT.to_string(), "decimals": DECIMALS}
                    }}
                }]
            }}
        }})
    }
}

/// Mock endpoint: a valid classic mint, one finalized signature, one tx.
fn rpc_with(tx: Value) -> MockTransport {
    MockTransport::new()
        .with("getAccountInfo", mint_account(DECIMALS, TOKEN_PROGRAM))
        .with(
            "getSignaturesForAddress",
            json!({"result": [{"signature": "SIG1", "err": null, "slot": 500}]}),
        )
        .with("getTransaction", tx)
}

// ── Derivation ──────────────────────────────────────────────────────────────

#[test]
fn reference_is_deterministic_and_order_scoped() {
    let a = derive_reference(&key(MERCHANT), "ORDER-1", "salt").unwrap();
    let b = derive_reference(&key(MERCHANT), "ORDER-1", "salt").unwrap();
    assert_eq!(a, b, "same order must re-derive the same reference");

    for (order, salt) in [("ORDER-2", "salt"), ("ORDER-1", "other-salt")] {
        assert_ne!(
            a,
            derive_reference(&key(MERCHANT), order, salt).unwrap(),
            "a different order or salt must give a different reference"
        );
    }
    assert_ne!(a, derive_reference(&key(OTHER), "ORDER-1", "salt").unwrap());
}

#[test]
fn reference_is_off_curve_so_no_key_can_ever_sign_for_it() {
    let reference = derive_reference(&key(MERCHANT), "ORDER-1", "salt").unwrap();
    assert!(
        !reference.is_on_curve(),
        "a reference must have no private key"
    );
}

#[test]
fn reference_accepts_any_order_id_length_but_not_empty() {
    assert!(derive_reference(&key(MERCHANT), &"x".repeat(500), "salt").is_ok());
    assert!(derive_reference(&key(MERCHANT), "", "salt").is_err());
    assert!(derive_reference(&key(MERCHANT), "   ", "salt").is_err());
}

// ── Amount rendering ────────────────────────────────────────────────────────

#[test]
fn raw_amounts_render_exactly_without_floats() {
    let cases = [
        (25_000_000u64, 6u8, "25"),
        (25_500_000, 6, "25.5"),
        (1, 6, "0.000001"),
        (999_999, 6, "0.999999"),
        (1_000_000_000, 9, "1"),
        (100, 0, "100"),
        (0, 6, "0"),
        (u64::MAX, 6, "18446744073709.551615"),
    ];
    for (raw, decimals, expected) in cases {
        assert_eq!(
            raw_to_decimal_string(raw, decimals),
            expected,
            "raw={raw} decimals={decimals}"
        );
    }
}

// ── URL ─────────────────────────────────────────────────────────────────────

fn request() -> InvoiceRequest {
    InvoiceRequest {
        merchant_owner: key(MERCHANT).to_string(),
        mint: key(MINT).to_string(),
        reference: reference(),
        amount_raw: AMOUNT,
        decimals: DECIMALS,
        label: None,
        message: None,
        memo: None,
    }
}

#[test]
fn url_matches_the_solana_pay_shape() {
    let url = request().url().unwrap();
    assert_eq!(
        url,
        format!(
            "solana:{}?amount=25&spl-token={}&reference={}",
            key(MERCHANT),
            key(MINT),
            reference()
        )
    );
}

#[test]
fn url_percent_encodes_untrusted_text() {
    let mut req = request();
    req.label = Some("Café & Bar".to_string());
    req.memo = Some("order #1".to_string());
    let url = req.url().unwrap();
    assert!(url.contains("&label=Caf%C3%A9%20%26%20Bar"), "{url}");
    assert!(url.contains("&memo=order%20%231"), "{url}");
    // The encoded text cannot introduce a new query parameter.
    assert_eq!(url.matches('&').count(), 4, "{url}");
}

#[test]
fn url_rejects_control_characters_and_overlong_text() {
    let mut req = request();
    req.label = Some("bad\nlabel".to_string());
    assert!(req.url().is_err());

    let mut req = request();
    req.message = Some("x".repeat(MAX_TEXT_BYTES + 1));
    assert!(req.url().is_err());
}

#[test]
fn url_rejects_zero_amount_and_malformed_addresses() {
    let mut req = request();
    req.amount_raw = 0;
    assert!(req.url().is_err());

    let mut req = request();
    req.mint = "not-a-key".to_string();
    assert!(req.url().is_err());
}

// ── The happy path ──────────────────────────────────────────────────────────

#[test]
fn exact_owner_signed_payment_is_paid() {
    let verdict = verify_payment(&rpc_with(Tx::default().build()), &expectation());
    let PaymentVerdict::Paid(evidence) = &verdict else {
        panic!("expected Paid, got {verdict:?}");
    };
    assert_eq!(evidence.observed_amount_raw, AMOUNT);
    assert_eq!(evidence.requested_amount_raw, AMOUNT);
    assert_eq!(evidence.payer_owner, key(PAYER).to_string());
    assert_eq!(evidence.signature, "SIG1");
    assert_eq!(evidence.slot, 500);
}

#[test]
fn verification_reads_only_finalized_evidence() {
    let rpc = rpc_with(Tx::default().build());
    verify_payment(&rpc, &expectation());
    for (method, params) in rpc.calls() {
        if method == "getSignaturesForAddress" || method == "getTransaction" {
            let commitment = params[1]["commitment"].as_str();
            assert_eq!(commitment, Some("finalized"), "{method} used {commitment:?}");
        }
    }
}

// ── Amount mismatches: reported, never auto-resolved ────────────────────────

#[test]
fn underpayment_and_overpayment_keep_both_amounts() {
    for (paid, expect_under) in [(AMOUNT - 1, true), (AMOUNT + 1, false)] {
        let tx = Tx {
            pre: vec![
                balance(1, MINT, &key(PAYER).to_string(), 100_000_000),
                balance(2, MINT, &key(MERCHANT).to_string(), 0),
            ],
            post: vec![
                balance(1, MINT, &key(PAYER).to_string(), 100_000_000 - paid),
                balance(2, MINT, &key(MERCHANT).to_string(), paid),
            ],
            ..Default::default()
        };
        let verdict = verify_payment(&rpc_with(tx.build()), &expectation());
        let evidence = verdict.evidence().expect("evidence present");
        assert_eq!(evidence.observed_amount_raw, paid);
        assert_eq!(
            evidence.requested_amount_raw, AMOUNT,
            "the requested amount must never be overwritten by the observed one"
        );
        if expect_under {
            assert!(matches!(verdict, PaymentVerdict::Underpaid(_)), "{verdict:?}");
        } else {
            assert!(matches!(verdict, PaymentVerdict::Overpaid(_)), "{verdict:?}");
        }
    }
}

#[test]
fn payment_after_expiry_is_late() {
    let mut expectation = expectation();
    expectation.expiry_unix = Some(1_699_999_999);
    let verdict = verify_payment(&rpc_with(Tx::default().build()), &expectation);
    assert!(matches!(verdict, PaymentVerdict::Late(_)), "{verdict:?}");
    assert!(verdict.evidence().unwrap().late);

    expectation.expiry_unix = Some(1_700_000_001);
    let verdict = verify_payment(&rpc_with(Tx::default().build()), &expectation);
    assert!(matches!(verdict, PaymentVerdict::Paid(_)), "{verdict:?}");
    assert!(!verdict.evidence().unwrap().late);
}

/// Regression from a live run: a model passed `expiry_unix: 0`, which made
/// every payment "late" against the epoch and hid a real underpayment.
#[test]
fn a_non_positive_expiry_is_no_expiry_at_all() {
    for expiry in [Some(0), Some(-1)] {
        let mut expectation = expectation();
        expectation.expiry_unix = expiry;
        let verdict = verify_payment(&rpc_with(Tx::default().build()), &expectation);
        assert!(matches!(verdict, PaymentVerdict::Paid(_)), "{expiry:?} -> {verdict:?}");
        assert!(!verdict.evidence().unwrap().late);
    }
}

/// Lateness must never hide the amount. A merchant told only "LATE" about a
/// payment that was also short would ship goods they were not paid for.
#[test]
fn a_late_payment_that_is_also_short_still_reports_underpaid() {
    let mut expectation = expectation();
    expectation.expiry_unix = Some(1_699_999_999);
    let tx = Tx {
        pre: vec![
            balance(1, MINT, &key(PAYER).to_string(), 100_000_000),
            balance(2, MINT, &key(MERCHANT).to_string(), 0),
        ],
        post: vec![
            balance(1, MINT, &key(PAYER).to_string(), 100_000_000 - 1),
            balance(2, MINT, &key(MERCHANT).to_string(), 1),
        ],
        ..Default::default()
    };
    let verdict = verify_payment(&rpc_with(tx.build()), &expectation);
    let PaymentVerdict::Underpaid(evidence) = &verdict else {
        panic!("expected Underpaid, got {verdict:?}");
    };
    assert_eq!(evidence.observed_amount_raw, 1);
    assert_eq!(evidence.requested_amount_raw, AMOUNT);
    assert!(evidence.late, "the lateness must still be reported");
}

// ── Nothing to see: unpaid, not review ──────────────────────────────────────

#[test]
fn no_signatures_is_unpaid() {
    let rpc = MockTransport::new()
        .with("getAccountInfo", mint_account(DECIMALS, TOKEN_PROGRAM))
        .with("getSignaturesForAddress", json!({"result": []}));
    assert_eq!(verify_payment(&rpc, &expectation()), PaymentVerdict::Unpaid);
}

#[test]
fn failed_transaction_moved_no_money_and_is_unpaid() {
    let tx = Tx {
        err: json!({"InstructionError": [0, "Custom"]}),
        ..Default::default()
    };
    assert_eq!(
        verify_payment(&rpc_with(tx.build()), &expectation()),
        PaymentVerdict::Unpaid
    );
}

#[test]
fn transfer_to_a_different_recipient_is_unpaid() {
    let tx = Tx {
        keys: vec![payer_ata(PAYER), payer_ata(OTHER)],
        post: vec![
            balance(1, MINT, &key(PAYER).to_string(), 100_000_000 - AMOUNT),
            balance(2, MINT, &key(OTHER).to_string(), AMOUNT),
        ],
        destination: payer_ata(OTHER),
        ..Default::default()
    };
    assert_eq!(
        verify_payment(&rpc_with(tx.build()), &expectation()),
        PaymentVerdict::Unpaid
    );
}

#[test]
fn a_transaction_not_carrying_the_reference_is_unpaid() {
    let tx = Tx {
        include_reference: false,
        ..Default::default()
    };
    assert_eq!(
        verify_payment(&rpc_with(tx.build()), &expectation()),
        PaymentVerdict::Unpaid
    );
}

#[test]
fn an_unrelated_mint_credit_is_unpaid() {
    let tx = Tx {
        pre: vec![balance(2, OTHER, &key(MERCHANT).to_string(), 0)],
        post: vec![balance(2, OTHER, &key(MERCHANT).to_string(), AMOUNT)],
        ..Default::default()
    };
    assert_eq!(
        verify_payment(&rpc_with(tx.build()), &expectation()),
        PaymentVerdict::Unpaid
    );
}

// ── Money moved, but not attributable: review ───────────────────────────────

fn assert_review(verdict: &PaymentVerdict, needle: &str) {
    let PaymentVerdict::Review { reason, .. } = verdict else {
        panic!("expected Review containing {needle:?}, got {verdict:?}");
    };
    assert!(reason.contains(needle), "reason was {reason:?}");
}

#[test]
fn delegated_transfer_is_review_because_a_delegate_is_not_the_payer() {
    let tx = Tx {
        authority: key(DELEGATE).to_string(),
        signers: vec![key(DELEGATE).to_string()],
        ..Default::default()
    };
    let verdict = verify_payment(&rpc_with(tx.build()), &expectation());
    assert_review(&verdict, "delegated transfer");
}

#[test]
fn split_payment_from_two_owners_is_review() {
    let tx = Tx {
        keys: vec![payer_ata(PAYER), merchant_ata(), payer_ata(OTHER)],
        pre: vec![
            balance(1, MINT, &key(PAYER).to_string(), 100_000_000),
            balance(2, MINT, &key(MERCHANT).to_string(), 0),
            balance(3, MINT, &key(OTHER).to_string(), 100_000_000),
        ],
        post: vec![
            balance(1, MINT, &key(PAYER).to_string(), 100_000_000 - 10_000_000),
            balance(2, MINT, &key(MERCHANT).to_string(), AMOUNT),
            balance(3, MINT, &key(OTHER).to_string(), 100_000_000 - 15_000_000),
        ],
        ..Default::default()
    };
    let verdict = verify_payment(&rpc_with(tx.build()), &expectation());
    assert_review(&verdict, "split payment");
}

#[test]
fn source_owner_that_did_not_sign_is_review() {
    // A different account pays the fee and signs; the token owner does not.
    let tx = Tx {
        signers: vec![key(FEE_PAYER).to_string()],
        ..Default::default()
    };
    let verdict = verify_payment(&rpc_with(tx.build()), &expectation());
    assert_review(&verdict, "did not sign");
}

/// The canonical Solana Pay shape, taken from a real devnet transaction.
///
/// Attaching the reference as a fifth account makes the RPC render the
/// multisig variant of TransferChecked: the payer appears as
/// `multisigAuthority` and the reference — which signed nothing — is listed
/// under `signers`. Refusing this would refuse every correctly formed
/// Solana Pay payment.
#[test]
fn the_real_solana_pay_shape_is_paid_not_review() {
    let mut tx = Tx::default().build();
    let info = &mut tx["result"]["transaction"]["message"]["instructions"][0]["parsed"]["info"];
    let object = info.as_object_mut().unwrap();
    object.remove("authority");
    object.insert("multisigAuthority".into(), json!(key(PAYER).to_string()));
    object.insert("signers".into(), json!([reference()]));

    let verdict = verify_payment(&rpc_with(tx), &expectation());
    let PaymentVerdict::Paid(evidence) = &verdict else {
        panic!("expected Paid, got {verdict:?}");
    };
    assert_eq!(evidence.payer_owner, key(PAYER).to_string());
}

/// A genuine SPL multisig is still refused — the token account is owned by a
/// Multisig account, and a Multisig account never signs a transaction itself.
#[test]
fn a_genuine_spl_multisig_owner_is_still_review() {
    let multisig_owner = key(OTHER).to_string();
    let tx = Tx {
        // The source token account is owned by the multisig account...
        pre: vec![
            balance(1, MINT, &multisig_owner, 100_000_000),
            balance(2, MINT, &key(MERCHANT).to_string(), 0),
        ],
        post: vec![
            balance(1, MINT, &multisig_owner, 100_000_000 - AMOUNT),
            balance(2, MINT, &key(MERCHANT).to_string(), AMOUNT),
        ],
        authority: multisig_owner.clone(),
        // ...but a member wallet, not the multisig, signs the transaction.
        signers: vec![key(PAYER).to_string()],
        ..Default::default()
    };
    let verdict = verify_payment(&rpc_with(tx.build()), &expectation());
    assert_review(&verdict, "did not sign");
}

#[test]
fn credit_with_no_matching_transfer_instruction_is_review() {
    // Balances credit the merchant, but the instruction does not.
    let tx = Tx {
        destination: payer_ata(OTHER),
        ..Default::default()
    };
    let verdict = verify_payment(&rpc_with(tx.build()), &expectation());
    assert_review(&verdict, "no classic SPL transfer instruction");
}

#[test]
fn duplicate_finalized_payments_are_review_and_name_every_signature() {
    let rpc = MockTransport::new()
        .with("getAccountInfo", mint_account(DECIMALS, TOKEN_PROGRAM))
        .with(
            "getSignaturesForAddress",
            json!({"result": [
                {"signature": "SIG1", "err": null},
                {"signature": "SIG2", "err": null}
            ]}),
        )
        .with("getTransaction", Tx::default().build());
    let verdict = verify_payment(&rpc, &expectation());
    let PaymentVerdict::Review {
        reason, signatures, ..
    } = &verdict
    else {
        panic!("expected Review, got {verdict:?}");
    };
    assert!(reason.contains("duplicate payment"), "{reason}");
    assert_eq!(signatures, &["SIG1".to_string(), "SIG2".to_string()]);
}

#[test]
fn balance_decimals_disagreeing_with_the_mint_is_review() {
    let mut tx = Tx::default().build();
    tx["result"]["meta"]["postTokenBalances"][1]["uiTokenAmount"]["decimals"] = json!(9);
    let verdict = verify_payment(&rpc_with(tx), &expectation());
    assert_review(&verdict, "decimals");
}

#[test]
fn a_griefing_flood_of_references_is_review_not_silent_truncation() {
    let entries: Vec<Value> = (0..MAX_SIGNATURES + 1)
        .map(|i| json!({"signature": format!("SIG{i}"), "err": null}))
        .collect();
    let rpc = MockTransport::new()
        .with("getAccountInfo", mint_account(DECIMALS, TOKEN_PROGRAM))
        .with("getSignaturesForAddress", json!({ "result": entries }))
        .with("getTransaction", Tx::default().build());
    let verdict = verify_payment(&rpc, &expectation());
    assert_review(&verdict, "manual review required");
}

// ── Untrusted evidence: unknown, always fail closed ─────────────────────────

#[test]
fn token_2022_cannot_reach_the_amount_comparison() {
    let rpc = MockTransport::new()
        .with("getAccountInfo", mint_account(DECIMALS, TOKEN_2022_PROGRAM))
        .with(
            "getSignaturesForAddress",
            json!({"result": [{"signature": "SIG1", "err": null}]}),
        )
        .with("getTransaction", Tx::default().build());
    let verdict = verify_payment(&rpc, &expectation());
    let PaymentVerdict::Unknown { reason } = &verdict else {
        panic!("expected Unknown, got {verdict:?}");
    };
    assert!(reason.contains("classic SPL Token"), "{reason}");
}

#[test]
fn a_dead_endpoint_is_unknown_never_unpaid() {
    let verdict = verify_payment(&DownTransport, &expectation());
    assert!(matches!(verdict, PaymentVerdict::Unknown { .. }), "{verdict:?}");
}

#[test]
fn malformed_or_missing_evidence_is_unknown() {
    let base = || MockTransport::new().with("getAccountInfo", mint_account(DECIMALS, TOKEN_PROGRAM));
    let cases: Vec<(&str, MockTransport)> = vec![
        (
            "signature list is not an array",
            base().with("getSignaturesForAddress", json!({"result": {}})),
        ),
        (
            "signature list is an rpc error",
            base().with(
                "getSignaturesForAddress",
                json!({"error": {"code": -32000, "message": "no"}}),
            ),
        ),
        (
            "finalized signature is not retrievable",
            base()
                .with(
                    "getSignaturesForAddress",
                    json!({"result": [{"signature": "SIG1", "err": null}]}),
                )
                .with("getTransaction", json!({"result": null})),
        ),
        (
            "transaction has no account keys",
            base()
                .with(
                    "getSignaturesForAddress",
                    json!({"result": [{"signature": "SIG1", "err": null}]}),
                )
                .with("getTransaction", json!({"result": {"meta": {"err": null}}})),
        ),
        (
            "token balance has no owner",
            base()
                .with(
                    "getSignaturesForAddress",
                    json!({"result": [{"signature": "SIG1", "err": null}]}),
                )
                .with("getTransaction", {
                    let mut tx = Tx::default().build();
                    tx["result"]["meta"]["postTokenBalances"][1]
                        .as_object_mut()
                        .unwrap()
                        .remove("owner");
                    tx
                }),
        ),
    ];
    for (name, rpc) in cases {
        let verdict = verify_payment(&rpc, &expectation());
        assert!(
            matches!(verdict, PaymentVerdict::Unknown { .. }),
            "{name}: expected Unknown, got {verdict:?}"
        );
    }
}

// ── Two endpoints must agree ────────────────────────────────────────────────

#[test]
fn agreeing_endpoints_return_the_verdict() {
    let verdict = verify_payment_agreed(
        &rpc_with(Tx::default().build()),
        &rpc_with(Tx::default().build()),
        &expectation(),
    );
    assert!(matches!(verdict, PaymentVerdict::Paid(_)), "{verdict:?}");
}

#[test]
fn one_lying_endpoint_cannot_mark_an_invoice_paid() {
    let honest = MockTransport::new()
        .with("getAccountInfo", mint_account(DECIMALS, TOKEN_PROGRAM))
        .with("getSignaturesForAddress", json!({"result": []}));
    let liar = rpc_with(Tx::default().build());

    for (primary, fallback) in [(&liar, &honest), (&honest, &liar)] {
        let verdict = verify_payment_agreed(primary, fallback, &expectation());
        let PaymentVerdict::Unknown { reason } = &verdict else {
            panic!("expected Unknown, got {verdict:?}");
        };
        assert!(reason.contains("disagree"), "{reason}");
    }
}

#[test]
fn a_failing_endpoint_is_named_in_the_reason() {
    let good = rpc_with(Tx::default().build());
    let verdict = verify_payment_agreed(&DownTransport, &good, &expectation());
    let PaymentVerdict::Unknown { reason } = &verdict else {
        panic!("expected Unknown, got {verdict:?}");
    };
    assert!(reason.starts_with("primary RPC:"), "{reason}");

    let verdict = verify_payment_agreed(&good, &DownTransport, &expectation());
    let PaymentVerdict::Unknown { reason } = &verdict else {
        panic!("expected Unknown, got {verdict:?}");
    };
    assert!(reason.starts_with("fallback RPC:"), "{reason}");
}

#[test]
fn every_verdict_has_a_stable_tag() {
    let evidence = PaymentEvidence {
        signature: "S".into(),
        payer_owner: key(PAYER).to_string(),
        observed_amount_raw: 1,
        requested_amount_raw: 1,
        block_time: None,
        slot: 1,
        late: false,
    };
    let cases = [
        (PaymentVerdict::Unpaid, "UNPAID"),
        (PaymentVerdict::Paid(evidence.clone()), "PAID"),
        (PaymentVerdict::Underpaid(evidence.clone()), "UNDERPAID"),
        (PaymentVerdict::Overpaid(evidence.clone()), "OVERPAID"),
        (PaymentVerdict::Late(evidence), "LATE"),
        (
            PaymentVerdict::Review {
                reason: String::new(),
                signatures: vec![],
            },
            "REVIEW",
        ),
        (
            PaymentVerdict::Unknown {
                reason: String::new(),
            },
            "UNKNOWN",
        ),
    ];
    for (verdict, tag) in cases {
        assert_eq!(verdict.tag(), tag);
    }
}
