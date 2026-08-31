//! Integration tests for the invoice-status pure core, exercised the same way
//! the wasm `execute` entry point drives it: build a `StatusConfig` from a flat
//! config section, then evaluate status from fixture signatures. Runs on the
//! host with a plain `cargo test` — no network.

use std::cell::RefCell;
use std::collections::HashMap;

use invoice_status::status_tool::{
    evaluate_status, evaluate_status_verified, fetch_and_status, fixture_success_sig,
    resolve_reference, StatusConfig, StatusRequest, DEFAULT_LOOKBACK, MAX_VALUE_CHECKS,
};
use serde_json::{json, Value};
use solana_wasm_core::{derive_reference, HttpTransport, RpcError, UsdcReceipt};

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

const MERCHANT: &str = "11111111111111111111111111111112";
const INVOICE_ID: &str = "inv-001";

#[test]
fn resolve_reference_is_deterministic() {
    let a = resolve_reference(INVOICE_ID, None, MERCHANT).unwrap();
    let b = resolve_reference(INVOICE_ID, None, MERCHANT).unwrap();
    assert_eq!(a, b);
    assert_eq!(a, derive_reference(INVOICE_ID, MERCHANT));

    let explicit = resolve_reference(INVOICE_ID, Some("ExplicitRef111"), MERCHANT).unwrap();
    assert_eq!(explicit, "ExplicitRef111");
}

#[test]
fn evaluate_status_unpaid() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let req = StatusRequest {
        invoice_id: INVOICE_ID.into(),
        reference: None,
        expected_usdc: Some("10".into()),
        pix_marked_paid: false,
        lookback: DEFAULT_LOOKBACK,
    };
    let s = evaluate_status(&req, &cfg, &[]);
    assert!(s.contains("USDC: PENDING"), "unexpected unpaid text: {s}");
    assert!(s.contains("PIX: PENDING"), "{s}");
    assert!(s.contains("OVERALL: PENDING"), "{s}");
    assert!(s.contains(INVOICE_ID), "{s}");
}

#[test]
fn evaluate_status_with_successful_sig() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let req = StatusRequest {
        invoice_id: INVOICE_ID.into(),
        reference: None,
        expected_usdc: Some("12.5".into()),
        pix_marked_paid: false,
        lookback: DEFAULT_LOOKBACK,
    };
    let sigs = vec![fixture_success_sig(
        "VeryLongSignatureSuccess111",
        Some("PIX|BRL|inv-001|x"),
    )];
    let s = evaluate_status(&req, &cfg, &sigs);
    assert!(s.contains("USDC: PAID"), "{s}");
    assert!(s.contains("solscan.io/tx/"), "{s}");
    assert!(
        s.contains("PIX: PENDING") || s.contains("PIX não confirmado"),
        "{s}"
    );
    assert!(s.contains("esperado=12.5") || s.contains("12.5"), "{s}");
}

#[test]
fn evaluate_status_pix_marked_paid() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let req = StatusRequest {
        invoice_id: "inv-2".into(),
        reference: Some("RefXYZ".into()),
        expected_usdc: None,
        pix_marked_paid: true,
        lookback: DEFAULT_LOOKBACK,
    };
    let sigs = vec![fixture_success_sig("SigOK", None)];
    let s = evaluate_status(&req, &cfg, &sigs);
    assert!(s.contains("USDC: PAID"), "{s}");
    assert!(s.contains("PIX: PAID"), "{s}");
    assert!(s.contains("ambos trilhos") || s.contains("OVERALL:"), "{s}");
}

#[test]
fn missing_merchant_fails_resolve_when_no_reference() {
    let err = resolve_reference(INVOICE_ID, None, "").unwrap_err();
    assert!(
        err.contains("merchant_solana") || err.contains("reference"),
        "unexpected error: {err}"
    );

    let cfg = StatusConfig::from_map(&HashMap::new());
    let req = StatusRequest {
        invoice_id: INVOICE_ID.into(),
        reference: None,
        expected_usdc: None,
        pix_marked_paid: false,
        lookback: DEFAULT_LOOKBACK,
    };
    let s = evaluate_status(&req, &cfg, &[]);
    assert!(
        s.contains("merchant_solana") || s.contains("reference"),
        "unexpected: {s}"
    );
}

#[test]
fn config_defaults_and_overrides() {
    let empty = StatusConfig::from_map(&HashMap::new());
    assert!(empty.rpc_url.contains("solana.com"));
    assert!(empty.merchant_solana.is_empty());

    let cfg = StatusConfig::from_map(&section(&[
        ("rpc_url", "https://rpc.example/"),
        ("merchant_solana", MERCHANT),
        ("usdc_mint", "Mint111"),
    ]));
    assert_eq!(cfg.rpc_url, "https://rpc.example/");
    assert_eq!(cfg.merchant_solana, MERCHANT);
    assert_eq!(cfg.usdc_mint, "Mint111");
}

// ── Value-aware (verified) path ─────────────────────────────────────────────

const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Receipt from a decimal string, parsed exactly at USDC's 6 decimals — the
/// verified path is integer-only, no float ever enters it.
fn recv(amount: &str) -> Option<UsdcReceipt> {
    Some(UsdcReceipt {
        received_units: solana_wasm_core::parse_decimal(amount, 6).unwrap().value,
        decimals: 6,
        block_time: Some(1_700_000_000),
    })
}

fn verified_req(expected: Option<&str>) -> StatusRequest {
    StatusRequest {
        invoice_id: INVOICE_ID.into(),
        reference: None,
        expected_usdc: expected.map(|s| s.to_string()),
        pix_marked_paid: false,
        lookback: DEFAULT_LOOKBACK,
    }
}

#[test]
fn verified_exact_payment_emits_receipt() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let sigs = vec![fixture_success_sig("VeryLongSigPaid1111", None)];
    let s = evaluate_status_verified(&verified_req(Some("27.27")), &cfg, &sigs, recv("27.27"));
    assert!(s.contains("USDC: PAID ✅"), "{s}");
    assert!(s.contains("RECIBO — INVOICE #inv-001"), "{s}");
    assert!(s.contains("Encaminhe esta mensagem ao cliente"), "{s}");
}

#[test]
fn verified_underpaid_flags_shortfall() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let sigs = vec![fixture_success_sig("Sig", None)];
    let s = evaluate_status_verified(&verified_req(Some("90")), &cfg, &sigs, recv("0.01"));
    assert!(s.contains("USDC: UNDERPAID ⚠️"), "{s}");
    assert!(s.contains("faltam"), "{s}");
    assert!(!s.contains("RECIBO"), "no receipt when underpaid: {s}");
}

#[test]
fn verified_overpaid_still_paid() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let sigs = vec![fixture_success_sig("Sig", None)];
    let s = evaluate_status_verified(&verified_req(Some("100")), &cfg, &sigs, recv("150"));
    assert!(s.contains("USDC: OVERPAID"), "{s}");
    assert!(s.contains("RECIBO"), "{s}");
}

#[test]
fn verified_no_expected_reports_received() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let sigs = vec![fixture_success_sig("Sig", None)];
    let s = evaluate_status_verified(&verified_req(None), &cfg, &sigs, recv("55.5"));
    assert!(s.contains("USDC: RECEBIDO 55.5"), "{s}");
    assert!(s.contains("RECIBO"), "{s}");
}

#[test]
fn verified_degrades_without_transaction() {
    let cfg = StatusConfig::from_map(&section(&[("merchant_solana", MERCHANT)]));
    let sigs = vec![fixture_success_sig("Sig", None)];
    // verified = None → getTransaction couldn't confirm the amount.
    let s = evaluate_status_verified(&verified_req(Some("90")), &cfg, &sigs, None);
    assert!(s.contains("USDC: SIG OK"), "{s}");
    assert!(
        !s.contains("USDC: PAID"),
        "never PAID without a checked value: {s}"
    );
}

// ── End-to-end: getSignaturesForAddress + getTransaction over a mock RPC ─────

/// Mock transport that dispatches on the JSON-RPC `method` so a single
/// `fetch_and_status` call exercises both round-trips without network.
struct DualMethodHttp {
    sigs: Value,
    tx: Value,
    calls: RefCell<Vec<String>>,
}

impl HttpTransport for DualMethodHttp {
    fn post_json(&self, _url: &str, body: &Value) -> Result<Value, RpcError> {
        let method = body["method"].as_str().unwrap_or_default().to_string();
        self.calls.borrow_mut().push(method.clone());
        let result = match method.as_str() {
            "getSignaturesForAddress" => self.sigs.clone(),
            "getTransaction" => self.tx.clone(),
            other => return Err(RpcError::new(format!("unexpected method: {other}"))),
        };
        Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
    }
}

fn token_balance(mint: &str, owner: &str, ui: f64) -> Value {
    json!({
        "accountIndex": 1,
        "mint": mint,
        "owner": owner,
        "uiTokenAmount": {
            "amount": format!("{}", (ui * 1_000_000.0) as u64),
            "decimals": 6,
            "uiAmount": ui,
            "uiAmountString": format!("{ui}")
        }
    })
}

#[test]
fn fetch_and_status_end_to_end_paid() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
        ("rpc_url", "https://rpc.example/"),
    ]));
    let http = DualMethodHttp {
        sigs: json!([{
            "signature": "SigPaid111",
            "slot": 10,
            "err": null,
            "blockTime": 1_700_000_000,
            "confirmationStatus": "finalized"
        }]),
        tx: json!({
            "blockTime": 1_700_000_000,
            "slot": 10,
            "meta": {
                "err": null,
                "preTokenBalances": [ token_balance(MINT, MERCHANT, 0.0) ],
                "postTokenBalances": [ token_balance(MINT, MERCHANT, 90.0) ]
            }
        }),
        calls: RefCell::new(Vec::new()),
    };

    let req = verified_req(Some("90"));
    let s = fetch_and_status(&req, &cfg, http).unwrap();
    assert!(s.contains("USDC: PAID ✅"), "{s}");
    assert!(s.contains("RECIBO"), "{s}");
    // Settled → the tool tells the agent to tear down any cron watcher.
    let last = s.lines().last().unwrap();
    assert!(
        last.starts_with("[sistema]") && last.contains("cron_remove"),
        "cron teardown must be the last line:\n{s}"
    );
    assert!(
        s.find("RECIBO").unwrap() < s.find("[sistema]").unwrap(),
        "{s}"
    );
}

#[test]
fn fetch_and_status_end_to_end_underpaid() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    let http = DualMethodHttp {
        sigs: json!([{
            "signature": "SigUnder111",
            "slot": 10,
            "err": null,
            "blockTime": 1_700_000_000,
            "confirmationStatus": "finalized"
        }]),
        tx: json!({
            "blockTime": 1_700_000_000,
            "meta": {
                "preTokenBalances": [],
                "postTokenBalances": [ token_balance(MINT, MERCHANT, 0.01) ]
            }
        }),
        calls: RefCell::new(Vec::new()),
    };

    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();
    assert!(s.contains("USDC: UNDERPAID ⚠️"), "{s}");
    assert!(!s.contains("USDC: PAID ✅"), "{s}");
    // Not settled → the cron watcher must keep running.
    assert!(!s.contains("cron_remove"), "{s}");
}

/// Mock transport that answers `getTransaction` per signature so multi-payment
/// summation can be exercised. Records which signatures were actually fetched,
/// so the early-stop behaviour is observable.
struct PerSigHttp {
    sigs: Value,
    txs: HashMap<String, Value>,
    fetched: RefCell<Vec<String>>,
}

impl PerSigHttp {
    fn new(sigs: Value, txs: HashMap<String, Value>) -> Self {
        Self {
            sigs,
            txs,
            fetched: RefCell::new(Vec::new()),
        }
    }
}

impl HttpTransport for PerSigHttp {
    fn post_json(&self, _url: &str, body: &Value) -> Result<Value, RpcError> {
        let method = body["method"].as_str().unwrap_or_default();
        let result = match method {
            "getSignaturesForAddress" => self.sigs.clone(),
            "getTransaction" => {
                let sig = body["params"][0].as_str().unwrap_or_default();
                self.fetched.borrow_mut().push(sig.to_string());
                self.txs.get(sig).cloned().unwrap_or(Value::Null)
            }
            other => return Err(RpcError::new(format!("unexpected method: {other}"))),
        };
        Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
    }
}

/// Signature list entry, newest first when listed in order.
fn sig_entry(signature: &str, slot: u64) -> Value {
    json!({
        "signature": signature,
        "slot": slot,
        "err": null,
        "blockTime": 1_700_000_000i64 + slot as i64,
        "confirmationStatus": "finalized"
    })
}

/// Token balance entry from exact minor units (no float on the path).
fn balance_units(mint: &str, owner: &str, units: u128) -> Value {
    json!({
        "accountIndex": 1,
        "mint": mint,
        "owner": owner,
        "uiTokenAmount": { "amount": units.to_string(), "decimals": 6 }
    })
}

/// A transaction whose merchant USDC balance goes from `pre` to `post` units.
fn tx_units(pre: u128, post: u128) -> Value {
    json!({
        "blockTime": 1_700_000_000,
        "slot": 10,
        "meta": {
            "err": null,
            "preTokenBalances": [ balance_units(MINT, MERCHANT, pre) ],
            "postTokenBalances": [ balance_units(MINT, MERCHANT, post) ]
        }
    })
}

fn tx_with_delta(pre: f64, post: f64) -> Value {
    json!({
        "blockTime": 1_700_000_000,
        "slot": 10,
        "meta": {
            "err": null,
            "preTokenBalances": [ token_balance(MINT, MERCHANT, pre) ],
            "postTokenBalances": [ token_balance(MINT, MERCHANT, post) ]
        }
    })
}

#[test]
fn fetch_and_status_sums_partial_payments() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    // Two partial transfers of 45 USDC each settle a 90 USDC invoice.
    let http = PerSigHttp::new(
        json!([
            { "signature": "SigPart2", "slot": 11, "err": null,
              "blockTime": 1_700_000_100, "confirmationStatus": "finalized" },
            { "signature": "SigPart1", "slot": 10, "err": null,
              "blockTime": 1_700_000_000, "confirmationStatus": "finalized" }
        ]),
        HashMap::from([
            ("SigPart2".to_string(), tx_with_delta(45.0, 90.0)),
            ("SigPart1".to_string(), tx_with_delta(0.0, 45.0)),
        ]),
    );

    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();
    assert!(
        s.contains("USDC: PAID ✅"),
        "partials must sum to PAID: {s}"
    );
    assert!(s.contains("RECIBO"), "{s}");
}

#[test]
fn fetch_and_status_spam_tx_does_not_mask_payment() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    // Newest tx touches the reference but transfers no USDC to the merchant;
    // the older real payment must still be counted.
    let http = PerSigHttp::new(
        json!([
            { "signature": "SigSpam", "slot": 12, "err": null,
              "blockTime": 1_700_000_200, "confirmationStatus": "finalized" },
            { "signature": "SigReal", "slot": 10, "err": null,
              "blockTime": 1_700_000_000, "confirmationStatus": "finalized" }
        ]),
        HashMap::from([
            ("SigSpam".to_string(), tx_with_delta(0.0, 0.0)),
            ("SigReal".to_string(), tx_with_delta(0.0, 90.0)),
        ]),
    );

    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();
    assert!(
        s.contains("USDC: PAID ✅"),
        "spam must not mask payment: {s}"
    );
}

/// FURO A: the exact attack the old `MAX_VALUE_CHECKS = 5` window enabled.
///
/// Six successful dust transactions naming the invoice reference — six network
/// fees, no privileged access — pushed the genuine payment out of the checked
/// window, so `received_sum` came back 0 and a fully paid invoice was reported
/// `PENDING`. Every successful signature the lookback returned is now checked.
#[test]
fn fetch_and_status_six_spam_txs_do_not_mask_payment() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));

    let mut sigs = Vec::new();
    let mut txs = HashMap::new();
    // Ten dust txs, newest first: successful, touch the reference, move nothing.
    for i in 0..10u64 {
        let name = format!("SigSpam{i}");
        sigs.push(sig_entry(&name, 100 - i));
        txs.insert(name, tx_units(0, 0));
    }
    // The real 90 USDC payment, older than all of them.
    sigs.push(sig_entry("SigReal", 1));
    txs.insert("SigReal".to_string(), tx_units(0, 90_000_000));

    let http = PerSigHttp::new(Value::Array(sigs), txs);
    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();

    assert!(
        s.contains("USDC: PAID ✅ (recebido 90 de 90 USDC)"),
        "10 spam txs must not bury the payment:\n{s}"
    );
    assert!(s.contains("RECIBO"), "{s}");
    assert!(
        s.contains("cron_remove"),
        "settled → tear the watcher down: {s}"
    );
}

/// The scan stops as soon as the invoice is covered, so the ordinary settled
/// case does not pay for the whole lookback in RPC calls.
#[test]
fn fetch_and_status_stops_early_once_expected_is_reached() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));

    // Newest signature settles the invoice; 20 older ones follow.
    let mut sigs = vec![sig_entry("SigReal", 100)];
    let mut txs = HashMap::from([("SigReal".to_string(), tx_units(0, 90_000_000))]);
    for i in 0..20u64 {
        let name = format!("SigOld{i}");
        sigs.push(sig_entry(&name, 50 - i));
        txs.insert(name, tx_units(0, 0));
    }

    let http = PerSigHttp::new(Value::Array(sigs), txs);
    let s = fetch_and_status(&verified_req(Some("90")), &cfg, &http).unwrap();
    assert!(s.contains("USDC: PAID ✅"), "{s}");
    let fetched = http.fetched.borrow();
    assert_eq!(
        fetched.len(),
        1,
        "must stop at the transaction that settled the invoice, fetched: {fetched:?}"
    );
    assert_eq!(fetched[0], "SigReal");
}

/// Without an expected amount there is nothing to stop early on, so everything
/// in the lookback is scanned and summed.
#[test]
fn fetch_and_status_without_expected_scans_everything() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    let http = PerSigHttp::new(
        json!([
            sig_entry("SigA", 12),
            sig_entry("SigB", 11),
            sig_entry("SigC", 10)
        ]),
        HashMap::from([
            ("SigA".to_string(), tx_units(0, 1_000_000)),
            ("SigB".to_string(), tx_units(0, 2_000_000)),
            ("SigC".to_string(), tx_units(0, 3_000_000)),
        ]),
    );
    let s = fetch_and_status(&verified_req(None), &cfg, &http).unwrap();
    assert!(s.contains("USDC: RECEBIDO 6"), "{s}");
    assert_eq!(http.fetched.borrow().len(), 3, "{s}");
}

/// FURO C, end to end: no tolerance band survives the RPC path.
#[test]
fn fetch_and_status_has_no_tolerance_band() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    // 99.6 of 100 — the old rule paid this out with a receipt. On a R$ 1.000
    // invoice that is R$ 5 the merchant never sees.
    let http = PerSigHttp::new(
        json!([sig_entry("SigShort", 10)]),
        HashMap::from([("SigShort".to_string(), tx_units(0, 99_600_000))]),
    );
    let s = fetch_and_status(&verified_req(Some("100")), &cfg, http).unwrap();
    assert!(s.contains("USDC: UNDERPAID ⚠️"), "{s}");
    assert!(s.contains("faltam 0.4"), "{s}");
    assert!(!s.contains("RECIBO"), "{s}");
    assert!(!s.contains("cron_remove"), "watcher keeps running: {s}");
}

/// FURO C: the summation itself is exact. Three transfers of 0.1 USDC settle a
/// 0.3 USDC invoice — in `f64` the sum is 0.30000000000000004 and, without the
/// old tolerance covering it up, would have read as an overpayment.
#[test]
fn fetch_and_status_sum_is_exact_integer_arithmetic() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    let http = PerSigHttp::new(
        json!([
            sig_entry("S1", 12),
            sig_entry("S2", 11),
            sig_entry("S3", 10)
        ]),
        HashMap::from([
            ("S1".to_string(), tx_units(0, 100_000)),
            ("S2".to_string(), tx_units(0, 100_000)),
            ("S3".to_string(), tx_units(0, 100_000)),
        ]),
    );
    let s = fetch_and_status(&verified_req(Some("0.3")), &cfg, http).unwrap();
    assert!(
        s.contains("USDC: PAID ✅ (recebido 0.3 de 0.3 USDC)"),
        "{s}"
    );
    assert!(!s.contains("OVERPAID"), "{s}");
}

/// A scan that could not read every candidate transaction produces a *lower
/// bound*, and a lower bound may not be published as a shortfall.
///
/// This matters more now that the tool checks the whole lookback instead of
/// five signatures: on the default public RPC, a rate-limited `getTransaction`
/// halfway through would otherwise turn a fully paid invoice into
/// `UNDERPAID ⚠️ … faltam 45`, which the merchant shows the customer.
#[test]
fn fetch_and_status_incomplete_scan_does_not_assert_a_shortfall() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    // SigA transferred 45 of a 90 USDC invoice; SigB cannot be fetched.
    let http = PerSigHttp::new(
        json!([sig_entry("SigA", 12), sig_entry("SigB", 11)]),
        HashMap::from([("SigA".to_string(), tx_units(0, 45_000_000))]),
    );
    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();
    assert!(s.contains("USDC: SIG OK"), "{s}");
    assert!(
        !s.contains("UNDERPAID"),
        "unproven shortfall must not be stated: {s}"
    );
    assert!(!s.contains("RECIBO"), "{s}");
    assert!(!s.contains("cron_remove"), "watcher keeps running: {s}");
}

/// The same lower bound is still enough to confirm a payment: once the total
/// covers the invoice, what the unreadable transactions held cannot unsettle it.
#[test]
fn fetch_and_status_incomplete_scan_still_confirms_a_covered_invoice() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    // Newest signature is unfetchable; the one behind it settles the invoice.
    let http = PerSigHttp::new(
        json!([sig_entry("SigUnreadable", 12), sig_entry("SigReal", 11)]),
        HashMap::from([("SigReal".to_string(), tx_units(0, 90_000_000))]),
    );
    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();
    assert!(s.contains("USDC: PAID ✅ (recebido 90 de 90 USDC)"), "{s}");
    assert!(s.contains("RECIBO"), "{s}");
}

/// Beyond `MAX_VALUE_CHECKS` the scan is truncated, and a truncated scan must
/// say so rather than reporting a paid invoice as PENDING.
#[test]
fn fetch_and_status_truncated_scan_degrades_instead_of_pending() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    let mut sigs = Vec::new();
    let mut txs = HashMap::new();
    // More dust than the ceiling allows, so the real payment is never reached.
    for i in 0..(MAX_VALUE_CHECKS as u64 + 5) {
        let name = format!("SigDust{i}");
        sigs.push(sig_entry(&name, 1000 - i));
        txs.insert(name, tx_units(0, 0));
    }
    sigs.push(sig_entry("SigReal", 1));
    txs.insert("SigReal".to_string(), tx_units(0, 90_000_000));

    let http = PerSigHttp::new(Value::Array(sigs), txs);
    let s = fetch_and_status(&verified_req(Some("90")), &cfg, &http).unwrap();
    assert!(
        s.contains("USDC: SIG OK"),
        "truncated scan must not claim PENDING: {s}"
    );
    assert!(!s.contains("USDC: PENDING"), "{s}");
    assert!(!s.contains("PAID ✅"), "{s}");
    // And the RPC budget was respected.
    assert_eq!(http.fetched.borrow().len(), MAX_VALUE_CHECKS);
}

/// Transactions that disagree on the mint's decimals cannot be summed. Degrade
/// honestly instead of inventing a total.
#[test]
fn fetch_and_status_conflicting_decimals_degrades() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    let nine_decimals = json!({
        "blockTime": 1_700_000_000,
        "meta": {
            "preTokenBalances": [],
            "postTokenBalances": [{
                "mint": MINT, "owner": MERCHANT,
                "uiTokenAmount": { "amount": "90000000000", "decimals": 9 }
            }]
        }
    });
    let http = PerSigHttp::new(
        json!([sig_entry("SigSix", 11), sig_entry("SigNine", 10)]),
        HashMap::from([
            ("SigSix".to_string(), tx_units(0, 45_000_000)),
            ("SigNine".to_string(), nine_decimals),
        ]),
    );
    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();
    assert!(s.contains("USDC: SIG OK"), "{s}");
    assert!(
        !s.contains("PAID ✅"),
        "never PAID from inconsistent data: {s}"
    );
}

#[test]
fn fetch_and_status_degrades_when_tx_missing() {
    let cfg = StatusConfig::from_map(&section(&[
        ("merchant_solana", MERCHANT),
        ("usdc_mint", MINT),
    ]));
    // getTransaction returns null result → cannot verify → SIG OK, never PAID.
    let http = DualMethodHttp {
        sigs: json!([{
            "signature": "SigX",
            "slot": 10,
            "err": null,
            "blockTime": 1_700_000_000,
            "confirmationStatus": "finalized"
        }]),
        tx: Value::Null,
        calls: RefCell::new(Vec::new()),
    };

    let s = fetch_and_status(&verified_req(Some("90")), &cfg, http).unwrap();
    assert!(s.contains("USDC: SIG OK"), "{s}");
    assert!(!s.contains("USDC: PAID"), "{s}");
}
