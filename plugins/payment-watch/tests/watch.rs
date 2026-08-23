//! Host integration tests for the payment-watch plugin.
//!
//! These tests exercise the pure [`evaluate_payment`] function without
//! any RPC dependency. They verify JSON formatting, status logic, and
//! edge cases for all three payment states.

use payment_watch::watch::evaluate_payment;

/// CONFIRMED: balance exactly equals expected amount.
#[test]
fn test_integration_confirmed_exact() {
    let json = evaluate_payment(
        "Addr1Exact111111111111111111111111111111111",
        2.0,
        2.0,
        "SOL",
        None,
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        val["status"], "CONFIRMED",
        "exact match should be CONFIRMED"
    );
    assert_eq!(
        val["address"],
        "Addr1Exact111111111111111111111111111111111"
    );
    assert_eq!(val["balance"].as_f64(), Some(2.0));
    assert_eq!(val["expected"].as_f64(), Some(2.0));
    assert_eq!(val["mint"], "SOL");
}

/// CONFIRMED: balance exceeds expected (overpayment).
#[test]
fn test_integration_confirmed_overpayment() {
    let json = evaluate_payment(
        "Addr2Over111111111111111111111111111111111",
        10.5,
        5.0,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        None,
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        val["status"], "CONFIRMED",
        "overpayment should be CONFIRMED"
    );
    assert_eq!(val["balance"].as_f64(), Some(10.5));
    assert_eq!(
        val["mint"],
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    );
}

/// PENDING: partial balance received.
#[test]
fn test_integration_pending_partial() {
    let json = evaluate_payment(
        "Addr3Part111111111111111111111111111111111",
        0.25,
        1.0,
        "SOL",
        None,
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        val["status"], "PENDING",
        "partial balance should be PENDING"
    );
    assert_eq!(val["balance"].as_f64(), Some(0.25));
    assert_eq!(val["expected"].as_f64(), Some(1.0));
    assert_eq!(val["shortfall"].as_f64(), Some(0.75));
}

/// PENDING: very small partial payment (dust).
#[test]
fn test_integration_pending_dust() {
    let json = evaluate_payment(
        "Addr4Dust1111111111111111111111111111111111",
        0.000001,
        1.0,
        "SOL",
        None,
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(val["status"], "PENDING", "dust should be PENDING");
    assert!(val["shortfall"].as_f64().unwrap() < 1.0);
}

/// NOT_FOUND: zero balance.
#[test]
fn test_integration_not_found() {
    let json = evaluate_payment(
        "Addr5Zero111111111111111111111111111111111",
        0.0,
        1.0,
        "SOL",
        None,
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        val["status"], "NOT_FOUND",
        "zero balance should be NOT_FOUND"
    );
    assert!(
        val.get("balance").is_none(),
        "NOT_FOUND should omit balance"
    );
    assert!(
        val.get("shortfall").is_none(),
        "NOT_FOUND should omit shortfall"
    );
}

/// CONFIRMED with reference key.
#[test]
fn test_integration_confirmed_with_reference() {
    let json = evaluate_payment(
        "Addr6Ref11111111111111111111111111111111111",
        3.0,
        3.0,
        "SOL",
        Some("refKey_abc123"),
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(val["status"], "CONFIRMED");
    assert_eq!(val["reference"], "refKey_abc123");
}

/// PENDING with reference key.
#[test]
fn test_integration_pending_with_reference() {
    let json = evaluate_payment(
        "Addr7RefPart11111111111111111111111111111111",
        0.75,
        2.0,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        Some("refKey_def456"),
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(val["status"], "PENDING");
    assert_eq!(val["reference"], "refKey_def456");
    assert_eq!(val["shortfall"].as_f64(), Some(1.25));
}

/// NOT_FOUND with reference key.
#[test]
fn test_integration_not_found_with_reference() {
    let json = evaluate_payment(
        "Addr8ZeroRef11111111111111111111111111111111",
        0.0,
        1.0,
        "SOL",
        Some("refKey_ghi789"),
    );
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(val["status"], "NOT_FOUND");
    assert_eq!(val["reference"], "refKey_ghi789");
}

/// All three statuses produce valid JSON that deserializes correctly.
#[test]
fn test_integration_all_statuses_valid_json() {
    let cases = vec![
        evaluate_payment("a", 1.0, 1.0, "SOL", None),
        evaluate_payment("b", 0.5, 1.0, "SOL", None),
        evaluate_payment("c", 0.0, 1.0, "SOL", None),
        evaluate_payment("d", 1.0, 1.0, "SOL", Some("ref")),
        evaluate_payment(
            "e",
            0.5,
            1.0,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            Some("ref"),
        ),
        evaluate_payment("f", 0.0, 1.0, "SOL", Some("ref")),
    ];

    for (i, json) in cases.iter().enumerate() {
        let val: serde_json::Value = serde_json::from_str(json)
            .unwrap_or_else(|e| panic!("case {i}: invalid JSON: {e} - got: {json}"));
        assert!(
            val["status"].as_str().is_some(),
            "case {i}: missing status field"
        );
        assert!(
            ["CONFIRMED", "PENDING", "NOT_FOUND"]
                .contains(&val["status"].as_str().unwrap()),
            "case {i}: unexpected status: {}",
            val["status"]
        );
    }
}

/// Very large amounts (e.g. 10k+ SOL) still produce valid JSON.
#[test]
fn test_integration_large_amounts() {
    let json = evaluate_payment("large", 99999.999999, 50000.0, "SOL", None);
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(val["status"], "CONFIRMED");
    assert_eq!(val["balance"].as_f64(), Some(99999.999999));
}

/// Zero expected amount should immediately be CONFIRMED.
#[test]
fn test_integration_zero_expected() {
    let json = evaluate_payment("zero", 0.0, 0.0, "SOL", None);
    let val: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(
        val["status"], "CONFIRMED",
        "zero expected with zero balance is confirmed"
    );
}