use std::collections::HashMap;

use serde_json::{json, Value};
use solana_payment_verify::verify::{
    parse_execute_args, verify_rpc_response, AmountPolicy, PaymentExpectation, RpcConfig,
    VerificationStatus,
};

fn key(seed: u8) -> String {
    bs58::encode([seed; 32]).into_string()
}

fn signature(seed: u8) -> String {
    bs58::encode([seed; 64]).into_string()
}

fn expectation(
    asset: &str,
    amount: &str,
    policy: AmountPolicy,
    reference: Option<String>,
    memo: Option<&str>,
) -> PaymentExpectation {
    PaymentExpectation::new(
        signature(9),
        key(2),
        amount.to_string(),
        asset.to_string(),
        reference,
        memo.map(str::to_string),
        policy,
    )
    .expect("valid expectation")
}

fn sol_rpc(pre: u64, post: u64, reference: Option<&str>, memo: Option<&str>) -> Value {
    let mut account_keys = vec![
        json!({"pubkey": key(1), "signer": true, "writable": true}),
        json!({"pubkey": key(2), "signer": false, "writable": true}),
    ];
    if let Some(reference) = reference {
        account_keys.push(json!({"pubkey": reference, "signer": false, "writable": false}));
    }
    let mut instructions = Vec::new();
    if let Some(memo) = memo {
        instructions.push(json!({
            "program": "spl-memo",
            "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
            "parsed": memo
        }));
    }
    json!({
        "jsonrpc": "2.0",
        "result": {
            "slot": 321,
            "meta": {
                "err": null,
                "preBalances": [5_000_000_000_u64, pre],
                "postBalances": [4_999_995_000_u64, post],
                "preTokenBalances": [],
                "postTokenBalances": [],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": account_keys,
                    "instructions": instructions
                },
                "signatures": [signature(9)]
            }
        }
    })
}

fn spl_rpc(mint: &str, pre: u64, post: u64, decimals: u8, reference: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "result": {
            "slot": 654,
            "meta": {
                "err": null,
                "preBalances": [5_000_000_000_u64, 2_039_280_u64, 0_u64],
                "postBalances": [4_999_995_000_u64, 2_039_280_u64, 0_u64],
                "preTokenBalances": [{
                    "accountIndex": 1,
                    "mint": mint,
                    "owner": key(2),
                    "uiTokenAmount": {"amount": pre.to_string(), "decimals": decimals}
                }],
                "postTokenBalances": [{
                    "accountIndex": 1,
                    "mint": mint,
                    "owner": key(2),
                    "uiTokenAmount": {"amount": post.to_string(), "decimals": decimals}
                }],
                "innerInstructions": []
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": key(1), "signer": true, "writable": true},
                        {"pubkey": key(2), "signer": false, "writable": true},
                        {"pubkey": reference, "signer": false, "writable": false}
                    ],
                    "instructions": []
                },
                "signatures": [signature(9)]
            }
        }
    })
}

#[test]
fn verifies_exact_sol_payment_with_reference_and_memo() {
    let reference = key(4);
    let expected = expectation(
        "SOL",
        "1.25",
        AmountPolicy::Exact,
        Some(reference.clone()),
        Some("invoice-1042"),
    );
    let rpc = sol_rpc(
        100_000_000,
        1_350_000_000,
        Some(&reference),
        Some("invoice-1042"),
    );

    let report = verify_rpc_response(&expected, &rpc);

    assert!(report.valid);
    assert_eq!(report.status, VerificationStatus::Paid);
    assert_eq!(report.observed_amount.as_deref(), Some("1.25"));
    assert_eq!(report.reference_matched, Some(true));
    assert_eq!(report.memo_matched, Some(true));
}

#[test]
fn exact_policy_rejects_underpayment_and_overpayment() {
    let expected = expectation("SOL", "1", AmountPolicy::Exact, None, None);

    let under = verify_rpc_response(&expected, &sol_rpc(0, 999_999_999, None, None));
    assert!(!under.valid);
    assert!(under.checks.contains(&"amount_underpaid".to_string()));

    let over = verify_rpc_response(&expected, &sol_rpc(0, 1_000_000_001, None, None));
    assert!(!over.valid);
    assert!(over
        .checks
        .contains(&"amount_overpaid_exact_policy".to_string()));
}

#[test]
fn at_least_policy_accepts_overpayment() {
    let expected = expectation("SOL", "1", AmountPolicy::AtLeast, None, None);
    let report = verify_rpc_response(&expected, &sol_rpc(0, 1_100_000_000, None, None));
    assert!(report.valid);
    assert_eq!(report.observed_amount.as_deref(), Some("1.1"));
}

#[test]
fn verifies_spl_payment_from_raw_balance_deltas() {
    let mint = key(3);
    let reference = key(4);
    let expected = expectation(
        &mint,
        "12.5",
        AmountPolicy::Exact,
        Some(reference.clone()),
        None,
    );
    let rpc = spl_rpc(&mint, 1_000_000, 13_500_000, 6, &reference);

    let report = verify_rpc_response(&expected, &rpc);

    assert!(report.valid);
    assert_eq!(report.status, VerificationStatus::Paid);
    assert_eq!(report.observed_amount.as_deref(), Some("12.5"));
}

#[test]
fn missing_reference_or_wrong_memo_fails_closed() {
    let reference = key(4);
    let expected = expectation(
        "SOL",
        "1",
        AmountPolicy::Exact,
        Some(reference),
        Some("invoice-7"),
    );
    let report = verify_rpc_response(
        &expected,
        &sol_rpc(0, 1_000_000_000, None, Some("invoice-8")),
    );

    assert!(!report.valid);
    assert_eq!(report.status, VerificationStatus::Mismatch);
    assert_eq!(report.reference_matched, Some(false));
    assert_eq!(report.memo_matched, Some(false));
}

#[test]
fn failed_and_missing_transactions_are_never_paid() {
    let expected = expectation("SOL", "1", AmountPolicy::Exact, None, None);
    let mut failed_rpc = sol_rpc(0, 1_000_000_000, None, None);
    failed_rpc["result"]["meta"]["err"] = json!({"InstructionError": [0, "Custom"]});

    let failed = verify_rpc_response(&expected, &failed_rpc);
    assert_eq!(failed.status, VerificationStatus::Failed);
    assert!(!failed.valid);

    let missing = verify_rpc_response(&expected, &json!({"jsonrpc":"2.0","result":null}));
    assert_eq!(missing.status, VerificationStatus::NotFound);
    assert!(!missing.valid);
}

#[test]
fn recipient_cannot_be_the_fee_payer() {
    let expected = PaymentExpectation::new(
        signature(9),
        key(1),
        "1".to_string(),
        "SOL".to_string(),
        None,
        None,
        AmountPolicy::Exact,
    )
    .expect("valid expectation");
    let report = verify_rpc_response(&expected, &sol_rpc(0, 1_000_000_000, None, None));
    assert!(!report.valid);
    assert!(report
        .checks
        .contains(&"recipient_is_fee_payer".to_string()));
}

#[test]
fn invalid_precision_is_reported_without_rounding() {
    let mint = key(3);
    let reference = key(4);
    let expected = expectation(
        &mint,
        "1.0000001",
        AmountPolicy::Exact,
        Some(reference.clone()),
        None,
    );
    let report = verify_rpc_response(&expected, &spl_rpc(&mint, 0, 1_000_000, 6, &reference));
    assert!(!report.valid);
    assert!(report
        .checks
        .iter()
        .any(|check| check.starts_with("amount_precision_invalid:")));
}

#[test]
fn malformed_rpc_shape_fails_closed() {
    let expected = expectation("SOL", "1", AmountPolicy::Exact, None, None);
    let report = verify_rpc_response(&expected, &json!({"jsonrpc":"2.0","error":{}}));
    assert_eq!(report.status, VerificationStatus::InvalidResponse);
    assert!(!report.valid);
}

#[test]
fn prompt_injection_style_override_fields_are_rejected() {
    let input = json!({
        "signature": signature(9),
        "recipient": key(2),
        "amount": "10",
        "asset": "SOL",
        "recipient_override": key(8),
        "ignore_previous_invoice": true
    });
    let error = parse_execute_args(&input.to_string()).expect_err("unknown fields fail closed");
    assert!(error.contains("unknown field"));
}

#[test]
fn invalid_addresses_amounts_and_signatures_are_rejected() {
    let invalid_signature = PaymentExpectation::new(
        "not-a-signature".to_string(),
        key(2),
        "1".to_string(),
        "SOL".to_string(),
        None,
        None,
        AmountPolicy::Exact,
    );
    assert!(invalid_signature.is_err());

    let invalid_amount = PaymentExpectation::new(
        signature(9),
        key(2),
        "-1".to_string(),
        "SOL".to_string(),
        None,
        None,
        AmountPolicy::Exact,
    );
    assert!(invalid_amount.is_err());
}

#[test]
fn rpc_config_defaults_are_safe_and_operator_values_are_bounded() {
    let defaults = RpcConfig::from_section(&HashMap::new()).expect("safe defaults");
    assert_eq!(defaults.commitment, "finalized");
    assert!(defaults.rpc_url.starts_with("https://"));

    let invalid = HashMap::from([("rpc_url".to_string(), "http://169.254.169.254".to_string())]);
    assert!(RpcConfig::from_section(&invalid).is_err());

    for value in [
        "https://user:secret@rpc.example.com",
        "https://localhost",
        "https://rpc.local",
        "https://127.0.0.1",
        "https://10.0.0.8",
        "https://169.254.169.254",
        "https://192.0.2.1",
        "https://[::1]",
        "https://[fc00::1]",
        "https://[2001:db8::1]",
    ] {
        let section = HashMap::from([("rpc_url".to_string(), value.to_string())]);
        assert!(
            RpcConfig::from_section(&section).is_err(),
            "unsafe RPC URL was accepted: {value}"
        );
    }

    for value in [
        "https://api.mainnet-beta.solana.com",
        "https://solana-rpc.publicnode.com",
        "https://8.8.8.8",
        "https://[2606:4700:4700::1111]",
    ] {
        let section = HashMap::from([("rpc_url".to_string(), value.to_string())]);
        assert!(
            RpcConfig::from_section(&section).is_ok(),
            "public RPC URL was rejected: {value}"
        );
    }

    let too_long = HashMap::from([("timeout_secs".to_string(), "31".to_string())]);
    assert!(RpcConfig::from_section(&too_long).is_err());
}

#[test]
fn malicious_token_decimals_fail_closed_without_panicking() {
    let mint = key(7);
    let expected = expectation(&mint, "1", AmountPolicy::Exact, None, None);

    for decimals in [20, u8::MAX] {
        let response = spl_rpc(&mint, 0, 1, decimals, &key(3));
        let report = verify_rpc_response(&expected, &response);
        assert_eq!(report.status, VerificationStatus::InvalidResponse);
        assert!(!report.valid);
        assert!(report
            .checks
            .contains(&"token_decimals_out_of_range".to_string()));
    }
}
