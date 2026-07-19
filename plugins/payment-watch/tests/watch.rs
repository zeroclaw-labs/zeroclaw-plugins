//! Host-run tests over the pure watch core against a mock RPC — no wasm
//! toolchain, no live network.

use std::collections::HashMap;

use payment_watch::watch::{check_payment, Status, WatchArgs, WatchConfig};
use serde_json::{json, Value};
use zeroclaw_solana_core::rpc::HttpTransport;

const RECIPIENT: &str = "Axesf2T7E49DGymaYyYPs5CivKE5JpzgLk5JCfASWHxE";
const PAYER: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const SIG: &str = "3aDUz5M5vp7vrkjT36G75pqr5HCmaSqyieEUCJ6MZg4BAKD";

/// Mock node: one signature for the recipient, and a getTransaction whose SOL
/// balance delta credits the recipient `lamports`.
struct MockRpc {
    sigs: Vec<Value>,
    tx_credit_lamports: u64,
}

impl MockRpc {
    fn with_payment(lamports: u64) -> Self {
        Self {
            sigs: vec![json!({"signature": SIG, "slot": 1u64, "err": Value::Null,
                              "confirmationStatus": "confirmed"})],
            tx_credit_lamports: lamports,
        }
    }
    fn no_payments() -> Self {
        Self {
            sigs: vec![],
            tx_credit_lamports: 0,
        }
    }
    fn failed_payment() -> Self {
        Self {
            sigs: vec![json!({"signature": SIG, "slot": 1u64,
                              "err": {"InstructionError": [0, "Custom"]},
                              "confirmationStatus": "confirmed"})],
            tx_credit_lamports: 0,
        }
    }
}

impl HttpTransport for MockRpc {
    fn post_json(&self, _url: &str, body: &str) -> Result<String, String> {
        let req: Value = serde_json::from_str(body).unwrap();
        let result = match req["method"].as_str().unwrap() {
            "getSignaturesForAddress" => json!(self.sigs),
            "getTransaction" => {
                // recipient at index 1, payer at index 0
                let credit = self.tx_credit_lamports;
                json!({
                    "meta": {
                        "err": Value::Null,
                        "preBalances": [10_000_000_000u64, 2_000_000u64],
                        "postBalances": [10_000_000_000u64 - credit - 5000, 2_000_000u64 + credit],
                        "preTokenBalances": [],
                        "postTokenBalances": []
                    },
                    "transaction": {"message": {"accountKeys": [
                        {"pubkey": PAYER}, {"pubkey": RECIPIENT}
                    ]}}
                })
            }
            other => return Err(format!("unexpected method {other}")),
        };
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string())
    }
}

fn cfg() -> WatchConfig {
    let mut m = HashMap::new();
    m.insert("recipient".into(), RECIPIENT.to_string());
    WatchConfig::from_section(&m).unwrap()
}
fn args(amount: Option<&str>, token: Option<&str>) -> WatchArgs {
    WatchArgs {
        amount: amount.map(str::to_string),
        token: token.map(str::to_string),
        label: Some("invoice #412".to_string()),
    }
}

#[test]
fn detects_incoming_sol_payment() {
    // 0.1 SOL = 100_000_000 lamports credited to the recipient.
    let rpc = MockRpc::with_payment(100_000_000);
    let res = check_payment(&rpc, &args(None, Some("SOL")), &cfg()).unwrap();
    assert_eq!(res.status, Status::Paid);
    assert!(res.text.contains("Payment received"));
    assert!(res.text.contains("0.1 SOL"));
    assert!(res.text.contains(SIG));
    assert!(res.text.contains("solscan.io/tx/"));
    assert!(res.text.contains("invoice #412"));
}

#[test]
fn matches_expected_amount() {
    let rpc = MockRpc::with_payment(100_000_000); // 0.1 SOL
                                                  // expecting exactly 0.1 → paid
    assert_eq!(
        check_payment(&rpc, &args(Some("0.1"), Some("SOL")), &cfg())
            .unwrap()
            .status,
        Status::Paid
    );
    // expecting 1 SOL but only 0.1 arrived → pending
    assert_eq!(
        check_payment(&rpc, &args(Some("1"), Some("SOL")), &cfg())
            .unwrap()
            .status,
        Status::Pending
    );
}

#[test]
fn no_signatures_is_pending() {
    let res = check_payment(&MockRpc::no_payments(), &args(None, Some("SOL")), &cfg()).unwrap();
    assert_eq!(res.status, Status::Pending);
    assert!(res.text.contains("Not paid yet"));
}

#[test]
fn failed_transaction_is_not_paid() {
    let res = check_payment(&MockRpc::failed_payment(), &args(None, Some("SOL")), &cfg()).unwrap();
    assert_eq!(res.status, Status::Pending);
}

#[test]
fn config_requires_recipient() {
    assert!(WatchConfig::from_section(&HashMap::new())
        .unwrap_err()
        .contains("recipient"));
}

#[test]
fn rejects_oversized_inputs() {
    let mut a = args(None, Some("SOL"));
    a.label = Some("x".repeat(5000));
    assert!(check_payment(&MockRpc::with_payment(1), &a, &cfg())
        .unwrap_err()
        .contains("too long"));
    let b = args(Some(&"9".repeat(5000)), Some("SOL"));
    assert!(check_payment(&MockRpc::with_payment(1), &b, &cfg())
        .unwrap_err()
        .contains("too long"));
}

#[test]
fn unlisted_token_is_refused() {
    let res = check_payment(&MockRpc::with_payment(1), &args(None, Some("EVIL")), &cfg());
    assert!(res.unwrap_err().contains("allowlist"));
}
