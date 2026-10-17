//! Host tests for the payment-watch core: mocked RPC replaying captured
//! devnet response shapes, no network, no wasm toolchain.

use std::collections::BTreeMap;

use payment_watch::watcher::{run, Lookups, WatchError};

const REFERENCE: &str = "SysvarC1ock11111111111111111111111111111111";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIP: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";

fn cfg() -> BTreeMap<String, String> {
    [(
        "rpc_url".to_string(),
        "https://api.devnet.solana.com".to_string(),
    )]
    .into()
}

fn args(extra: &[(&str, &str)]) -> String {
    let mut v = serde_json::json!({ "reference": REFERENCE, "__config": cfg() });
    for (k, val) in extra {
        v[*k] = serde_json::json!(val);
    }
    v.to_string()
}

struct MockRpc {
    responses: Vec<(&'static str, String)>,
    calls: Vec<String>,
}

impl MockRpc {
    fn new(responses: Vec<(&'static str, String)>) -> Self {
        Self {
            responses,
            calls: Vec::new(),
        }
    }
}

impl Lookups for MockRpc {
    fn rpc(&mut self, body: &str) -> Result<String, String> {
        self.calls.push(body.to_string());
        for (pat, resp) in &self.responses {
            if body.contains(pat) {
                return Ok(resp.clone());
            }
        }
        Err(format!("mock has no response for: {body}"))
    }
}

fn sigs_resp(entries: &[(&str, bool)]) -> String {
    let list: Vec<String> = entries
        .iter()
        .map(|(sig, ok)| {
            format!(
                r#"{{"signature":"{sig}","slot":100,"err":{},"memo":null,"blockTime":1700000000,"confirmationStatus":"finalized"}}"#,
                if *ok { "null" } else { r#"{"InstructionError":[0,"Custom"]}"# }
            )
        })
        .collect();
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":[{}]}}"#,
        list.join(",")
    )
}

fn tx_resp(owner: &str, mint: &str, pre: u64, post: u64, decimals: u8) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"meta":{{"err":null,
        "preTokenBalances":[{{"accountIndex":1,"mint":"{mint}","owner":"{owner}","uiTokenAmount":{{"amount":"{pre}","decimals":{decimals},"uiAmountString":"x"}}}}],
        "postTokenBalances":[{{"accountIndex":1,"mint":"{mint}","owner":"{owner}","uiTokenAmount":{{"amount":"{post}","decimals":{decimals},"uiAmountString":"x"}}}}]
        }}}}}}"#
    )
}

#[test]
fn paid_when_expected_amount_arrives() {
    let mut rpc = MockRpc::new(vec![
        ("getSignaturesForAddress", sigs_resp(&[("sigA", true)])),
        ("getTransaction", tx_resp(RECIP, USDC, 0, 25_000_000, 6)),
    ]);
    let out = run(
        &args(&[
            ("expected_amount", "25"),
            ("mint", USDC),
            ("recipient", RECIP),
        ]),
        &mut rpc,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["paid"], true);
    let s = v["summary"].as_str().unwrap();
    assert!(
        s.contains("PAID") && s.contains("25") && s.contains("finalized"),
        "{s}"
    );
    assert_eq!(v["signature"], "sigA");
}

#[test]
fn not_seen_when_no_signatures() {
    let mut rpc = MockRpc::new(vec![(
        "getSignaturesForAddress",
        r#"{"jsonrpc":"2.0","id":1,"result":[]}"#.to_string(),
    )]);
    let out = run(&args(&[]), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["paid"], false);
    assert!(v["summary"].as_str().unwrap().contains("NOT SEEN"));
    assert_eq!(
        rpc.calls.len(),
        1,
        "no getTransaction when nothing to inspect"
    );
}

#[test]
fn underpayment_not_satisfied() {
    let mut rpc = MockRpc::new(vec![
        ("getSignaturesForAddress", sigs_resp(&[("sigA", true)])),
        ("getTransaction", tx_resp(RECIP, USDC, 0, 10_000_000, 6)),
    ]);
    let out = run(
        &args(&[("expected_amount", "25"), ("mint", USDC)]),
        &mut rpc,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["paid"], false);
    assert!(
        v["summary"].as_str().unwrap().contains("received 10"),
        "{}",
        v["summary"]
    );
}

#[test]
fn wrong_mint_not_satisfied() {
    let mut rpc = MockRpc::new(vec![
        ("getSignaturesForAddress", sigs_resp(&[("sigA", true)])),
        (
            "getTransaction",
            tx_resp(
                RECIP,
                "So11111111111111111111111111111111111111112",
                0,
                25_000_000,
                9,
            ),
        ),
    ]);
    let out = run(
        &args(&[("expected_amount", "25"), ("mint", USDC)]),
        &mut rpc,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["paid"], false);
}

#[test]
fn wrong_recipient_not_satisfied() {
    let mut rpc = MockRpc::new(vec![
        ("getSignaturesForAddress", sigs_resp(&[("sigA", true)])),
        (
            "getTransaction",
            tx_resp("someoneElse", USDC, 0, 25_000_000, 6),
        ),
    ]);
    let out = run(&args(&[("recipient", RECIP)]), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["paid"], false);
    assert!(v["summary"]
        .as_str()
        .unwrap()
        .contains("expected recipient"));
}

#[test]
fn failed_transactions_skipped() {
    // Newest sig failed on-chain; older one succeeded. The failed one must
    // not count as payment.
    let mut rpc = MockRpc::new(vec![
        (
            "getSignaturesForAddress",
            sigs_resp(&[("sigBad", false), ("sigGood", true)]),
        ),
        ("sigGood", tx_resp(RECIP, USDC, 0, 25_000_000, 6)),
    ]);
    let out = run(
        &args(&[("expected_amount", "25"), ("mint", USDC)]),
        &mut rpc,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["paid"], true);
    assert_eq!(v["signature"], "sigGood");
    assert!(
        !rpc.calls.iter().any(|c| c.contains("sigBad")),
        "err'd sig never inspected"
    );
}

#[test]
fn no_transfer_in_tx_not_satisfied() {
    let mut rpc = MockRpc::new(vec![
        ("getSignaturesForAddress", sigs_resp(&[("sigA", true)])),
        (
            "getTransaction",
            r#"{"jsonrpc":"2.0","id":1,"result":{"meta":{"err":null,"preTokenBalances":[],"postTokenBalances":[]}}}"#.to_string(),
        ),
    ]);
    let out = run(&args(&[]), &mut rpc).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["paid"], false);
    assert!(v["summary"].as_str().unwrap().contains("no token transfer"));
}

// ---------- fail-closed paths ----------

#[test]
fn amount_without_mint_rejected() {
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&args(&[("expected_amount", "25")]), &mut rpc).unwrap_err();
    assert!(matches!(err, WatchError::BadArgs(_)));
    assert!(rpc.calls.is_empty());
}

#[test]
fn bad_reference_rejected_before_network() {
    let mut v: serde_json::Value = serde_json::from_str(&args(&[])).unwrap();
    v["reference"] = serde_json::json!("tooshort");
    let mut rpc = MockRpc::new(vec![]);
    assert!(run(&v.to_string(), &mut rpc).is_err());
    assert!(rpc.calls.is_empty());
}

#[test]
fn injected_rpc_url_arg_rejected() {
    // deny_unknown_fields: a prompt-injected rpc_url argument cannot reroute
    // the lookup to an attacker's endpoint.
    let mut v: serde_json::Value = serde_json::from_str(&args(&[])).unwrap();
    v["rpc_url"] = serde_json::json!("https://evil.example");
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&v.to_string(), &mut rpc).unwrap_err();
    assert!(matches!(err, WatchError::BadArgs(_)));
}

#[test]
fn unknown_config_key_fails_closed() {
    let mut v: serde_json::Value = serde_json::from_str(&args(&[])).unwrap();
    v["__config"]["rcp_url"] = serde_json::json!("https://typo.example");
    let mut rpc = MockRpc::new(vec![]);
    let err = run(&v.to_string(), &mut rpc).unwrap_err();
    assert!(err.to_string().contains("unknown config key"));
}

#[test]
fn http_rpc_url_rejected() {
    let mut v: serde_json::Value = serde_json::from_str(&args(&[])).unwrap();
    v["__config"]["rpc_url"] = serde_json::json!("http://insecure.example");
    let mut rpc = MockRpc::new(vec![]);
    assert!(run(&v.to_string(), &mut rpc).is_err());
}

#[test]
fn rpc_error_propagates() {
    let mut rpc = MockRpc::new(vec![(
        "getSignaturesForAddress",
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"behind"}}"#.to_string(),
    )]);
    assert!(matches!(
        run(&args(&[]), &mut rpc).unwrap_err(),
        WatchError::Rpc(_)
    ));
}
