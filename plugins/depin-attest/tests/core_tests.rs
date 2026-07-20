//! Host tests: mocked RPC, zero network, zero wasm. (Hard requirement.)
use std::cell::RefCell;

use depin_attest::{attest, encode, instructions, rpc, sanitize, CoreError, HttpClient};

struct MockRpc(&'static str);
impl HttpClient for MockRpc {
    fn post_json(&self, _url: &str, _body: &str) -> Result<String, CoreError> {
        Ok(self.0.to_string())
    }
}

/// Mock that returns a canned response AND records the request body it was
/// handed, so tests can assert both the parse and the JSON-RPC request shape.
struct Mock {
    resp: &'static str,
    last_body: RefCell<String>,
}
impl Mock {
    fn new(resp: &'static str) -> Self {
        Self {
            resp,
            last_body: RefCell::new(String::new()),
        }
    }
    fn body(&self) -> String {
        self.last_body.borrow().clone()
    }
}
impl HttpClient for Mock {
    fn post_json(&self, _url: &str, body: &str) -> Result<String, CoreError> {
        *self.last_body.borrow_mut() = body.to_string();
        Ok(self.resp.to_string())
    }
}

#[test]
fn parses_latest_blockhash() {
    let mock = MockRpc(
        r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"blockhash":"EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N","lastValidBlockHeight":1}},"id":1}"#,
    );
    let bh = rpc::get_latest_blockhash(&mock, "http://mock").unwrap();
    assert_eq!(bh, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N");
}

#[test]
fn parses_account_info() {
    let mock = Mock::new(include_str!("fixtures/getAccountInfo.json"));
    let acct = rpc::get_account_info(&mock, "http://mock", "NonceAcct111")
        .unwrap()
        .expect("account should be present");
    assert_eq!(acct.owner, "11111111111111111111111111111111");
    assert_eq!(acct.lamports, 1_447_680);
    assert!(acct.data_base64.starts_with("AAAAAAEAAAA"));
    assert!(!acct.executable);
    // request shape: correct method, base64 encoding, and the pubkey param
    let body = mock.body();
    assert!(body.contains("\"getAccountInfo\""), "body: {body}");
    assert!(
        body.contains("base64"),
        "must request base64 encoding: {body}"
    );
    assert!(
        body.contains("NonceAcct111"),
        "must include the pubkey: {body}"
    );
}

#[test]
fn account_info_is_none_when_account_missing() {
    let mock = Mock::new(include_str!("fixtures/getAccountInfo_null.json"));
    let acct = rpc::get_account_info(&mock, "http://mock", "Missing111").unwrap();
    assert!(
        acct.is_none(),
        "a null value means the account does not exist"
    );
}

#[test]
fn parses_signatures_for_address() {
    let mock = Mock::new(include_str!("fixtures/getSignaturesForAddress.json"));
    let sigs = rpc::get_signatures_for_address(&mock, "http://mock", "DeviceKey11", 10).unwrap();
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].slot, 210);
    assert_eq!(sigs[0].block_time, Some(1_753_000_000));
    assert!(!sigs[0].err, "err: null means success");
    assert_eq!(
        sigs[0].memo.as_deref(),
        Some("[25] v1|DeviceKey|1753000000|42|abcd1234")
    );
    assert_eq!(sigs[1].memo, None, "a null memo becomes None");
    // request shape: the limit is passed through
    let body = mock.body();
    assert!(body.contains("getSignaturesForAddress"), "body: {body}");
    assert!(
        body.contains("\"limit\":10"),
        "limit must be in params: {body}"
    );
}

#[test]
fn parses_transaction_and_extracts_memo() {
    let mock = Mock::new(include_str!("fixtures/getTransaction.json"));
    let tx = rpc::get_transaction(&mock, "http://mock", "5j7sHj")
        .unwrap()
        .expect("transaction should be present");
    assert_eq!(tx.slot, 210);
    assert_eq!(tx.block_time, Some(1_753_000_000));
    assert!(!tx.err);
    let memo = rpc::memo_from_logs(&tx.log_messages).expect("a memo should be in the logs");
    assert_eq!(memo, "v1|DeviceKey|1753000000|42|abcd1234");
    let body = mock.body();
    assert!(body.contains("getTransaction"), "body: {body}");
}

#[test]
fn transaction_is_none_when_not_found() {
    let mock = Mock::new(include_str!("fixtures/getTransaction_null.json"));
    assert!(rpc::get_transaction(&mock, "http://mock", "missing")
        .unwrap()
        .is_none());
}

#[test]
fn memo_from_logs_returns_none_without_a_memo() {
    let logs = vec![
        "Program 11111111111111111111111111111111 invoke [1]".to_string(),
        "Program 11111111111111111111111111111111 success".to_string(),
    ];
    assert!(rpc::memo_from_logs(&logs).is_none());
}

#[test]
fn parses_token_accounts_by_owner() {
    let mock = Mock::new(include_str!("fixtures/getTokenAccountsByOwner.json"));
    let toks = rpc::get_token_accounts_by_owner(&mock, "http://mock", "WalletOwner", "RewardMint")
        .unwrap();
    assert_eq!(toks.len(), 1);
    assert_eq!(toks[0].mint, "RewardMint11111111111111111111111111111111");
    assert_eq!(toks[0].amount_raw, 123_456_789);
    assert_eq!(toks[0].decimals, 6);
    assert!((toks[0].ui_amount - 123.456789).abs() < 1e-9);
    let body = mock.body();
    assert!(body.contains("getTokenAccountsByOwner"), "body: {body}");
    assert!(
        body.contains("jsonParsed"),
        "must request jsonParsed: {body}"
    );
    assert!(body.contains("RewardMint"), "must filter by mint: {body}");
}

#[test]
fn rpc_error_response_becomes_core_error() {
    let mock = Mock::new(include_str!("fixtures/rpcError.json"));
    let err = rpc::get_account_info(&mock, "http://mock", "bad-pubkey").unwrap_err();
    assert!(matches!(err, CoreError::Rpc(_)), "got: {err:?}");
    assert!(
        err.to_string().contains("Invalid params"),
        "message surfaced: {err}"
    );
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn serializes_memo_message_matching_web3js_golden() {
    // The golden vector is generated by @solana/web3.js (scripts/golden/gen.ts).
    // Our hand-rolled encoder must produce byte-identical output.
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden_memo_tx.json")).unwrap();
    let fee_payer = golden["fee_payer"].as_str().unwrap();
    let blockhash = golden["recent_blockhash"].as_str().unwrap();
    let memo = golden["memo"].as_str().unwrap();
    let expected = hex_to_bytes(golden["message_hex"].as_str().unwrap());

    let ix = instructions::memo(memo).unwrap();
    let msg = encode::compile_message(fee_payer, &[ix], blockhash).unwrap();
    let bytes = encode::serialize_message(&msg);

    assert_eq!(
        bytes, expected,
        "serialized message must byte-match web3.js"
    );
    // The full unsigned tx (1 sig placeholder + message) must fit a Solana packet.
    let full_tx_len = 1 + 64 + bytes.len();
    assert!(
        full_tx_len <= 1232,
        "unsigned tx {full_tx_len} bytes exceeds 1232"
    );
}

#[test]
fn serializes_durable_nonce_message_matching_web3js_golden() {
    // AdvanceNonceAccount first, then Memo — exercises multi-account ordering.
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden_nonce_memo_tx.json")).unwrap();
    let fee_payer = golden["fee_payer"].as_str().unwrap();
    let blockhash = golden["recent_blockhash"].as_str().unwrap();
    let nonce_account = golden["nonce_account"].as_str().unwrap();
    let nonce_authority = golden["nonce_authority"].as_str().unwrap();
    let memo = golden["memo"].as_str().unwrap();
    let expected = hex_to_bytes(golden["message_hex"].as_str().unwrap());

    let advance = instructions::advance_nonce_account(nonce_account, nonce_authority).unwrap();
    let memo_ix = instructions::memo(memo).unwrap();
    let msg = encode::compile_message(fee_payer, &[advance, memo_ix], blockhash).unwrap();
    let bytes = encode::serialize_message(&msg);

    assert_eq!(
        bytes, expected,
        "durable-nonce message must byte-match web3.js"
    );
}

#[test]
fn memo_rejects_oversize_data() {
    let big = "x".repeat(567);
    assert!(
        instructions::memo(&big).is_err(),
        "memo over 566 bytes must be rejected"
    );
    assert!(instructions::memo(&"x".repeat(566)).is_ok());
}

#[test]
fn parses_nonce_from_attestation_memo() {
    // Signature memos arrive with a "[len] " prefix; the payload is v1|dev|ts|nonce|hash.
    assert_eq!(
        attest::parse_memo_nonce("[25] v1|DeviceKey|1753000000|42|abcd1234"),
        Some(42)
    );
    assert_eq!(attest::parse_memo_nonce("v1|Dev|1|7|hash"), Some(7));
    assert_eq!(attest::parse_memo_nonce("just some unrelated memo"), None);
}

#[test]
fn derives_latest_nonce_from_chain() {
    // The signatures fixture has one memo with nonce 42 and one null memo.
    let mock = MockRpc(include_str!("fixtures/getSignaturesForAddress.json"));
    let n = attest::latest_nonce(&mock, "http://mock", "DeviceKey11").unwrap();
    assert_eq!(n, 42, "newest attestation nonce on chain");
}

#[test]
fn latest_nonce_is_zero_when_no_attestations() {
    let mock = MockRpc(r#"{"jsonrpc":"2.0","result":[],"id":1}"#);
    assert_eq!(
        attest::latest_nonce(&mock, "http://mock", "New1111").unwrap(),
        0
    );
}

#[test]
fn compact_u16_golden_vectors() {
    for (n, expect) in [
        (0u16, vec![0u8]),
        (5, vec![5]),
        (127, vec![127]),
        (128, vec![0x80, 0x01]),
        (16384, vec![0x80, 0x80, 0x01]),
    ] {
        let mut out = vec![];
        encode::compact_u16(n, &mut out);
        assert_eq!(out, expect, "n={n}");
    }
}

#[test]
fn attestation_is_deterministic_and_replay_guarded() {
    let a = attest::build(23.5, 1_753_000_000, 42);
    let b = attest::build(23.5, 1_753_000_000, 42);
    assert_eq!(a.hash_hex, b.hash_hex);
    assert!(attest::check_nonce(42, 42).is_err());
    assert!(attest::check_nonce(42, 43).is_ok());
}

#[test]
fn sanitize_fails_closed_on_injection() {
    // Canned strings live in a fixture so the PLAN.md I2 CHECK is runnable verbatim.
    let canned = include_str!("fixtures/injections.txt");
    let strings: Vec<&str> = canned
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(
        !strings.is_empty(),
        "fixture must contain injection strings"
    );
    for s in &strings {
        assert!(
            sanitize::check_text("label", s, 256).is_err(),
            "should reject as instruction-like: {s}"
        );
    }
    assert!(sanitize::check_text("label", "greenhouse-sensor-04", 128).is_ok());
    assert!(sanitize::check_text("label", "temp reading from balcony sensor", 128).is_ok());
}
