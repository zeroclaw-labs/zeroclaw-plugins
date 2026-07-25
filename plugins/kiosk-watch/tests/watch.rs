//! Host tests for the kiosk-watch core, driven exactly as the wasm shim drives
//! it: config from a flat section, strict args, RPC mocked via a one-method
//! transport. Plain `cargo test` — NO live network. Every fail-closed behavior
//! (and above all "RPC failure is NEVER Paid") is a test.

use std::cell::Cell;

use kiosk_core::rpc::{RpcError, RpcTransport};
use kiosk_watch::watch::{
    verify_heartbeat, verify_payment, Heartbeat, Verdict, WatchArgs, WatchConfig, WatchError,
    DEFAULT_USDC_MINT,
};

// Valid 32-byte base58 pubkeys reused across cases.
const MERCHANT: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
const REFERENCE: &str = "11111111111111111111111111111111";
const DEVICE: &str = "So11111111111111111111111111111111111111112";
const OTHER_MINT: &str = "So11111111111111111111111111111111111111112";
const OTHER_OWNER: &str = "So11111111111111111111111111111111111111112";
const RPC: &str = "https://api.devnet.solana.com";
const NOW: u64 = 1_000_000;

// ── Mock transport: dispatch by RPC method, return canned bodies or an error ──

struct Mock {
    sig: Result<String, RpcError>,
    tx: Result<String, RpcError>,
    sig_calls: Cell<u32>,
    tx_calls: Cell<u32>,
}

impl Mock {
    fn new(sig: Result<String, RpcError>, tx: Result<String, RpcError>) -> Self {
        Self {
            sig,
            tx,
            sig_calls: Cell::new(0),
            tx_calls: Cell::new(0),
        }
    }
    fn sigs(body: &str) -> Self {
        Mock::new(Ok(wrap(body)), Ok(wrap("null")))
    }
    fn full(sig_body: &str, tx_body: &str) -> Self {
        Mock::new(Ok(wrap(sig_body)), Ok(wrap(tx_body)))
    }
}

impl RpcTransport for Mock {
    fn send(&self, request_body: &str) -> Result<String, RpcError> {
        if request_body.contains("getSignaturesForAddress") {
            self.sig_calls.set(self.sig_calls.get() + 1);
            self.sig.clone()
        } else if request_body.contains("getTransaction") {
            self.tx_calls.set(self.tx_calls.get() + 1);
            self.tx.clone()
        } else {
            Err(RpcError::Transport("unexpected method".into()))
        }
    }
}

/// Wrap a bare `result` value in a JSON-RPC envelope, as the node would.
fn wrap(result_json: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_json}}}"#)
}

fn cfg() -> WatchConfig {
    WatchConfig::from_section(
        &[
            ("rpc_url", RPC),
            ("merchant_address", MERCHANT),
            // usdc_mint defaults to mainnet USDC; finality defaults to "confirmed"
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
    )
    .unwrap()
}

fn pay_args() -> WatchArgs {
    WatchArgs {
        reference: Some(REFERENCE.into()),
        expected_amount: Some("1.5".into()),
        window_s: Some(300),
        ..Default::default()
    }
}

// One signature referencing the charge, `age` seconds before NOW.
fn one_sig(age: u64) -> String {
    let bt = NOW - age;
    format!(
        r#"[{{"signature":"5xSig","slot":100,"err":null,"blockTime":{bt},"confirmationStatus":"confirmed"}}]"#
    )
}

// A getTransaction result crediting `amount` base units of `mint` to `owner`,
// with the reference present in accountKeys and meta.err = `err`.
fn tx(owner: &str, mint: &str, amount: &str, err: &str) -> String {
    format!(
        r#"{{
          "slot":100,"blockTime":{bt},
          "meta":{{"err":{err},
            "preTokenBalances":[{{"accountIndex":3,"mint":"{mint}","owner":"{owner}","uiTokenAmount":{{"amount":"0","decimals":6}}}}],
            "postTokenBalances":[{{"accountIndex":3,"mint":"{mint}","owner":"{owner}","uiTokenAmount":{{"amount":"{amount}","decimals":6}}}}]}},
          "transaction":{{"message":{{"accountKeys":[
            {{"pubkey":"PayerAcct"}},{{"pubkey":"MerchantAta"}},{{"pubkey":"TokenProgram"}},{{"pubkey":"{reference}"}}]}}}}
        }}"#,
        bt = NOW - 5,
        reference = REFERENCE,
    )
}

// A getTransaction result whose accountKeys do NOT include the queried
// reference — a payment for a *different* charge (replay attempt).
fn tx_without_reference(owner: &str, mint: &str, amount: &str) -> String {
    format!(
        r#"{{
          "slot":100,"blockTime":{bt},
          "meta":{{"err":null,
            "preTokenBalances":[{{"accountIndex":3,"mint":"{mint}","owner":"{owner}","uiTokenAmount":{{"amount":"0","decimals":6}}}}],
            "postTokenBalances":[{{"accountIndex":3,"mint":"{mint}","owner":"{owner}","uiTokenAmount":{{"amount":"{amount}","decimals":6}}}}]}},
          "transaction":{{"message":{{"accountKeys":[
            {{"pubkey":"PayerAcct"}},{{"pubkey":"MerchantAta"}},{{"pubkey":"TokenProgram"}}]}}}}
        }}"#,
        bt = NOW - 5,
    )
}

fn cfg_with_mint(mint: &str) -> WatchConfig {
    WatchConfig::from_section(
        &[
            ("rpc_url", RPC),
            ("merchant_address", MERCHANT),
            ("usdc_mint", mint),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
    )
    .unwrap()
}

// ── USER-FRIENDLY + SECURE: human errors that leak no secrets ────────────────

#[test]
fn misconfig_errors_are_human_and_leak_no_rpc_url() {
    let sec = |pairs: &[(&str, &str)]| -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    // Missing rpc_url → names the missing key.
    let e = WatchConfig::from_section(&sec(&[("merchant_address", MERCHANT)])).unwrap_err();
    assert!(e.to_string().contains("rpc_url"), "unhelpful: {e}");
    // Invalid merchant → names the field and says what's wrong.
    let e2 = WatchConfig::from_section(&sec(&[("rpc_url", RPC), ("merchant_address", "xx")]))
        .unwrap_err();
    let s = e2.to_string();
    assert!(
        s.contains("merchant_address") && s.contains("pubkey"),
        "unhelpful: {s}"
    );
    // The configured RPC endpoint never appears in an error message.
    assert!(!s.contains(RPC), "rpc_url leaked into error: {s}");
}

// ── FAST: bounded RPC — one getSignaturesForAddress + at most one getTransaction ──

#[test]
fn paid_path_makes_exactly_one_sig_and_one_tx_call() {
    let mock = Mock::full(
        &one_sig(5),
        &tx(MERCHANT, DEFAULT_USDC_MINT, "1500000", "null"),
    );
    // Borrow (via impl RpcTransport for &T) so we can read the counters after.
    let v = verify_payment(&pay_args(), &cfg(), &mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Paid { .. }));
    assert_eq!(
        mock.sig_calls.get(),
        1,
        "exactly one getSignaturesForAddress"
    );
    assert_eq!(mock.tx_calls.get(), 1, "at most one getTransaction");
}

#[test]
fn pending_path_makes_one_sig_and_zero_tx_calls() {
    let mock = Mock::sigs("[]");
    let v = verify_payment(&pay_args(), &cfg(), &mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Pending));
    assert_eq!(mock.sig_calls.get(), 1);
    assert_eq!(
        mock.tx_calls.get(),
        0,
        "no getTransaction when nothing to verify"
    );
}

// ── SECURE: replay / double-spend — a tx for a different charge cannot clear this one ──

#[test]
fn payment_not_referencing_this_charge_is_mismatch() {
    // The reference is single-use: a landed payment whose tx does not reference
    // THIS charge must never verify it (prevents replaying one payment across sales).
    let mock = Mock::full(
        &one_sig(5),
        &tx_without_reference(MERCHANT, DEFAULT_USDC_MINT, "1500000"),
    );
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Mismatch { .. }), "got {v:?}");
}

// ── BROADLY-USABLE: any SPL mint, not just USDC ──────────────────────────────

#[test]
fn verifies_a_non_usdc_spl_mint() {
    // Operator configures a different stablecoin/token mint; verification generalizes.
    let mint = "So11111111111111111111111111111111111111112";
    let mock = Mock::full(&one_sig(5), &tx(MERCHANT, mint, "1500000", "null"));
    let v = verify_payment(&pay_args(), &cfg_with_mint(mint), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Paid { .. }), "got {v:?}");
}

// ── Payment: happy path ──────────────────────────────────────────────────────

#[test]
fn paid_happy_path() {
    let mock = Mock::full(
        &one_sig(5),
        &tx(MERCHANT, DEFAULT_USDC_MINT, "1500000", "null"),
    );
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    match v {
        Verdict::Paid {
            payer,
            signature,
            slot,
        } => {
            assert_eq!(payer, "PayerAcct");
            assert_eq!(signature, "5xSig");
            assert_eq!(slot, 100);
        }
        other => panic!("expected Paid, got {other:?}"),
    }
}

#[test]
fn pending_when_no_signatures() {
    let mock = Mock::sigs("[]");
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Pending), "got {v:?}");
}

#[test]
fn wrong_amount_is_mismatch() {
    let mock = Mock::full(
        &one_sig(5),
        &tx(MERCHANT, DEFAULT_USDC_MINT, "500000", "null"),
    );
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Mismatch { .. }), "got {v:?}");
}

#[test]
fn wrong_recipient_is_mismatch() {
    let mock = Mock::full(
        &one_sig(5),
        &tx(OTHER_OWNER, DEFAULT_USDC_MINT, "1500000", "null"),
    );
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Mismatch { .. }), "got {v:?}");
}

#[test]
fn wrong_mint_is_mismatch() {
    let mock = Mock::full(&one_sig(5), &tx(MERCHANT, OTHER_MINT, "1500000", "null"));
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Mismatch { .. }), "got {v:?}");
}

#[test]
fn stale_payment_outside_window_is_expired() {
    // A matching signature exists but landed 1 hour before now; window is 60s.
    let mut args = pay_args();
    args.window_s = Some(60);
    let mock = Mock::full(
        &one_sig(3600),
        &tx(MERCHANT, DEFAULT_USDC_MINT, "1500000", "null"),
    );
    let v = verify_payment(&args, &cfg(), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Expired), "got {v:?}");
}

#[test]
fn on_chain_failed_tx_is_mismatch_not_paid() {
    let mock = Mock::full(
        &one_sig(5),
        &tx(
            MERCHANT,
            DEFAULT_USDC_MINT,
            "1500000",
            r#"{"InstructionError":[0,"Custom"]}"#,
        ),
    );
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    assert!(matches!(v, Verdict::Mismatch { .. }), "got {v:?}");
}

// ── Payment: fail-closed — RPC / decode failures are NEVER Paid ──────────────

#[test]
fn rpc_error_is_err_never_paid() {
    let mock = Mock::new(
        Ok(wrap(&one_sig(5))),
        Err(RpcError::Transport("boom".into())),
    );
    let r = verify_payment(&pay_args(), &cfg(), mock, NOW);
    assert!(matches!(r, Err(WatchError::Rpc(_))), "got {r:?}");
}

#[test]
fn signatures_rpc_error_is_err_never_paid() {
    let mock = Mock::new(
        Err(RpcError::Rpc {
            code: -32000,
            message: "node down".into(),
        }),
        Ok(wrap("null")),
    );
    let r = verify_payment(&pay_args(), &cfg(), mock, NOW);
    assert!(r.is_err(), "RPC failure must never be Paid; got {r:?}");
    assert!(!matches!(r, Ok(Verdict::Paid { .. })));
}

#[test]
fn malformed_get_transaction_is_err_never_paid() {
    // Signature exists, but getTransaction lacks meta/accountKeys entirely.
    let mock = Mock::full(&one_sig(5), r#"{"foo":1}"#);
    let r = verify_payment(&pay_args(), &cfg(), mock, NOW);
    assert!(matches!(r, Err(WatchError::Decode(_))), "got {r:?}");
}

// ── Args / config fail-closed ────────────────────────────────────────────────

#[test]
fn deny_unknown_fields_rejects_smuggled_key() {
    let raw = r#"{"reference":"x","expected_amount":"1","rpc_url":"http://evil"}"#;
    let parsed: Result<WatchArgs, _> = serde_json::from_str(raw);
    assert!(
        parsed.is_err(),
        "smuggled `rpc_url` must fail deserialization"
    );
}

#[test]
fn missing_rpc_url_fails_closed() {
    let section = [("merchant_address", MERCHANT)]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let err = WatchConfig::from_section(&section).unwrap_err();
    assert!(matches!(err, WatchError::Config(_)), "got {err:?}");
}

#[test]
fn missing_reference_arg_fails_closed() {
    let args = WatchArgs {
        expected_amount: Some("1".into()),
        ..Default::default()
    };
    let mock = Mock::sigs("[]");
    let r = verify_payment(&args, &cfg(), mock, NOW);
    assert!(matches!(r, Err(WatchError::Args(_))), "got {r:?}");
}

#[test]
fn summary_within_token_budget() {
    let mock = Mock::full(
        &one_sig(5),
        &tx(MERCHANT, DEFAULT_USDC_MINT, "1500000", "null"),
    );
    let v = verify_payment(&pay_args(), &cfg(), mock, NOW).unwrap();
    assert!(
        kiosk_core::shape::approx_tokens(&v.summary()) <= kiosk_core::shape::DEFAULT_BUDGET_TOKENS
    );
}

// ── Heartbeat mode ───────────────────────────────────────────────────────────

fn hb_args(max_silence_s: u64) -> WatchArgs {
    WatchArgs {
        mode: Some("heartbeat".into()),
        device_address: Some(DEVICE.into()),
        max_silence_s: Some(max_silence_s),
        ..Default::default()
    }
}

#[test]
fn heartbeat_live_when_recent() {
    let mock = Mock::sigs(&one_sig(30));
    let h = verify_heartbeat(&hb_args(300), &cfg(), mock, NOW).unwrap();
    assert!(matches!(h, Heartbeat::Live { .. }), "got {h:?}");
}

#[test]
fn heartbeat_stale_when_old() {
    let mock = Mock::sigs(&one_sig(3600));
    let h = verify_heartbeat(&hb_args(300), &cfg(), mock, NOW).unwrap();
    assert!(matches!(h, Heartbeat::Stale { .. }), "got {h:?}");
}

#[test]
fn heartbeat_missing_when_no_signatures() {
    let mock = Mock::sigs("[]");
    let h = verify_heartbeat(&hb_args(300), &cfg(), mock, NOW).unwrap();
    assert!(matches!(h, Heartbeat::Missing), "got {h:?}");
}

#[test]
fn heartbeat_rpc_error_is_err_never_live() {
    let mock = Mock::new(Err(RpcError::Transport("boom".into())), Ok(wrap("null")));
    let r = verify_heartbeat(&hb_args(300), &cfg(), mock, NOW);
    assert!(r.is_err());
    assert!(!matches!(r, Ok(Heartbeat::Live { .. })));
}

#[test]
fn heartbeat_missing_device_address_fails_closed() {
    let args = WatchArgs {
        mode: Some("heartbeat".into()),
        max_silence_s: Some(300),
        ..Default::default()
    };
    let mock = Mock::sigs("[]");
    let r = verify_heartbeat(&args, &cfg(), mock, NOW);
    assert!(matches!(r, Err(WatchError::Args(_))), "got {r:?}");
}
