//! Host tests for the kiosk-attest core. RPC (chain recovery + nonce read) is
//! mocked; NO live network. Injection drills come first. The load-bearing test
//! is structural: the built transaction can contain ONLY the Memo and System
//! (advance-nonce) programs — a transfer is not expressible.

use std::collections::HashMap;

use kiosk_attest::attest::{execute_attest, AttestArgs, AttestConfig, AttestError, AttestOutput};
use kiosk_core::rpc::{RpcError, RpcTransport};
use kiosk_core::{b58, b64, memo, nonce};

const NONCE_AUTHORITY: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
const NONCE_ACCOUNT: &str = "So11111111111111111111111111111111111111112";
const RPC: &str = "https://api.devnet.solana.com";
const NOW: u64 = 1_700_000_000;

// ── mock: dispatch by method; chain sigs + nonce account info ────────────────

struct Mock {
    sigs: Result<String, RpcError>,
    account: Result<String, RpcError>,
    sig_calls: std::cell::Cell<u32>,
    account_calls: std::cell::Cell<u32>,
}
impl Mock {
    fn build(sigs: Result<String, RpcError>, account: Result<String, RpcError>) -> Self {
        Self {
            sigs,
            account,
            sig_calls: std::cell::Cell::new(0),
            account_calls: std::cell::Cell::new(0),
        }
    }
}
impl RpcTransport for Mock {
    fn send(&self, req: &str) -> Result<String, RpcError> {
        if req.contains("getSignaturesForAddress") {
            self.sig_calls.set(self.sig_calls.get() + 1);
            self.sigs.clone()
        } else if req.contains("getAccountInfo") {
            self.account_calls.set(self.account_calls.get() + 1);
            self.account.clone()
        } else {
            Err(RpcError::Transport("unexpected method".into()))
        }
    }
}
fn env(result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#)
}
/// A valid Current+Initialized nonce account owned by NONCE_AUTHORITY.
fn account_info() -> String {
    let authority = b58::decode_pubkey(NONCE_AUTHORITY).unwrap();
    let mut blob = Vec::new();
    blob.extend_from_slice(&1u32.to_le_bytes()); // version Current
    blob.extend_from_slice(&1u32.to_le_bytes()); // state Initialized
    blob.extend_from_slice(&authority);
    blob.extend_from_slice(&[0x11u8; 32]); // durable nonce (blockhash)
    blob.extend_from_slice(&5000u64.to_le_bytes());
    let data = b64::encode(&blob);
    env(&format!(
        r#"{{"context":{{"slot":1}},"value":{{"data":["{data}","base64"],"executable":false}}}}"#
    ))
}
fn fresh_chain() -> Mock {
    Mock::build(Ok(env("[]")), Ok(account_info()))
}
fn chain_at_seq(seq: u64, sig: &str) -> Mock {
    let sigs = env(&format!(
        r#"[{{"signature":"{sig}","slot":9,"memo":"[20] {{\"v\":1,\"seq\":{seq}}}"}}]"#
    ));
    Mock::build(Ok(sigs), Ok(account_info()))
}

fn cfg() -> AttestConfig {
    let section: HashMap<String, String> = [
        ("rpc_url", RPC),
        ("device_id", "kiosk01"),
        ("nonce_account", NONCE_ACCOUNT),
        ("nonce_authority", NONCE_AUTHORITY),
        ("allowed_metrics", "temp_c:-40:85, humidity:0:100"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    AttestConfig::from_section(&section).unwrap()
}

fn reading(metric: &str, value: f64) -> AttestArgs {
    AttestArgs {
        kind: Some("reading".into()),
        metric: Some(metric.into()),
        value: Some(value),
        ..Default::default()
    }
}

// ── injection drills (first) ─────────────────────────────────────────────────

#[test]
fn smuggled_key_is_a_serde_error() {
    let raw = r#"{"kind":"reading","metric":"temp_c","value":4.2,"recipient":"EVIL"}"#;
    let parsed: Result<AttestArgs, _> = serde_json::from_str(raw);
    assert!(
        parsed.is_err(),
        "unknown `recipient` field must fail deserialization"
    );
}

#[test]
fn metric_not_in_allowlist_rejected() {
    let r = execute_attest(&reading("evil_metric", 1.0), &cfg(), fresh_chain(), NOW);
    assert!(
        matches!(r, Err(AttestError::Rejected(_)) | Err(AttestError::Args(_))),
        "got {r:?}"
    );
}

#[test]
fn value_out_of_bounds_rejected() {
    let r = execute_attest(&reading("temp_c", 999.0), &cfg(), fresh_chain(), NOW);
    assert!(matches!(r, Err(AttestError::Rejected(_))), "got {r:?}");
    let r2 = execute_attest(&reading("temp_c", -100.0), &cfg(), fresh_chain(), NOW);
    assert!(matches!(r2, Err(AttestError::Rejected(_))), "got {r2:?}");
}

#[test]
fn value_nan_or_inf_rejected() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let r = execute_attest(&reading("temp_c", bad), &cfg(), fresh_chain(), NOW);
        assert!(
            matches!(r, Err(AttestError::Rejected(_))),
            "{bad} must be rejected, got {r:?}"
        );
    }
}

// ── structural safety: funds cannot move ─────────────────────────────────────

#[test]
fn tx_contains_only_memo_and_system_programs() {
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), fresh_chain(), NOW).unwrap();
    let mut progs = out.program_ids();
    progs.sort();
    let mut expected = vec![nonce::SYSTEM_PROGRAM_ID, memo::memo_program_id()];
    expected.sort();
    assert_eq!(
        progs, expected,
        "attestation tx must contain ONLY Memo + System programs"
    );
}

#[test]
fn advance_nonce_is_instruction_zero() {
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), fresh_chain(), NOW).unwrap();
    let ix0 = &out.message.instructions[0];
    assert_eq!(
        out.message.account_keys[ix0.program_id_index as usize],
        nonce::SYSTEM_PROGRAM_ID
    );
    assert_eq!(
        ix0.data,
        vec![4, 0, 0, 0],
        "instruction 0 must be AdvanceNonceAccount"
    );
    assert_eq!(out.message.instructions.len(), 2);
}

#[test]
fn memo_instruction_present_and_carries_the_reading() {
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), fresh_chain(), NOW).unwrap();
    let memo_id = memo::memo_program_id();
    let memo_ix = out
        .message
        .instructions
        .iter()
        .find(|ci| out.message.account_keys[ci.program_id_index as usize] == memo_id)
        .expect("memo instruction present");
    let json: serde_json::Value = serde_json::from_slice(&memo_ix.data).unwrap();
    assert_eq!(json["metric"], "temp_c");
    assert_eq!(json["dev"], "kiosk01");
}

#[test]
fn output_is_unsigned_zero_signatures() {
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), fresh_chain(), NOW).unwrap();
    // The output is the bare serialized message — no signature section prepended.
    let decoded = b64::decode(&out.tx_base64).unwrap();
    assert_eq!(decoded, out.message.serialize());
    // First byte is the header's num_required_signatures (1), NOT a signature blob.
    assert_eq!(decoded[0], out.message.header.num_required_signatures);
}

#[test]
fn seq_increments_and_prev_is_linked() {
    let out = execute_attest(
        &reading("temp_c", 4.2),
        &cfg(),
        chain_at_seq(7, "PrevSig9"),
        NOW,
    )
    .unwrap();
    assert_eq!(out.seq, 8);
    let memo_id = memo::memo_program_id();
    let memo_ix = out
        .message
        .instructions
        .iter()
        .find(|ci| out.message.account_keys[ci.program_id_index as usize] == memo_id)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&memo_ix.data).unwrap();
    assert_eq!(json["seq"], 8);
    assert_eq!(json["prev"], "PrevSig9");
}

#[test]
fn fresh_device_starts_at_seq_zero_with_null_prev() {
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), fresh_chain(), NOW).unwrap();
    assert_eq!(out.seq, 0);
    let memo_id = memo::memo_program_id();
    let memo_ix = out
        .message
        .instructions
        .iter()
        .find(|ci| out.message.account_keys[ci.program_id_index as usize] == memo_id)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&memo_ix.data).unwrap();
    assert!(json["prev"].is_null());
}

// ── no secrets leak; output budget; config fail-closed ───────────────────────

#[test]
fn secrets_never_in_summary() {
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), fresh_chain(), NOW).unwrap();
    assert!(
        !out.summary.contains(RPC),
        "rpc_url must not leak into output"
    );
    assert!(
        !out.summary.contains(NONCE_AUTHORITY),
        "authority must not leak into output"
    );
}

#[test]
fn summary_within_token_budget() {
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), fresh_chain(), NOW).unwrap();
    assert!(
        kiosk_core::shape::approx_tokens(&out.summary) <= kiosk_core::shape::DEFAULT_BUDGET_TOKENS
    );
}

#[test]
fn bad_nonce_pubkey_config_fails_closed() {
    let section: HashMap<String, String> = [
        ("rpc_url", RPC),
        ("device_id", "kiosk01"),
        ("nonce_account", "not-a-pubkey"),
        ("nonce_authority", NONCE_AUTHORITY),
        ("allowed_metrics", "temp_c:-40:85"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert!(matches!(
        AttestConfig::from_section(&section),
        Err(AttestError::Config(_))
    ));
}

#[test]
fn rpc_failure_is_never_a_successful_attestation() {
    let mock = Mock::build(Err(RpcError::Transport("down".into())), Ok(account_info()));
    let r: Result<AttestOutput, AttestError> =
        execute_attest(&reading("temp_c", 4.2), &cfg(), mock, NOW);
    assert!(r.is_err());
}

// ── USER-FRIENDLY + SECURE: human errors that leak no secrets ────────────────

#[test]
fn misconfig_errors_are_human_and_leak_no_rpc_url() {
    let sec = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    // Missing rpc_url → names the missing key.
    let e = AttestConfig::from_section(&sec(&[("device_id", "k")])).unwrap_err();
    assert!(e.to_string().contains("rpc_url"), "unhelpful: {e}");
    // Bad nonce pubkey → names the field and 'pubkey'; no rpc leak.
    let e2 = AttestConfig::from_section(&sec(&[
        ("rpc_url", RPC),
        ("device_id", "k"),
        ("nonce_account", "xx"),
        ("nonce_authority", NONCE_AUTHORITY),
    ]))
    .unwrap_err();
    let s = e2.to_string();
    assert!(
        s.contains("nonce_account") && s.contains("pubkey"),
        "unhelpful: {s}"
    );
    assert!(!s.contains(RPC), "rpc_url leaked into error: {s}");
}

// ── FAST: seq/prev recovery is exactly ONE getSignaturesForAddress ───────────

#[test]
fn recovers_chain_in_exactly_one_signatures_call() {
    let mock = fresh_chain();
    // Borrow via impl RpcTransport for &T so counters are readable afterward.
    let out = execute_attest(&reading("temp_c", 4.2), &cfg(), &mock, NOW).unwrap();
    assert!(out.seq == 0);
    assert_eq!(
        mock.sig_calls.get(),
        1,
        "chain recovery must be ONE getSignaturesForAddress"
    );
    assert_eq!(
        mock.account_calls.get(),
        1,
        "one getAccountInfo for the durable nonce"
    );
}
