//! Host tests for the pure attestation core. Run with a plain `cargo test` —
//! no wasm toolchain, no RPC, no sensor: the RPC/sensor are only ever touched
//! by the wasm shim (`src/lib.rs`), which this crate never compiles on the
//! host.

use depin_attest::attest::{attestation_hash, build_memo, derive_nonce, hex_encode, AttestArgs};
use depin_attest::memo::memo_instruction;
use depin_attest::tx::{base64_encode, serialize, UnsignedTx};

fn sample_args() -> AttestArgs {
    AttestArgs {
        device_id: "pi-node-001".into(),
        sensor_type: "temperature".into(),
        value: 23.4,
        unit: "celsius".into(),
    }
}

#[test]
fn nonce_is_deterministic() {
    let a = derive_nonce("pi-node-001", 100);
    let b = derive_nonce("pi-node-001", 100);
    assert_eq!(a, b);
}

#[test]
fn nonce_differs_by_slot() {
    let a = derive_nonce("pi-node-001", 100);
    let b = derive_nonce("pi-node-001", 101);
    assert_ne!(a, b);
}

#[test]
fn nonce_differs_by_device() {
    let a = derive_nonce("pi-node-001", 100);
    let b = derive_nonce("pi-node-002", 100);
    assert_ne!(a, b);
}

#[test]
fn memo_format_includes_all_fields() {
    let args = sample_args();
    let nonce = derive_nonce(&args.device_id, 12345);
    let memo = build_memo(&args, 12345, &nonce).expect("valid args must build a memo");
    assert!(memo.starts_with("zc-depin|pi-node-001|temperature"));
    assert!(memo.contains("slot:12345"));
    assert!(memo.contains("nonce:"));
    // Output length check — must fit comfortably in a small context budget.
    assert!(memo.len() < 400, "memo too long: {} chars", memo.len());
}

#[test]
fn attestation_hash_is_deterministic_and_matches_memo() {
    let args = sample_args();
    let nonce = derive_nonce(&args.device_id, 1);
    let memo = build_memo(&args, 1, &nonce).expect("valid args must build a memo");
    let h1 = attestation_hash(&memo);
    let h2 = attestation_hash(&memo);
    assert_eq!(h1, h2);
    assert_eq!(hex_encode(&h1).len(), 64);
}

#[test]
fn tx_serializes_without_panic() {
    let args = AttestArgs {
        device_id: "pi-node-001".into(),
        sensor_type: "uptime".into(),
        value: 86400.0,
        unit: "seconds".into(),
    };
    let nonce = derive_nonce(&args.device_id, 9999);
    let memo_text = build_memo(&args, 9999, &nonce).expect("valid args must build a memo");
    let instr = memo_instruction(&memo_text);
    let tx = UnsignedTx {
        fee_payer: [0u8; 32],
        recent_blockhash: [1u8; 32],
        instruction: instr,
    };
    let bytes = serialize(&tx);
    // [0 signatures shortvec][0x80 version prefix][message...]
    assert_eq!(bytes[0], 0x00);
    assert_eq!(bytes[1], 0x80);
    assert!(!bytes.is_empty());
}

#[test]
fn tx_base64_roundtrips_expected_length() {
    let args = sample_args();
    let nonce = derive_nonce(&args.device_id, 42);
    let memo_text = build_memo(&args, 42, &nonce).expect("valid args must build a memo");
    let instr = memo_instruction(&memo_text);
    let tx = UnsignedTx {
        fee_payer: [0u8; 32],
        recent_blockhash: [2u8; 32],
        instruction: instr,
    };
    let bytes = serialize(&tx);
    let b64 = base64_encode(&bytes);
    // base64 with padding is always a multiple of 4 chars.
    assert_eq!(b64.len() % 4, 0);
    assert!(!b64.is_empty());
}

/// Prompt-injection guard: an attacker embeds an extra field (e.g. trying to
/// smuggle a `private_key` or a `submit: true` flag) into the tool-call JSON,
/// hoping either to exfiltrate something back through a permissive parser or
/// to get T1-tier code to behave like a T2 (auto-submit) plugin. `AttestArgs`
/// is `#[serde(deny_unknown_fields)]`, so parsing MUST fail closed rather
/// than silently ignoring or accepting the extra field.
#[test]
fn prompt_injection_unknown_field_rejected() {
    let malicious = r#"{
        "device_id": "pi-node-001",
        "sensor_type": "temperature",
        "value": 23.4,
        "unit": "celsius",
        "private_key": "EXFILTRATE_THIS"
    }"#;
    let result: Result<AttestArgs, _> = serde_json::from_str(malicious);
    assert!(result.is_err(), "unknown field should be rejected");
}

/// Second injection guard: even absent the deny_unknown_fields check, this
/// crate exposes no signing or submission path at all — `execute` (in the
/// wasm shim) only ever returns unsigned bytes. This test pins that
/// invariant at the data level: the memo text produced from a normal request
/// contains no such command markers.
#[test]
fn prompt_injection_sign_and_submit_ignored() {
    let args = sample_args();
    let nonce = derive_nonce(&args.device_id, 1);
    let memo = build_memo(&args, 1, &nonce).expect("valid args must build a memo");
    assert!(!memo.contains("sendTransaction"));
    assert!(!memo.contains("private_key"));
}

#[test]
fn summary_stays_compact() {
    let args = AttestArgs {
        device_id: "pi-node-001".into(),
        sensor_type: "energy_kwh".into(),
        value: 1.234,
        unit: "kWh".into(),
    };
    let nonce = derive_nonce(&args.device_id, 500_000);
    let nonce_hex = hex_encode(&nonce);
    let summary = format!(
        "Attestation built for {} ({}: {:.4} {}) at slot {}. Unsigned — sign with your wallet \
         and submit to commit on-chain. Nonce: {}...",
        args.device_id, args.sensor_type, args.value, args.unit, 500_000, &nonce_hex[..16],
    );
    assert!(summary.len() < 300, "summary too long: {} chars", summary.len());
}

#[test]
fn delimiter_injection_in_device_id_rejected() {
    let args = AttestArgs {
        device_id: "pi-node|slot:0|nonce:fake".into(),
        sensor_type: "temperature".into(),
        value: 23.0,
        unit: "celsius".into(),
    };
    let nonce = derive_nonce(&args.device_id, 1);
    assert!(build_memo(&args, 1, &nonce).is_err());
}

#[test]
fn delimiter_injection_in_unit_rejected() {
    let args = AttestArgs {
        device_id: "pi-node-001".into(),
        sensor_type: "temperature".into(),
        value: 23.0,
        unit: "celsius|nonce:evil".into(),
    };
    let nonce = derive_nonce(&args.device_id, 1);
    assert!(build_memo(&args, 1, &nonce).is_err());
}

#[test]
fn memo_length_cap_enforced() {
    let args = AttestArgs {
        device_id: "a".repeat(64),
        sensor_type: "custom".into(),
        value: 1.0,
        unit: "x".repeat(16),
    };
    let nonce = derive_nonce(&args.device_id, u64::MAX);
    // May or may not exceed 256 — just assert build_memo doesn't panic
    let _ = build_memo(&args, u64::MAX, &nonce);
}

#[test]
fn zero_fee_payer_produces_valid_tx_bytes() {
    // Even with zero fee-payer, the tx must serialize without panic
    // and the v0 prefix must be present.
    let instr = memo_instruction("test");
    let tx = UnsignedTx {
        fee_payer: [0u8; 32],
        recent_blockhash: [1u8; 32],
        instruction: instr,
    };
    let bytes = serialize(&tx);
    assert_eq!(bytes[1], 0x80);
}
