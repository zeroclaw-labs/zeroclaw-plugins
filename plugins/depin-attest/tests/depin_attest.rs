//! Integration tests for the depin-attest pure core (slice B: config + reading + nonce).
//! Host-run with plain `cargo test` — no wasm, no live network.

use std::collections::HashMap;
use std::str::FromStr;

use depin_attest::depin_attest::{AttestConfig, AttestError, CustodyMode, MEMO_MAX_BYTES, SensorReading};
use palinurus_core::Pubkey;
use sha2::{Digest, Sha256};

// ── Known valid base58 pubkeys for config tests ──
const SYSTEM: &str = "11111111111111111111111111111111"; // System program
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"; // Memo program
const SAS: &str = "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG"; // SAS program
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"; // SPL Token (for a distinct address)

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A minimal valid T1 config section.
fn valid_t1_section() -> HashMap<String, String> {
    section(&[
        ("rpc_endpoint", "https://devnet.helius.com"),
        ("credential_pda", SAS),
        ("schema_pda", MEMO),
        ("authority", SYSTEM),
        ("payer", SYSTEM),
        ("nonce_account", TOKEN),
        ("nonce_authority", SYSTEM),
    ])
}

// ── Config parsing tests ──

#[test]
fn config_valid_t1() {
    let cfg = AttestConfig::from_section(&valid_t1_section()).expect("valid T1 config");
    assert_eq!(cfg.rpc_endpoint, "https://devnet.helius.com");
    assert_eq!(cfg.credential_pda, Pubkey::from_str(SAS).unwrap());
    assert_eq!(cfg.schema_pda, Pubkey::from_str(MEMO).unwrap());
    assert_eq!(cfg.authority, Pubkey::from_str(SYSTEM).unwrap());
    assert_eq!(cfg.payer, Pubkey::from_str(SYSTEM).unwrap());
    assert_eq!(cfg.nonce_account, Pubkey::from_str(TOKEN).unwrap());
    assert_eq!(cfg.nonce_authority, Pubkey::from_str(SYSTEM).unwrap());
    assert_eq!(cfg.custody_mode, CustodyMode::T1);
    assert_eq!(cfg.attestation_ttl_secs, 7_776_000); // default 90d
    assert!(!cfg.memo_fallback); // default false
    assert_eq!(cfg.network, "devnet"); // default
    assert!(cfg.session_key.is_none()); // T1 has no session key
}

#[test]
fn config_custody_mode_defaults_to_t1_when_absent() {
    let mut s = valid_t1_section();
    s.remove("custody_mode");
    let cfg = AttestConfig::from_section(&s).unwrap();
    assert_eq!(cfg.custody_mode, CustodyMode::T1);
}

#[test]
fn config_custody_mode_explicit_t1() {
    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t1".to_string());
    let cfg = AttestConfig::from_section(&s).unwrap();
    assert_eq!(cfg.custody_mode, CustodyMode::T1);
}

#[test]
fn config_empty_section_fails_closed() {
    let s = HashMap::new();
    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("not configured")));
}

#[test]
fn config_missing_required_key() {
    let mut s = valid_t1_section();
    s.remove("rpc_endpoint");
    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("missing required key: rpc_endpoint")));
}

#[test]
fn config_invalid_base58() {
    let mut s = valid_t1_section();
    s.insert("credential_pda".to_string(), "not-base58!!".to_string());
    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("invalid base58 for credential_pda")));
}

#[test]
fn config_unknown_custody_mode() {
    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t3".to_string());
    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("unknown custody_mode: 't3'")));
}

#[test]
fn config_negative_ttl_rejected() {
    let mut s = valid_t1_section();
    s.insert("attestation_ttl_secs".to_string(), "-1".to_string());
    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("non-negative")));
}

#[test]
fn config_ttl_overflow_guard() {
    let mut s = valid_t1_section();
    s.insert("attestation_ttl_secs".to_string(), i64::MAX.to_string());
    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("too large")));
}

#[test]
fn config_memo_fallback_true() {
    let mut s = valid_t1_section();
    s.insert("memo_fallback".to_string(), "true".to_string());
    let cfg = AttestConfig::from_section(&s).unwrap();
    assert!(cfg.memo_fallback);
}

#[test]
fn config_network_override() {
    let mut s = valid_t1_section();
    s.insert("network".to_string(), "mainnet-beta".to_string());
    let cfg = AttestConfig::from_section(&s).unwrap();
    assert_eq!(cfg.network, "mainnet-beta");
}

#[test]
fn config_t2_missing_session_key() {
    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    // No session_key provided.
    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("missing required key: session_key")));
}

#[test]
fn config_t2_valid_session_key() {
    // Generate a deterministic test keypair (ed25519-dalek).
    let secret = [42u8; 32]; // deterministic test key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let key_b58 = bs58::encode(secret).into_string();

    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    s.insert("session_key".to_string(), key_b58);
    s.insert("max_lamports_per_tx".to_string(), "5000".to_string());
    s.insert("max_attestations_per_day".to_string(), "50".to_string());

    let cfg = AttestConfig::from_section(&s).expect("valid T2 config");
    assert_eq!(cfg.custody_mode, CustodyMode::T2);
    assert!(cfg.session_key.is_some());
    assert_eq!(
        cfg.session_key.as_ref().unwrap().verifying_key(),
        signing_key.verifying_key()
    );
    assert_eq!(cfg.max_lamports_per_tx, 5000);
    assert_eq!(cfg.max_attestations_per_day, 50);
}

#[test]
fn config_t2_session_key_wrong_length() {
    let short = [1u8; 16]; // 16 bytes, not 32
    let key_b58 = bs58::encode(short).into_string();

    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    s.insert("session_key".to_string(), key_b58);

    let err = AttestConfig::from_section(&s).unwrap_err();
    assert!(matches!(err, AttestError::Config(ref m) if m.contains("32 bytes")));
}

#[test]
fn config_t2_caps_default_when_absent() {
    let secret = [7u8; 32];
    let key_b58 = bs58::encode(secret).into_string();

    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    s.insert("session_key".to_string(), key_b58);
    // max_lamports_per_tx + max_attestations_per_day absent → defaults.

    let cfg = AttestConfig::from_section(&s).unwrap();
    assert_eq!(cfg.max_lamports_per_tx, 10_000); // default
    assert_eq!(cfg.max_attestations_per_day, 100); // default
}

// ── SensorReading::encode tests ──

#[test]
fn encode_is_deterministic() {
    let r = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let a = r.encode();
    let b = r.encode();
    assert_eq!(a, b, "encode must be deterministic");
}

#[test]
fn encode_round_trips() {
    let r = SensorReading {
        sensor_id: "scd41-2".to_string(),
        value: 412.8,
        unit: "ppm".to_string(),
        timestamp: 1_753_010_000,
    };
    let bytes = r.encode();
    // BorshDeserialize round-trip.
    let decoded: SensorReading = borsh::from_slice(&bytes).expect("decode");
    assert_eq!(decoded, r);
}

#[test]
fn encode_has_expected_borsh_layout() {
    // Borsh layout: [u32 LE len(sensor_id)] [sensor_id bytes] [f64 LE value]
    //               [u32 LE len(unit)] [unit bytes] [i64 LE timestamp]
    let r = SensorReading {
        sensor_id: "ab".to_string(),
        value: 1.0,
        unit: "C".to_string(),
        timestamp: 1_000,
    };
    let bytes = r.encode();
    // sensor_id "ab" = 2 bytes → u32 LE = [2,0,0,0]
    assert_eq!(&bytes[0..4], &[2, 0, 0, 0]);
    assert_eq!(&bytes[4..6], b"ab");
    // value 1.0 f64 LE = [0,0,0,0,0,0,240,63]
    assert_eq!(&bytes[6..14], &[0, 0, 0, 0, 0, 0, 0xf0, 0x3f]);
    // unit "C" = 1 byte → u32 LE = [1,0,0,0]
    assert_eq!(&bytes[14..18], &[1, 0, 0, 0]);
    assert_eq!(&bytes[18..19], b"C");
    // timestamp 1000 i64 LE
    assert_eq!(&bytes[19..27], &[0xe8, 3, 0, 0, 0, 0, 0, 0]);
    assert_eq!(bytes.len(), 27);
}

// ── SensorReading::derive_nonce tests ──

fn expected_nonce(sensor_id: &str, value: f64, unit: &str, timestamp: i64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sensor_id.as_bytes());
    hasher.update(timestamp.to_le_bytes());
    hasher.update(value.to_le_bytes());
    hasher.update(unit.as_bytes());
    hasher.finalize().into()
}

#[test]
fn nonce_deterministic() {
    let r = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let a = r.derive_nonce();
    let b = r.derive_nonce();
    assert_eq!(a.to_bytes(), b.to_bytes());
}

#[test]
fn nonce_matches_manual_sha256() {
    let r = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let nonce = r.derive_nonce();
    let expected = expected_nonce("bme280-1", 24.7, "celsius", 1_753_000_000);
    assert_eq!(nonce.to_bytes(), expected);
}

#[test]
fn nonce_unique_per_sensor_id() {
    let a = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let b = SensorReading {
        sensor_id: "bme280-2".to_string(),
        ..a.clone()
    };
    assert_ne!(a.derive_nonce().to_bytes(), b.derive_nonce().to_bytes());
}

#[test]
fn nonce_unique_per_value() {
    let a = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let b = SensorReading {
        value: 24.8,
        ..a.clone()
    };
    assert_ne!(a.derive_nonce().to_bytes(), b.derive_nonce().to_bytes());
}

#[test]
fn nonce_unique_per_timestamp() {
    let a = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let b = SensorReading {
        timestamp: 1_753_000_001,
        ..a.clone()
    };
    assert_ne!(a.derive_nonce().to_bytes(), b.derive_nonce().to_bytes());
}

#[test]
fn nonce_unique_per_unit() {
    let a = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let b = SensorReading {
        unit: "fahrenheit".to_string(),
        ..a.clone()
    };
    assert_ne!(a.derive_nonce().to_bytes(), b.derive_nonce().to_bytes());
}

#[test]
fn nonce_identical_readings_collide() {
    // Natural dedup: two identical readings produce the same nonce → same PDA.
    // The second attestation fails with PDA-already-exists. This is a feature.
    let a = SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let b = a.clone();
    assert_eq!(a.derive_nonce().to_bytes(), b.derive_nonce().to_bytes());
}
// ── Slice C: instruction building tests ──

use depin_attest::depin_attest::{build_attest_ix, build_memo_ix};
use palinurus_core::{find_program_address, CreateAttestationIxData};

/// A valid config for instruction-building tests (uses distinct pubkeys so
/// account ordering is testable).
fn test_config() -> AttestConfig {
    AttestConfig::from_section(&section(&[
        ("rpc_endpoint", "https://devnet.helius.com"),
        ("credential_pda", SAS),      // credential = SAS addr (stand-in)
        ("schema_pda", MEMO),         // schema = MEMO addr (stand-in)
        ("authority", TOKEN),         // authority = TOKEN addr (distinct)
        ("payer", TOKEN),             // payer = same as authority
        ("nonce_account", SYSTEM),    // nonce_account = System (stand-in)
        ("nonce_authority", TOKEN),   // nonce_authority = TOKEN
    ]))
    .expect("valid test config")
}

fn test_reading() -> SensorReading {
    SensorReading {
        sensor_id: "bme280-1".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    }
}

#[test]
fn attest_ix_program_is_sas() {
    let cfg = test_config();
    let (ix, _, _) = build_attest_ix(&test_reading(), &cfg).unwrap();
    assert_eq!(ix.program_id, Pubkey::from_str(SAS).unwrap());
}

#[test]
fn attest_ix_has_six_accounts_in_correct_order() {
    let cfg = test_config();
    let (ix, _, _) = build_attest_ix(&test_reading(), &cfg).unwrap();
    assert_eq!(ix.accounts.len(), 6, "must have exactly 6 accounts");

    let cred = Pubkey::from_str(SAS).unwrap();
    let schema = Pubkey::from_str(MEMO).unwrap();
    let auth = Pubkey::from_str(TOKEN).unwrap();
    let system = Pubkey::from_str(SYSTEM).unwrap();

    // 0: payer — W signer
    assert_eq!(ix.accounts[0].pubkey, auth, "payer");
    assert!(ix.accounts[0].is_signer, "payer must be signer");
    assert!(ix.accounts[0].is_writable, "payer must be writable");

    // 1: authority — R signer
    assert_eq!(ix.accounts[1].pubkey, auth, "authority");
    assert!(ix.accounts[1].is_signer, "authority must be signer");
    assert!(!ix.accounts[1].is_writable, "authority must be readonly");

    // 2: credential — R non-signer
    assert_eq!(ix.accounts[2].pubkey, cred, "credential");
    assert!(!ix.accounts[2].is_signer, "credential must not be signer");
    assert!(!ix.accounts[2].is_writable, "credential must be readonly");

    // 3: schema — R non-signer
    assert_eq!(ix.accounts[3].pubkey, schema, "schema");
    assert!(!ix.accounts[3].is_signer, "schema must not be signer");
    assert!(!ix.accounts[3].is_writable, "schema must be readonly");

    // 4: attestation — W non-signer (the PDA being created)
    assert!(!ix.accounts[4].is_signer, "attestation must not be signer");
    assert!(ix.accounts[4].is_writable, "attestation must be writable");

    // 5: system_program — R non-signer
    assert_eq!(ix.accounts[5].pubkey, system, "system_program");
    assert!(!ix.accounts[5].is_signer, "system must not be signer");
    assert!(!ix.accounts[5].is_writable, "system must be readonly");
}

#[test]
fn attest_pda_matches_find_program_address() {
    let cfg = test_config();
    let reading = test_reading();
    let (ix, pda, _) = build_attest_ix(&reading, &cfg).unwrap();

    // Independently derive the PDA to cross-check.
    let nonce = reading.derive_nonce();
    let (expected_pda, _bump) = find_program_address(
        &[
            b"attestation",
            cfg.credential_pda.as_bytes(),
            cfg.schema_pda.as_bytes(),
            nonce.as_bytes(),
        ],
        &Pubkey::from_str(SAS).unwrap(),
    );
    assert_eq!(pda, expected_pda);

    // The attestation account in the ix must match the returned PDA.
    assert_eq!(ix.accounts[4].pubkey, pda);
}

#[test]
fn attest_ix_data_matches_create_attestation_ix_data() {
    let cfg = test_config();
    let reading = test_reading();
    let (ix, _pda, expiry) = build_attest_ix(&reading, &cfg).unwrap();

    let nonce = reading.derive_nonce();
    let expected_data = CreateAttestationIxData::new(nonce, reading.encode(), expiry).to_ix_bytes();
    assert_eq!(ix.data, expected_data, "ix data must match CreateAttestationIxData encoding");
}

#[test]
fn attest_ix_expiry_is_timestamp_plus_ttl() {
    let cfg = test_config();
    let reading = test_reading();
    let (_ix, _, expiry) = build_attest_ix(&reading, &cfg).unwrap();
    assert_eq!(expiry, reading.timestamp + cfg.attestation_ttl_secs);
}

#[test]
fn attest_ix_expiry_overflow_detected() {
    let mut cfg = test_config();
    cfg.attestation_ttl_secs = i64::MAX - 1_000_000_000; // huge but passes config validation
    let reading = SensorReading {
        sensor_id: "x".to_string(),
        value: 1.0,
        unit: "C".to_string(),
        timestamp: i64::MAX - 1, // near overflow
    };
    let err = build_attest_ix(&reading, &cfg).unwrap_err();
    assert!(matches!(err, AttestError::InvalidReading(ref m) if m.contains("expiry overflow")));
}

#[test]
fn memo_ix_is_raw_utf8_no_accounts() {
    let ix = build_memo_ix("sensor reading ok");
    assert_eq!(ix.program_id, Pubkey::from_str(MEMO).unwrap());
    assert!(ix.accounts.is_empty(), "memo ix takes no accounts");
    assert_eq!(ix.data, b"sensor reading ok");
}

#[test]
fn memo_ix_empty_string() {
    let ix = build_memo_ix("");
    assert_eq!(ix.program_id, Pubkey::from_str(MEMO).unwrap());
    assert!(ix.accounts.is_empty());
    assert!(ix.data.is_empty());
}

// ── Slice D: execute_t1 tests ──

use depin_attest::depin_attest::execute_t1;
use palinurus_core::{estimate_tokens, MockRpc};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use serde_json::json;

/// Build a scripted MockRpc getAccountInfo response for an Initialized nonce
/// account with the given authority + a fixed durable nonce.
fn nonce_account_response(authority: &Pubkey, durable_nonce: [u8; 32]) -> serde_json::Value {
    let mut data = vec![0u8; 80];
    // u32 LE version = 1 (Current)
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    // u32 LE state = 1 (Initialized)
    data[4..8].copy_from_slice(&1u32.to_le_bytes());
    // 32B authority
    data[8..40].copy_from_slice(authority.as_bytes());
    // 32B durable_nonce
    data[40..72].copy_from_slice(&durable_nonce);
    // u64 LE lamports_per_signature = 5000
    data[72..80].copy_from_slice(&5000u64.to_le_bytes());

    json!({
        "result": {
            "value": {
                "data": [BASE64_STANDARD.encode(&data), "base64"],
                "owner": "11111111111111111111111111111111",
                "lamports": 100000000,
                "executable": false
            }
        }
    })
}

/// A MockRpc with a single initialized nonce account (authority = TOKEN, matching test_config).
fn mock_rpc_with_nonce() -> MockRpc {
    let auth = Pubkey::from_str(TOKEN).unwrap();
    let nonce_hash = [0xAA; 32]; // fixed durable nonce
    MockRpc::new(vec![nonce_account_response(&auth, nonce_hash)])
}

#[test]
fn execute_t1_happy_path() {
    let cfg = test_config();
    let rpc = mock_rpc_with_nonce();
    let reading = test_reading();

    let out = execute_t1(&reading, None, &cfg, &rpc).expect("T1 happy path");

    // Attestation PDA is correct (cross-checked in slice C).
    let (_expected_ix, expected_pda, _) = build_attest_ix(&reading, &cfg).unwrap();
    assert_eq!(out.attestation_pda, expected_pda);

    // tx_b64 decodes to valid bytes.
    let tx_bytes = BASE64_STANDARD.decode(&out.tx_b64).unwrap();
    assert!(!tx_bytes.is_empty());

    // Unsigned (T1) → no signature.
    assert!(out.signature.is_none());
    assert!(!out.used_memo_fallback);

    // Summary ≤200 tokens AND ≤800 chars.
    assert!(estimate_tokens(&out.summary) <= 200, "summary must be ≤200 tokens, got {}", estimate_tokens(&out.summary));
    assert!(out.summary.len() <= 800, "summary must be ≤800 chars, got {}", out.summary.len());

    // Explorer URL contains the PDA.
    assert!(out.explorer_url.contains(&out.attestation_pda.to_string()));
    assert!(out.explorer_url.contains("devnet"));

    // Summary contains key elements.
    assert!(out.summary.contains("attested reading"), "summary: {}", out.summary);
    assert!(out.summary.contains("unsigned"), "summary: {}", out.summary);
    assert!(out.summary.contains("multisig"), "summary: {}", out.summary);
}

#[test]
fn execute_t1_tx_first_ix_is_advance_nonce() {
    let cfg = test_config();
    let rpc = mock_rpc_with_nonce();
    let out = execute_t1(&test_reading(), None, &cfg, &rpc).unwrap();

    let tx_bytes = BASE64_STANDARD.decode(&out.tx_b64).unwrap();
    // Wire format: [compact-u16 sigs=0] [message...]
    // Message V0: [0x80 prefix] [header 3B] [compact-u16 account_keys count] [account_keys...] ...
    // The first instruction is at a specific offset. Instead of full parsing,
    // verify the AdvanceNonceAccount data [0x04,0x00,0x00,0x00] appears early.
    // The advance ix data is 4 bytes; the compiled ix has program_id_index (1B) +
    // accounts short-vec (3B: [nonce, sysvar, authority]) + data (4B).
    // We verify the data bytes [0x04,0x00,0x00,0x00] are present in the tx.
    assert!(
        tx_bytes.windows(4).any(|w| w == [0x04, 0x00, 0x00, 0x00]),
        "tx must contain AdvanceNonceAccount ix data [0x04,0,0,0]"
    );
}

#[test]
fn execute_t1_with_memo() {
    let cfg = test_config();
    // Need 1 nonce account response.
    let auth = Pubkey::from_str(TOKEN).unwrap();
    let rpc = MockRpc::new(vec![nonce_account_response(&auth, [0xBB; 32])]);

    let out = execute_t1(&test_reading(), Some("sensor ok"), &cfg, &rpc).unwrap();

    // The tx should be larger (SAS ix + memo ix + advance = 3 ixs).
    let tx_bytes = BASE64_STANDARD.decode(&out.tx_b64).unwrap();
    // Verify "sensor ok" UTF-8 appears in the tx bytes (memo data).
    assert!(
        tx_bytes.windows(9).any(|w| w == b"sensor ok"),
        "tx must contain the memo text"
    );
}

/// F5: an attacker-supplied memo longer than MEMO_MAX_BYTES is rejected before
/// any tx is built or any RPC call is made (the memo could otherwise blow past
/// Solana's 1232-byte tx limit or bloat the tx). validate_memo runs before
/// build_attest_ix + get_account_info, so no RPC is touched.
#[test]
fn execute_t1_rejects_oversized_memo() {
    let cfg = test_config();
    let rpc = MockRpc::new(vec![]); // never reached — validate_memo fails first
    let huge = "x".repeat(MEMO_MAX_BYTES + 34);
    let err = execute_t1(&test_reading(), Some(&huge), &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::InvalidReading(m) if m.contains("memo too long")));
}

#[test]
fn execute_t1_empty_memo_ignored() {
    let cfg = test_config();
    let rpc = mock_rpc_with_nonce();
    let out = execute_t1(&test_reading(), Some(""), &cfg, &rpc).unwrap();
    // Empty memo → no memo ix (same as None).
    assert!(!out.used_memo_fallback);
}

#[test]
fn execute_t1_invalid_reading_empty_sensor_id() {
    let cfg = test_config();
    let rpc = mock_rpc_with_nonce();
    let reading = SensorReading {
        sensor_id: "".to_string(),
        value: 24.7,
        unit: "celsius".to_string(),
        timestamp: 1_753_000_000,
    };
    let err = execute_t1(&reading, None, &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::InvalidReading(ref m) if m.contains("sensor_id")));
}

#[test]
fn execute_t1_invalid_reading_nan_value() {
    let cfg = test_config();
    let rpc = mock_rpc_with_nonce();
    let reading = SensorReading {
        sensor_id: "bme280".to_string(),
        value: f64::NAN,
        unit: "C".to_string(),
        timestamp: 1_753_000_000,
    };
    let err = execute_t1(&reading, None, &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::InvalidReading(ref m) if m.contains("finite")));
}

#[test]
fn execute_t1_nonce_account_not_found() {
    let cfg = test_config();
    // MockRpc returns value: null (account not found).
    let rpc = MockRpc::new(vec![json!({ "result": { "value": null } })]);
    let err = execute_t1(&test_reading(), None, &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::NonceAccount(ref m) if m.contains("not found")));
}

#[test]
fn execute_t1_nonce_account_uninitialized() {
    let cfg = test_config();
    // Build an uninitialized nonce account (state = 0).
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // version = Current
    data[4..8].copy_from_slice(&0u32.to_le_bytes()); // state = Uninitialized
    let rpc = MockRpc::new(vec![json!({
        "result": {
            "value": {
                "data": [BASE64_STANDARD.encode(&data), "base64"],
                "owner": "11111111111111111111111111111111",
                "lamports": 100000000,
                "executable": false
            }
        }
    })]);
    let err = execute_t1(&test_reading(), None, &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::NonceAccount(ref m) if m.contains("uninitialized")));
}

#[test]
fn execute_t1_nonce_authority_mismatch() {
    let cfg = test_config(); // nonce_authority = TOKEN
    // Script a nonce account with a DIFFERENT authority (SYSTEM).
    let wrong_auth = Pubkey::from_str(SYSTEM).unwrap();
    let rpc = MockRpc::new(vec![nonce_account_response(&wrong_auth, [0xCC; 32])]);
    let err = execute_t1(&test_reading(), None, &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::NonceAccount(ref m) if m.contains("authority mismatch")));
}

#[test]
fn execute_t1_rpc_error() {
    let cfg = test_config();
    // MockRpc returns a JSON-RPC error.
    let rpc = MockRpc::new(vec![json!({
        "error": { "code": -32603, "message": "internal error" }
    })]);
    let err = execute_t1(&test_reading(), None, &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::Rpc(_)));
}

// ── Slice E: memo fallback tests ──

use depin_attest::depin_attest::execute_t1_entry;

fn t1_config_with_memo_fallback() -> AttestConfig {
    let mut s = valid_t1_section();
    s.insert("memo_fallback".to_string(), "true".to_string());
    AttestConfig::from_section(&s).unwrap()
}

#[test]
fn memo_fallback_happy_path() {
    let cfg = t1_config_with_memo_fallback();
    let auth = Pubkey::from_str(SYSTEM).unwrap();
    let rpc = MockRpc::new(vec![nonce_account_response(&auth, [0xDD; 32])]);

    let out = execute_t1_entry(&test_reading(), None, &cfg, &rpc).unwrap();

    assert!(out.used_memo_fallback, "must use memo fallback");
    assert!(out.signature.is_none());
    assert!(estimate_tokens(&out.summary) <= 200);
    assert!(out.summary.len() <= 800);
    assert!(out.summary.contains("memo attestation"), "summary: {}", out.summary);

    // The tx contains the memo text.
    let tx_bytes = BASE64_STANDARD.decode(&out.tx_b64).unwrap();
    let memo_text = "palinurus: bme280-1=24.7celsius @ 1753000000";
    assert!(
        tx_bytes.windows(memo_text.len()).any(|w| w == memo_text.as_bytes()),
        "tx must contain the memo text"
    );
}

#[test]
fn memo_fallback_with_optional_memo() {
    let cfg = t1_config_with_memo_fallback();
    let auth = Pubkey::from_str(SYSTEM).unwrap();
    let rpc = MockRpc::new(vec![nonce_account_response(&auth, [0xEE; 32])]);

    let out = execute_t1_entry(&test_reading(), Some("extra note"), &cfg, &rpc).unwrap();

    assert!(out.used_memo_fallback);
    let tx_bytes = BASE64_STANDARD.decode(&out.tx_b64).unwrap();
    assert!(tx_bytes.windows(10).any(|w| w == b"extra note"));
}

#[test]
fn memo_fallback_explorer_url_points_to_nonce_account() {
    let cfg = t1_config_with_memo_fallback();
    let auth = Pubkey::from_str(SYSTEM).unwrap();
    let rpc = MockRpc::new(vec![nonce_account_response(&auth, [0xFF; 32])]);

    let out = execute_t1_entry(&test_reading(), None, &cfg, &rpc).unwrap();
    // Explorer URL should contain the nonce_account address, not a SAS PDA.
    assert!(out.explorer_url.contains(&cfg.nonce_account.to_string()));
}

#[test]
fn memo_fallback_validates_reading() {
    let cfg = t1_config_with_memo_fallback();
    let rpc = mock_rpc_with_nonce();
    let reading = SensorReading {
        sensor_id: "".to_string(),
        value: 1.0,
        unit: "C".to_string(),
        timestamp: 100,
    };
    let err = execute_t1_entry(&reading, None, &cfg, &rpc).unwrap_err();
    assert!(matches!(err, AttestError::InvalidReading(_)));
}

#[test]
fn sas_path_used_when_memo_fallback_false() {
    // Default config (memo_fallback = false) → SAS path.
    let cfg = test_config();
    let auth = Pubkey::from_str(TOKEN).unwrap();
    let rpc = MockRpc::new(vec![nonce_account_response(&auth, [0x11; 32])]);

    let out = execute_t1_entry(&test_reading(), None, &cfg, &rpc).unwrap();
    assert!(!out.used_memo_fallback, "should use SAS path");
}

// ── Slice F: T2 custody guard tests ──

use depin_attest::depin_attest::{
    enforce_daily_cap, enforce_lamport_cap, enforce_program_allowlist,
    enforce_session_key_identity, DailyCapState,
};

/// Build a T2 config where the session key is authority + payer + nonce_authority.
fn t2_test_config() -> AttestConfig {
    let secret = [99u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_b58 = bs58::encode(pubkey_bytes).into_string();

    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    s.insert("session_key".to_string(), bs58::encode(secret).into_string());
    // Override authority, payer, nonce_authority to the session key's pubkey.
    s.insert("authority".to_string(), pubkey_b58.clone());
    s.insert("payer".to_string(), pubkey_b58.clone());
    s.insert("nonce_authority".to_string(), pubkey_b58);
    AttestConfig::from_section(&s).unwrap()
}

#[test]
fn allowlist_allows_system_sas_memo() {
    let ixs = vec![
        palinurus_core::Instruction {
            program_id: Pubkey::from_str(SYSTEM).unwrap(),
            accounts: vec![],
            // System is allowed only as AdvanceNonceAccount (disc 0x04); the
            // hardened allowlist rejects any other System variant (e.g. Transfer).
            data: vec![0x04, 0x00, 0x00, 0x00],
        },
        palinurus_core::Instruction {
            program_id: Pubkey::from_str(SAS).unwrap(),
            accounts: vec![],
            data: vec![],
        },
        palinurus_core::Instruction {
            program_id: Pubkey::from_str(MEMO).unwrap(),
            accounts: vec![],
            data: vec![],
        },
    ];
    assert!(enforce_program_allowlist(&ixs).is_ok());
}

#[test]
fn allowlist_rejects_spl_token() {
    let ixs = vec![palinurus_core::Instruction {
        program_id: Pubkey::from_str(TOKEN).unwrap(),
        accounts: vec![],
        data: vec![],
    }];
    let err = enforce_program_allowlist(&ixs).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("not allowed")));
}

#[test]
fn allowlist_rejects_random_program() {
    let random = Pubkey::from_bytes([0xAB; 32]);
    let ixs = vec![palinurus_core::Instruction {
        program_id: random,
        accounts: vec![],
        data: vec![],
    }];
    let err = enforce_program_allowlist(&ixs).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("not allowed")));
}

#[test]
fn identity_allows_all_match() {
    let cfg = t2_test_config();
    assert!(enforce_session_key_identity(&cfg).is_ok());
}

#[test]
fn identity_rejects_authority_mismatch() {
    let mut cfg = t2_test_config();
    // Change authority to a different key.
    cfg.authority = Pubkey::from_bytes([0xFF; 32]);
    let err = enforce_session_key_identity(&cfg).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("authority")));
}

#[test]
fn identity_rejects_payer_mismatch() {
    let mut cfg = t2_test_config();
    cfg.payer = Pubkey::from_bytes([0xFF; 32]);
    let err = enforce_session_key_identity(&cfg).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("payer")));
}

#[test]
fn identity_rejects_nonce_authority_mismatch() {
    let mut cfg = t2_test_config();
    cfg.nonce_authority = Pubkey::from_bytes([0xFF; 32]);
    let err = enforce_session_key_identity(&cfg).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("nonce_authority")));
}

#[test]
fn identity_rejects_missing_session_key() {
    let cfg = test_config(); // T1 config, no session key
    let err = enforce_session_key_identity(&cfg).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("requires a session key")));
}

#[test]
fn daily_cap_allows_under_cap() {
    let mut state = DailyCapState::default();
    for _ in 0..5 {
        assert!(enforce_daily_cap(&mut state, 100, 10).is_ok());
    }
    assert_eq!(state.count, 5);
}

#[test]
fn daily_cap_rejects_over_cap() {
    let mut state = DailyCapState { last_day: 100, count: 10 };
    let err = enforce_daily_cap(&mut state, 100, 10).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("cap exceeded")));
}

#[test]
fn daily_cap_resets_on_day_rollover() {
    let mut state = DailyCapState { last_day: 100, count: 10 };
    // New day → resets.
    assert!(enforce_daily_cap(&mut state, 101, 10).is_ok());
    assert_eq!(state.count, 1);
    assert_eq!(state.last_day, 101);
}

#[test]
fn lamport_cap_allows_small_fee() {
    assert!(enforce_lamport_cap(5000, 1, 10000).is_ok());
}

#[test]
fn lamport_cap_rejects_over_cap() {
    let err = enforce_lamport_cap(5000, 3, 10000).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("exceeds per-tx cap")));
}

// ── Slice G: execute_t2 tests ──

use depin_attest::depin_attest::{execute_entry, execute_t2};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use palinurus_core::versioned_tx::serialize_message;
use palinurus_core::build_with_durable_nonce;

/// Build a T2 config + the session key's pubkey for test assertions.
fn t2_config_and_pubkey() -> (AttestConfig, [u8; 32]) {
    let secret = [99u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_b58 = bs58::encode(pubkey_bytes).into_string();

    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    s.insert("session_key".to_string(), bs58::encode(secret).into_string());
    s.insert("authority".to_string(), pubkey_b58.clone());
    s.insert("payer".to_string(), pubkey_b58.clone());
    s.insert("nonce_authority".to_string(), pubkey_b58);
    // nonce_account = TOKEN (from valid_t1_section), so the mock nonce account
    // must have authority = pubkey_bytes.
    let cfg = AttestConfig::from_section(&s).unwrap();
    (cfg, pubkey_bytes)
}

/// MockRpc with a nonce account (authority = session key) + a sendTransaction response.
fn mock_rpc_for_t2(authority: &Pubkey) -> MockRpc {
    let nonce_resp = nonce_account_response(authority, [0x42; 32]);
    let send_resp = json!({ "result": "mock_tx_signature_abc123" });
    MockRpc::new(vec![nonce_resp, send_resp])
}

#[test]
fn execute_t2_happy_path() {
    let (cfg, sk_pubkey) = t2_config_and_pubkey();
    let auth = Pubkey::from_bytes(sk_pubkey);
    let rpc = mock_rpc_for_t2(&auth);
    let mut cap = DailyCapState::default();

    let out = execute_t2(&test_reading(), None, &cfg, &rpc, &mut cap).expect("T2 happy path");

    // Signature is present.
    assert!(out.signature.is_some());
    assert_eq!(out.signature.as_ref().unwrap(), "mock_tx_signature_abc123");

    // tx_b64 decodes to a signed tx.
    let tx_bytes = BASE64_STANDARD.decode(&out.tx_b64).unwrap();
    // Wire format: [compact-u16 sig_count=1] [64B sig] [message...]
    assert_eq!(tx_bytes[0], 1, "first byte = sig count (1)");
    let sig_bytes: [u8; 64] = tx_bytes[1..65].try_into().unwrap();
    let msg_bytes = &tx_bytes[65..];

    // Verify the signature against the session key's pubkey.
    let vk = VerifyingKey::from_bytes(&sk_pubkey).unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    assert!(
        vk.verify(msg_bytes, &sig).is_ok(),
        "signature must verify against the session key's pubkey"
    );

    // Summary ≤200 tokens.
    assert!(estimate_tokens(&out.summary) <= 200);
    assert!(out.summary.contains("attested + submitted"));
    assert!(!out.used_memo_fallback);
}

#[test]
fn execute_t2_signature_matches_message() {
    // Cross-check: the signed message bytes == serialize_message(tx.message).
    let (cfg, _) = t2_config_and_pubkey();
    let auth = Pubkey::from_bytes(cfg.authority.to_bytes());
    let rpc = mock_rpc_for_t2(&auth);
    let mut cap = DailyCapState::default();

    let out = execute_t2(&test_reading(), None, &cfg, &rpc, &mut cap).unwrap();

    // Reconstruct the tx (unsigned) to get the message, then verify the sig is over it.
    let (sas_ix, _, _) = build_attest_ix(&test_reading(), &cfg).unwrap();
    let user_ixs = vec![sas_ix];
    // We need the nonce account's durable_nonce. The mock used [0x42; 32].
    let tx = build_with_durable_nonce(
        &user_ixs,
        cfg.payer,
        cfg.nonce_account,
        [0x42; 32], // the durable nonce from the mock
        cfg.nonce_authority,
    );
    let expected_msg = serialize_message(&tx.message);

    let tx_bytes = BASE64_STANDARD.decode(&out.tx_b64).unwrap();
    let msg_bytes = &tx_bytes[65..]; // skip sig_count(1) + sig(64)
    assert_eq!(msg_bytes, expected_msg.as_slice(), "signed message must match serialize_message");
}

#[test]
fn execute_t2_memo_fallback() {
    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    s.insert("memo_fallback".to_string(), "true".to_string());
    let secret = [77u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let pk_b58 = bs58::encode(sk.verifying_key().to_bytes()).into_string();
    s.insert("session_key".to_string(), bs58::encode(secret).into_string());
    s.insert("authority".to_string(), pk_b58.clone());
    s.insert("payer".to_string(), pk_b58.clone());
    s.insert("nonce_authority".to_string(), pk_b58);
    let cfg = AttestConfig::from_section(&s).unwrap();

    let auth = Pubkey::from_bytes(sk.verifying_key().to_bytes());
    let rpc = mock_rpc_for_t2(&auth);
    let mut cap = DailyCapState::default();

    let out = execute_t2(&test_reading(), None, &cfg, &rpc, &mut cap).unwrap();
    assert!(out.used_memo_fallback);
    assert!(out.signature.is_some());
}

#[test]
fn execute_t2_daily_cap_exceeded() {
    let (cfg, sk_pubkey) = t2_config_and_pubkey();
    let auth = Pubkey::from_bytes(sk_pubkey);
    let rpc = mock_rpc_for_t2(&auth);
    // Pre-set the daily cap to the limit.
    let mut cap = DailyCapState { last_day: 1_753_000_000 / 86400, count: 100 };

    let err = execute_t2(&test_reading(), None, &cfg, &rpc, &mut cap).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("cap exceeded")));
}

#[test]
fn execute_t2_identity_mismatch_rejected() {
    // Build a T2 config where authority != session key.
    let secret = [99u8; 32];
    let mut s = valid_t1_section();
    s.insert("custody_mode".to_string(), "t2".to_string());
    s.insert("session_key".to_string(), bs58::encode(secret).into_string());
    // authority = SYSTEM (from valid_t1_section), NOT the session key's pubkey.
    // This should fail the identity check.
    let cfg = AttestConfig::from_section(&s).unwrap();
    let rpc = mock_rpc_for_t2(&Pubkey::from_str(SYSTEM).unwrap());
    let mut cap = DailyCapState::default();

    let err = execute_t2(&test_reading(), None, &cfg, &rpc, &mut cap).unwrap_err();
    assert!(matches!(err, AttestError::Custody(ref m) if m.contains("authority")));
}

#[test]
fn execute_entry_routes_t2() {
    let (cfg, sk_pubkey) = t2_config_and_pubkey();
    let auth = Pubkey::from_bytes(sk_pubkey);
    let rpc = mock_rpc_for_t2(&auth);
    let mut cap = DailyCapState::default();

    let out = execute_entry(&test_reading(), None, &cfg, &rpc, Some(&mut cap)).unwrap();
    assert!(out.signature.is_some(), "T2 via execute_entry must produce a signature");
}

#[test]
fn execute_entry_routes_t1() {
    let cfg = test_config(); // T1 config
    let auth = Pubkey::from_str(TOKEN).unwrap();
    let rpc = MockRpc::new(vec![nonce_account_response(&auth, [0x55; 32])]);

    let out = execute_entry(&test_reading(), None, &cfg, &rpc, None).unwrap();
    assert!(out.signature.is_none(), "T1 via execute_entry must NOT produce a signature");
}
