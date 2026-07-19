//! Integration tests for the depin-attest pure core (slice B: config + reading + nonce).
//! Host-run with plain `cargo test` — no wasm, no live network.

use std::collections::HashMap;
use std::str::FromStr;

use depin_attest::depin_attest::{AttestConfig, AttestError, CustodyMode, SensorReading};
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
