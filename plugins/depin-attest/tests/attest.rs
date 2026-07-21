use std::collections::HashMap;

use base64::Engine;
use depin_attest::attest::{
    attestation_hash, build_memo, execute, format_reading, parse_args_strict, period_bucket,
    validate_policy, AttestConfig,
};
use depin_attest::keys::Pubkey;
use depin_attest::nonce::NONCE_ACCOUNT_SIZE;
use depin_attest::rpc::HttpClient;
use depin_attest::{CoreError, CoreResult};
use serde_json::{json, Value};

const RPC_URL: &str = "https://rpc.test";

struct MapHttp {
    responses: HashMap<String, Value>,
}

impl MapHttp {
    fn with_nonce(nonce_account: &Pubkey, authority: &Pubkey, durable_nonce: &[u8; 32]) -> Self {
        let nonce_data = initialized_nonce_fixture(authority, durable_nonce, 5_000);
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_data);
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [
                nonce_account.to_base58(),
                { "encoding": "base64" }
            ]
        });
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "value": {
                    "data": [nonce_b64, "base64"]
                }
            }
        });

        Self {
            responses: HashMap::from([(fingerprint(RPC_URL, &body), response)]),
        }
    }
}

impl HttpClient for MapHttp {
    fn post_json(&self, url: &str, body: &Value) -> CoreResult<Value> {
        self.responses
            .get(&fingerprint(url, body))
            .cloned()
            .ok_or_else(|| CoreError::msg(format!("missing mock response for {url}: {body}")))
    }
}

fn fingerprint(url: &str, body: &Value) -> String {
    format!("{url}\n{body}")
}

fn initialized_nonce_fixture(authority: &Pubkey, durable_nonce: &[u8; 32], fee: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(NONCE_ACCOUNT_SIZE);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(authority.as_bytes());
    data.extend_from_slice(durable_nonce);
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

fn execute_config(payer: &Pubkey, nonce_account: &Pubkey) -> HashMap<String, String> {
    HashMap::from([
        ("payer".to_string(), payer.to_base58()),
        ("nonce_account".to_string(), nonce_account.to_base58()),
        ("rpc_url".to_string(), RPC_URL.to_string()),
    ])
}

#[test]
fn formats_reading_with_six_decimal_places_and_trims_trailing_zeros() {
    assert_eq!(format_reading(21.2345678), "21.234568");
    assert_eq!(format_reading(42.0), "42");
    assert_eq!(format_reading(-0.1250001), "-0.125");
}

#[test]
fn buckets_periods_into_five_minute_windows() {
    assert_eq!(period_bucket(0), 0);
    assert_eq!(period_bucket(299), 0);
    assert_eq!(period_bucket(300), 1);
    assert_eq!(period_bucket(1_720_000_000), 5_733_333);
}

#[test]
fn hashes_canonical_attestation_payload_stably() {
    let hash = attestation_hash("device-7", "temperature", "21.234568", "celsius", 5_733_333);

    assert_eq!(
        hash,
        "162751dec7d2299ebf6a032862b6a5fe59aa3f1abe5ece3b70a0c9b3da8f682a"
    );
}

#[test]
fn builds_compact_memo_with_hash_prefix_and_length_limit() {
    let hash = attestation_hash("device-7", "temperature", "21.234568", "celsius", 5_733_333);
    let memo = build_memo(
        "ZCDEPIN",
        "device-7",
        "temperature",
        "21.234568",
        "celsius",
        5_733_333,
        &hash[..12],
    )
    .unwrap();

    assert_eq!(
        memo,
        "ZCDEPIN|device-7|temperature|21.234568|celsius|5733333|162751dec7d2"
    );

    let huge_device_id = "d".repeat(600);
    let err = build_memo(
        "ZCDEPIN",
        &huge_device_id,
        "temperature",
        "1",
        "celsius",
        5_733_333,
        &hash[..12],
    )
    .unwrap_err();
    assert!(err.contains("memo exceeds 566 bytes"));
}

#[test]
fn uses_default_allowlist_when_allowed_metrics_absent() {
    let cfg = AttestConfig::from_section(&HashMap::new()).unwrap();
    let args = parse_args_strict(
        r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature"}"#,
    )
    .unwrap();

    validate_policy(&cfg, &args).unwrap();
}

#[test]
fn accepts_numeric_string_readings_from_llm_tool_args() {
    let args = parse_args_strict(
        r#"{"device_id":"device-7","reading":"21.4","unit":"celsius","metric":"temperature"}"#,
    )
    .unwrap();
    assert!((args.reading - 21.4).abs() < 1e-9);
}

#[test]
fn rejects_non_numeric_string_readings() {
    let err = parse_args_strict(
        r#"{"device_id":"device-7","reading":"hot","unit":"celsius","metric":"temperature"}"#,
    )
    .unwrap_err();
    assert!(err.contains("reading must be a number"));
}

#[test]
fn rejects_metrics_outside_allowlist() {
    let cfg = AttestConfig::from_section(&HashMap::new()).unwrap();
    let args =
        parse_args_strict(r#"{"device_id":"device-7","reading":12.5,"unit":"ppm","metric":"co2"}"#)
            .unwrap();

    let err = validate_policy(&cfg, &args).unwrap_err();
    assert!(err.contains("metric is not allowlisted"));
}

#[test]
fn rejects_present_but_empty_allowed_metrics() {
    let mut section = HashMap::new();
    section.insert("allowed_metrics".to_string(), "   ".to_string());

    let err = AttestConfig::from_section(&section).unwrap_err();
    assert_eq!(err, "allowed_metrics is empty");
}

#[test]
fn rejects_readings_outside_configured_cap() {
    let mut section = HashMap::new();
    section.insert("max_abs_reading".to_string(), "10".to_string());
    let cfg = AttestConfig::from_section(&section).unwrap();
    let args = parse_args_strict(
        r#"{"device_id":"device-7","reading":10.001,"unit":"celsius","metric":"temperature"}"#,
    )
    .unwrap();

    let err = validate_policy(&cfg, &args).unwrap_err();
    assert!(err.contains("reading exceeds max_abs_reading"));
}

#[test]
fn rejects_delimiters_and_control_characters_in_memo_fields() {
    let cfg = AttestConfig {
        allowed_metrics: vec![
            "temperature".to_string(),
            "temperature|humidity".to_string(),
            "uptime\nseconds".to_string(),
        ],
        max_abs_reading: 1_000_000.0,
    };

    for (label, json) in [
        (
            "device_id",
            r#"{"device_id":"device|7","reading":12.5,"unit":"celsius","metric":"temperature"}"#,
        ),
        (
            "metric",
            r#"{"device_id":"device-7","reading":12.5,"unit":"celsius","metric":"temperature|humidity"}"#,
        ),
        (
            "unit",
            "{\"device_id\":\"device-7\",\"reading\":12.5,\"unit\":\"uptime\\nseconds\",\"metric\":\"temperature\"}",
        ),
    ] {
        let args = parse_args_strict(json).unwrap();
        let err = validate_policy(&cfg, &args).unwrap_err();

        assert!(
            err.contains("must not contain `|` or control characters"),
            "{label}: {err}"
        );
    }
}

#[test]
fn execute_builds_durable_unsigned_memo_tx_summary() {
    let payer = Pubkey::new([1u8; 32]);
    let nonce_account = Pubkey::new([2u8; 32]);
    let durable_nonce = [7u8; 32];
    let http = MapHttp::with_nonce(&nonce_account, &payer, &durable_nonce);

    let output = execute(
        r#"{"device_id":"device-7","reading":21.2345678,"unit":"celsius","metric":"temperature"}"#,
        &execute_config(&payer, &nonce_account),
        &http,
        1_720_000_000,
    )
    .expect("execute attest");

    assert_eq!(output.durability, "durable-nonce");
    assert_eq!(output.nonce_account, nonce_account.to_base58());
    assert_eq!(
        output.attestation_hash,
        "162751dec7d2299ebf6a032862b6a5fe59aa3f1abe5ece3b70a0c9b3da8f682a"
    );
    assert!(!output.unsigned_tx_base64.is_empty());
    assert!(output.summary.chars().count() <= 900);
    assert_eq!(
        output.summary,
        format!(
            "DEPIN attest OK\ndevice: device-7\nmetric: temperature=21.234568 celsius\nperiod: 5733333\nhash: 162751dec7d2…\nnonce: {}\ndurability: durable-nonce\nunsigned_tx_base64: {}",
            nonce_account.to_base58(),
            output.unsigned_tx_base64
        )
    );

    let tx = base64::engine::general_purpose::STANDARD
        .decode(&output.unsigned_tx_base64)
        .expect("base64 tx");
    assert_eq!(tx[0], 1);
    assert_eq!(&tx[1..65], &[0u8; 64]);
}

#[test]
fn execute_rejects_nonce_authority_that_does_not_match_payer() {
    let payer = Pubkey::new([1u8; 32]);
    let nonce_account = Pubkey::new([2u8; 32]);
    let wrong_authority = Pubkey::new([3u8; 32]);
    let durable_nonce = [7u8; 32];
    let http = MapHttp::with_nonce(&nonce_account, &wrong_authority, &durable_nonce);

    let err = execute(
        r#"{"device_id":"device-7","reading":21.2345678,"unit":"celsius","metric":"temperature"}"#,
        &execute_config(&payer, &nonce_account),
        &http,
        1_720_000_000,
    )
    .unwrap_err();

    assert!(err.contains("nonce authority must match payer"));
}
