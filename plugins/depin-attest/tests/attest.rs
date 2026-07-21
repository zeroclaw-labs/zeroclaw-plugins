use std::collections::HashMap;

use depin_attest::attest::{
    attestation_hash, build_memo, format_reading, parse_args_strict, period_bucket,
    validate_policy, AttestConfig,
};

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
