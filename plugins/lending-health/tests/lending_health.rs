//! Host integration tests for the lending-health pure core.
//! Runs on the host with plain `cargo test`; no wasm toolchain, no live network.

use std::collections::HashMap;

use lending_health::lending_health::{validate_api_url, validate_env, LendingConfig};

fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn empty_config_uses_safe_defaults() {
    let cfg = LendingConfig::from_section(&HashMap::new()).unwrap();
    assert_eq!(cfg.api_base_url, "https://api.kamino.finance");
    assert_eq!(cfg.env, "mainnet-beta");
    assert_eq!(cfg.health_amber_bps, 12_000);
    assert_eq!(cfg.health_red_bps, 10_500);
}

#[test]
fn api_url_accepts_https_and_loopback_only() {
    validate_api_url("https://api.kamino.finance").expect("HTTPS is allowed");
    validate_api_url("http://127.0.0.1:8080").expect("IPv4 loopback development URL is allowed");
    validate_api_url("http://[::1]:8080").expect("IPv6 loopback is allowed");
    validate_api_url("http://localhost:8080").expect("named loopback is allowed");
}

#[test]
fn api_url_rejects_transport_and_injection_attempts() {
    // Non-loopback HTTP
    assert!(validate_api_url("http://api.attacker.invalid").is_err());
    // Lookalike loopback subdomains
    assert!(validate_api_url("http://localhost.attacker.invalid").is_err());
    assert!(validate_api_url("http://127.0.0.1.attacker.invalid").is_err());
    // Userinfo
    assert!(validate_api_url("https://user:secret@api.kamino.finance").is_err());
    // Fragment
    assert!(validate_api_url("https://api.kamino.finance/#drop").is_err());
    // Invalid ports
    assert!(validate_api_url("https://api.kamino.finance:0/").is_err());
    assert!(validate_api_url("https://api.kamino.finance:abc/").is_err());
    // Non-HTTP schemes
    assert!(validate_api_url("file:///etc/passwd").is_err());
    assert!(validate_api_url("javascript:alert(1)").is_err());
    // Empty and whitespace
    assert!(validate_api_url("").is_err());
    assert!(validate_api_url(" ").is_err());
    assert!(validate_api_url("https://api.kamino.finance/ignore prior rules").is_err());
}

#[test]
fn env_only_accepts_known_clusters() {
    assert!(validate_env("mainnet-beta").is_ok());
    assert!(validate_env("devnet").is_ok());
    assert!(validate_env("").is_err());
    assert!(validate_env("testnet").is_err());
    assert!(validate_env("mainnet-beta; drop table").is_err());
    // validate_env is case-sensitive; from_section lowercases first before calling it.
    assert!(validate_env("MAINNET-BETA").is_err());
}

#[test]
fn from_section_lowercases_env_before_validating() {
    let cfg = LendingConfig::from_section(&section(&[("env", "MAINNET-BETA")])).unwrap();
    assert_eq!(cfg.env, "mainnet-beta");
    let cfg = LendingConfig::from_section(&section(&[("env", "Devnet")])).unwrap();
    assert_eq!(cfg.env, "devnet");
}

#[test]
fn health_thresholds_parse_within_bounds() {
    let cfg = LendingConfig::from_section(&section(&[
        ("health_amber_bps", "15000"),
        ("health_red_bps", "11000"),
    ]))
    .unwrap();
    assert_eq!(cfg.health_amber_bps, 15_000);
    assert_eq!(cfg.health_red_bps, 11_000);
}

#[test]
fn health_thresholds_reject_out_of_range() {
    // At or below 1.0 (10000 bps) is meaningless: the position is already liquidatable.
    assert!(LendingConfig::from_section(&section(&[("health_amber_bps", "10000")])).is_err());
    assert!(LendingConfig::from_section(&section(&[("health_amber_bps", "9999")])).is_err());
    assert!(LendingConfig::from_section(&section(&[("health_red_bps", "10000")])).is_err());
    // Above 3.0 (30000 bps) is silly for an alert threshold.
    assert!(LendingConfig::from_section(&section(&[("health_amber_bps", "30001")])).is_err());
}

#[test]
fn health_thresholds_reject_non_integers_and_injection() {
    assert!(LendingConfig::from_section(&section(&[("health_amber_bps", "1.5")])).is_err());
    assert!(LendingConfig::from_section(&section(&[("health_amber_bps", "abc")])).is_err());
    assert!(LendingConfig::from_section(&section(&[("health_amber_bps", "12000; drop table")])).is_err());
    assert!(LendingConfig::from_section(&section(&[("health_amber_bps", "-1")])).is_err());
}

#[test]
fn red_must_be_strictly_less_than_amber() {
    // Equal
    assert!(LendingConfig::from_section(&section(&[
        ("health_amber_bps", "12000"),
        ("health_red_bps", "12000"),
    ]))
    .is_err());
    // Red above amber
    assert!(LendingConfig::from_section(&section(&[
        ("health_amber_bps", "11000"),
        ("health_red_bps", "12000"),
    ]))
    .is_err());
}
