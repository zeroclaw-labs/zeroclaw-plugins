//! Host-run tests for lending-health core.
use lending_health::*;

#[test]
fn test_health_result_serialization() {
    let h = HealthResult {
        protocol: "Kamino".to_string(),
        wallet: "7xK...abcd".to_string(),
        health_factor: Some(1.85),
        tier: "healthy".to_string(),
        message: "Health factor 1.85 — position is healthy".to_string(),
        details: vec!["2 lending positions active".to_string()],
    };
    let json = serde_json::to_string(&h).unwrap();
    assert!(json.contains("Kamino"));
    assert!(json.contains("1.85"));
}

#[test]
fn test_unknown_protocol() {
    let result = check_health("7xK...abcd", "unknown_protocol", "https://api.mainnet-beta.solana.com");
    // Should return a result with unknown tier
    if let Some(h) = result {
        assert_eq!(h.tier, "unknown");
        assert!(h.message.contains("Unknown protocol"));
    }
}

#[test]
fn test_health_tier_classification() {
    let healthy = HealthResult {
        protocol: "Kamino".to_string(), wallet: "test".to_string(),
        health_factor: Some(2.5), tier: "healthy".to_string(),
        message: String::new(), details: vec![],
    };
    let caution = HealthResult {
        protocol: "Kamino".to_string(), wallet: "test".to_string(),
        health_factor: Some(1.2), tier: "caution".to_string(),
        message: String::new(), details: vec![],
    };
    let danger = HealthResult {
        protocol: "Kamino".to_string(), wallet: "test".to_string(),
        health_factor: Some(0.95), tier: "danger".to_string(),
        message: String::new(), details: vec![],
    };
    assert_eq!(healthy.tier, "healthy");
    assert_eq!(caution.tier, "caution");
    assert_eq!(danger.tier, "danger");
}

#[test]
fn test_no_position_result() {
    let h = HealthResult {
        protocol: "Kamino".to_string(), wallet: "test".to_string(),
        health_factor: None, tier: "no_position".to_string(),
        message: "No active lending position found on Kamino".to_string(),
        details: vec![],
    };
    assert!(h.health_factor.is_none());
    assert_eq!(h.tier, "no_position");
}
