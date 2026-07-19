//! Host-run tests for sns-resolve core.
use sns_resolve::*;

#[test]
fn test_resolution_result_serialization() {
    let r = ResolutionResult {
        name: "alice.sol".to_string(),
        address: Some("7xK...abcd".to_string()),
        found: true,
        message: "Resolved alice.sol to 7xK...abcd".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("alice.sol"));
    assert!(json.contains("7xK"));
}

#[test]
fn test_not_found_result() {
    let r = ResolutionResult {
        name: "notexist.sol".to_string(),
        address: None,
        found: false,
        message: "Domain notexist.sol not found or not registered".to_string(),
    };
    assert!(r.address.is_none());
    assert!(!r.found);
}

#[test]
fn test_strip_sol_suffix() {
    let name = "alice.sol";
    let stripped = name.strip_suffix(".sol").unwrap_or(name);
    assert_eq!(stripped, "alice");
}
