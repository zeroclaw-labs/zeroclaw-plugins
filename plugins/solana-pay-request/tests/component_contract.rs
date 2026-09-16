use solana_pay_request::pay_request::{parameters_schema, RequestError};

#[test]
fn manifest_grants_config_only_and_matches_component_identity() {
    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("name = \"solana-pay-request\""));
    assert!(manifest.contains("version = \"0.1.0\""));
    assert!(manifest.contains("wasm_path = \"solana_pay_request.wasm\""));
    assert!(manifest.contains("capabilities = [\"tool\"]"));
    assert!(manifest.contains("permissions = [\"config_read\"]"));
    assert!(!manifest.contains("http_client"));
}

#[test]
fn component_source_has_no_stdout_logging_or_http_client() {
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "println!",
        "eprintln!",
        "wasi:logging",
        "waki::",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "found forbidden source: {forbidden}"
        );
    }
    assert!(source.contains("log_record("));
    assert!(source.contains("world: \"tool-plugin\""));
}

#[test]
fn schema_is_valid_and_errors_expose_stable_codes() {
    let schema: serde_json::Value =
        serde_json::from_str(&parameters_schema()).expect("schema JSON");
    assert_eq!(schema["type"], "object");
    assert_eq!(RequestError::InvalidRecipient.code(), "invalid_recipient");
    assert_eq!(
        RequestError::RecipientNotAllowed.code(),
        "recipient_not_allowed"
    );
}
