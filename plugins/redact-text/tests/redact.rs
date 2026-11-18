//! Integration test for the redaction core, exercised exactly as the wasm
//! `execute` entry point drives it: deserialize the typed `__config` object the
//! host injects, then redact. This runs on the host with a plain `cargo test`
//! and covers the same code path the component runs inside the wasmtime host.
//!
//! The config values below are the JSON the host materializes from the operator's
//! string map according to `[config_schema]` in `manifest.toml` -- real booleans
//! and real arrays, not strings for the guest to parse.

use serde_json::{json, Value};

use redact_text::redact::{redact, RedactConfig, DEFAULT_REPLACEMENT};

/// The typed object a host injects when `config_read` is granted.
fn config(value: Value) -> RedactConfig {
    RedactConfig::from_json(&value).expect("host-validated config must deserialize")
}

/// What a plugin without the `config_read` grant receives: the host validates
/// the empty object against the schema and injects it.
fn withheld() -> RedactConfig {
    config(json!({}))
}

#[test]
fn masks_email_by_default() {
    let (out, n) = redact("ping bob@corp.com now", &withheld());
    assert_eq!(n, 1);
    assert!(!out.contains("bob@corp.com"));
    assert!(out.contains(DEFAULT_REPLACEMENT));
}

#[test]
fn masks_known_token_prefixes() {
    let cfg = withheld();
    for token in [
        "sk-abcdef0123456789",
        "ghp_abcd1234efgh5678",
        "xoxb-1-2-3abcXYZ",
    ] {
        let (out, n) = redact(&format!("key {token} end"), &cfg);
        assert!(n >= 1, "{token} should redact");
        assert!(!out.contains(token), "{token} should be masked");
    }
}

#[test]
fn masks_high_entropy_run() {
    let (out, n) = redact("token AKIA1234567890ABCDEF42 trailing", &withheld());
    assert_eq!(n, 1);
    assert!(!out.contains("AKIA1234567890ABCDEF42"));
}

#[test]
fn applies_configured_replacement_and_patterns() {
    let cfg = config(json!({
        "replacement": "<X>",
        "patterns": ["project-zeus", "internal-codename"],
    }));
    let (out, n) = redact("re: project-zeus and internal-codename", &cfg);
    assert_eq!(n, 2);
    assert!(!out.contains("project-zeus"));
    assert!(!out.contains("internal-codename"));
    assert_eq!(out.matches("<X>").count(), 2);
}

#[test]
fn email_masking_disabled_by_config() {
    // A real JSON boolean, which is what the host injects for a `boolean`
    // property. The pre-typed-config guest string-matched "false" here.
    let cfg = config(json!({"redact_emails": false}));
    let (out, n) = redact("mail a@b.com", &cfg);
    assert_eq!(n, 0);
    assert!(out.contains("a@b.com"));
}

#[test]
fn empty_config_is_the_unprivileged_jail_case() {
    // Without `config_read` the host validates and injects `{}`. Every schema
    // property is optional, so that must succeed and yield the defaults.
    let cfg = withheld();
    assert_eq!(cfg.replacement, DEFAULT_REPLACEMENT);
    assert!(cfg.redact_emails);
    assert!(cfg.patterns.is_empty());
    assert_eq!(cfg, RedactConfig::default());
}

#[test]
fn non_secret_text_passes_through_unchanged() {
    let input = "the quick brown fox jumps over 13 lazy dogs";
    let (out, n) = redact(input, &withheld());
    assert_eq!(n, 0);
    assert_eq!(out, input);
}

#[test]
fn absent_config_object_falls_back_to_defaults() {
    // `__config` missing entirely (a host that injected nothing) deserializes
    // as JSON null and must not be treated as a malformed object.
    assert_eq!(
        RedactConfig::from_json(&Value::Null).expect("null config is not an error"),
        RedactConfig::default()
    );
}

#[test]
fn partial_config_defaults_only_the_absent_keys() {
    let cfg = config(json!({"replacement": "###"}));
    assert_eq!(cfg.replacement, "###");
    assert!(cfg.redact_emails, "absent key keeps its default");
    assert!(cfg.patterns.is_empty(), "absent key keeps its default");
}

#[test]
fn every_declared_type_round_trips_from_one_injected_object() {
    // The exact payload shape `execute` receives once the host merges the
    // validated config in under `__config`.
    let injected = json!({
        "replacement": "<X>",
        "redact_emails": false,
        "patterns": ["alpha", "beta"],
    });
    let cfg = config(injected);
    assert_eq!(cfg.replacement, "<X>");
    assert!(!cfg.redact_emails);
    assert_eq!(cfg.patterns, vec!["alpha".to_string(), "beta".to_string()]);
}

#[test]
fn stringly_typed_values_are_rejected_rather_than_silently_defaulted() {
    // The pre-migration encodings. A schema-enforcing host never sends these,
    // so seeing one means manifest/guest drift. Failing loudly matters more
    // than usual here: silently defaulting would drop the operator's
    // `patterns` list and under-redact.
    for stale in [
        json!({"redact_emails": "false"}),
        json!({"patterns": "alpha,beta"}),
    ] {
        assert!(
            RedactConfig::from_json(&stale).is_err(),
            "stale string encoding {stale} must be rejected, not defaulted"
        );
    }
}

#[test]
fn config_errors_never_quote_the_offending_config_value() {
    // `patterns` holds the very strings an operator wants scrubbed, so a config
    // error must not echo one into a ToolResult that goes back to the model.
    let secret = "project-zeus-must-not-leak";
    let error = RedactConfig::from_json(&json!({"patterns": secret}))
        .expect_err("a string is not a valid patterns array");
    assert!(
        !error.contains(secret),
        "config error leaked the value: {error}"
    );

    let secret_replacement = "internal-codename-must-not-leak";
    let error = RedactConfig::from_json(&json!({"redact_emails": secret_replacement}))
        .expect_err("a string is not a valid boolean");
    assert!(
        !error.contains(secret_replacement),
        "config error leaked the value: {error}"
    );
}

#[test]
fn empty_pattern_is_dropped_instead_of_matching_every_boundary() {
    // `"".matches()` hits every character boundary, so an unfiltered empty
    // pattern rewrites the entire input into replacement markers. The schema
    // forbids it via `minLength`; the guest filters it regardless.
    let cfg = config(json!({"patterns": ["", "zeus"]}));
    assert_eq!(cfg.patterns, vec!["zeus".to_string()]);
    let (out, n) = redact("hello world", &cfg);
    assert_eq!(out, "hello world");
    assert_eq!(n, 0);
}

#[test]
fn empty_replacement_falls_back_to_the_default_marker() {
    // The schema forbids this via `minLength`; the guest still refuses to
    // redact secrets into an empty string if it ever arrives.
    let cfg = config(json!({"replacement": ""}));
    assert_eq!(cfg.replacement, DEFAULT_REPLACEMENT);
}
