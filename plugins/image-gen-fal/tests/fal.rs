//! Host tests for the pure fal.ai core. No wasm toolchain required:
//! `cargo test` compiles the rlib without the `waki`/wasm-only dependencies.

use std::collections::HashMap;

use image_gen_fal::fal::{
    api_key, parameters_schema, parse_args, parse_response, success_output, truncate_error,
    DEFAULT_MODEL, VALID_SIZES,
};
use serde_json::json;

// ── parse_args ───────────────────────────────────────────────────

#[test]
fn defaults_are_applied_when_only_prompt_is_given() {
    let req = parse_args(&json!({"prompt": "a crab made of rust"})).unwrap();
    assert_eq!(req.prompt, "a crab made of rust");
    assert_eq!(req.size, "square_hd");
    assert_eq!(req.model, DEFAULT_MODEL);
}

#[test]
fn prompt_is_trimmed() {
    let req = parse_args(&json!({"prompt": "  spaced  "})).unwrap();
    assert_eq!(req.prompt, "spaced");
}

#[test]
fn missing_or_blank_prompt_is_rejected() {
    for args in [json!({}), json!({"prompt": ""}), json!({"prompt": "   "})] {
        let err = parse_args(&args).unwrap_err();
        assert!(err.contains("prompt"), "unexpected error: {err}");
    }
}

#[test]
fn every_documented_size_is_accepted() {
    for size in VALID_SIZES {
        let req = parse_args(&json!({"prompt": "x", "size": size})).unwrap();
        assert_eq!(&req.size, size);
    }
}

#[test]
fn unknown_size_is_rejected_and_lists_valid_values() {
    let err = parse_args(&json!({"prompt": "x", "size": "gigantic"})).unwrap_err();
    assert!(err.contains("gigantic"));
    assert!(err.contains("square_hd"), "error should list valid sizes");
}

#[test]
fn blank_size_or_model_falls_back_to_defaults() {
    let req = parse_args(&json!({"prompt": "x", "size": "  ", "model": "  "})).unwrap();
    assert_eq!(req.size, "square_hd");
    assert_eq!(req.model, DEFAULT_MODEL);
}

#[test]
fn path_traversal_and_url_smuggling_in_model_are_rejected() {
    for bad in [
        "../../etc/passwd",
        "fal-ai/flux?key=leak",
        "fal-ai/flux#frag",
        "fal-ai\\flux",
        "/absolute/path",
    ] {
        let err = parse_args(&json!({"prompt": "x", "model": bad})).unwrap_err();
        assert!(
            err.contains("Invalid model identifier"),
            "expected rejection for {bad}, got: {err}"
        );
    }
}

#[test]
fn a_normal_model_path_is_accepted() {
    let req = parse_args(&json!({"prompt": "x", "model": "fal-ai/flux-pro/v1.1"})).unwrap();
    assert_eq!(req.model, "fal-ai/flux-pro/v1.1");
}

// ── request shaping ──────────────────────────────────────────────

#[test]
fn endpoint_and_body_match_the_fal_contract() {
    let req = parse_args(&json!({"prompt": "hello", "size": "landscape_16_9"})).unwrap();
    assert_eq!(req.endpoint(), format!("https://fal.run/{DEFAULT_MODEL}"));
    assert_eq!(
        req.body(),
        json!({"prompt": "hello", "image_size": "landscape_16_9", "num_images": 1})
    );
}

// ── api_key (config, not env) ────────────────────────────────────

#[test]
fn api_key_is_read_from_the_injected_config_section() {
    let cfg = HashMap::from([("api_key".to_string(), "fal-secret".to_string())]);
    assert_eq!(api_key(&cfg).unwrap(), "fal-secret");
}

#[test]
fn api_key_is_trimmed() {
    let cfg = HashMap::from([("api_key".to_string(), "  padded  ".to_string())]);
    assert_eq!(api_key(&cfg).unwrap(), "padded");
}

#[test]
fn missing_or_blank_api_key_points_at_the_config_section_not_an_env_var() {
    for cfg in [
        HashMap::new(),
        HashMap::from([("api_key".to_string(), "   ".to_string())]),
    ] {
        let err = api_key(&cfg).unwrap_err();
        assert!(err.contains("api_key"), "unexpected error: {err}");
        assert!(
            !err.contains("FAL_API_KEY") && !err.to_lowercase().contains("environment"),
            "error must not send operators back to the removed env flow: {err}"
        );
    }
}

// ── response parsing ─────────────────────────────────────────────

#[test]
fn image_url_is_extracted_from_a_well_formed_response() {
    let body = r#"{"images":[{"url":"https://fal.media/files/abc.png","width":1024}]}"#;
    assert_eq!(
        parse_response(body).unwrap(),
        "https://fal.media/files/abc.png"
    );
}

#[test]
fn malformed_or_imageless_responses_are_rejected() {
    for body in [
        "not json at all",
        r#"{"images":[]}"#,
        r#"{"detail":"quota exceeded"}"#,
        r#"{"images":[{"url":"  "}]}"#,
    ] {
        assert!(
            parse_response(body).is_err(),
            "expected error for body: {body}"
        );
    }
}

// ── error and output shaping ─────────────────────────────────────

#[test]
fn upstream_error_bodies_are_truncated_so_they_cannot_flood_context() {
    let huge = "x".repeat(5_000);
    let msg = truncate_error(&huge, 500);
    assert!(msg.contains("500"));
    assert!(msg.len() < 600, "error should be clipped, got {}", msg.len());
}

#[test]
fn success_output_names_the_model_prompt_and_url() {
    let req = parse_args(&json!({"prompt": "a crab"})).unwrap();
    let out = success_output(&req, "https://fal.media/x.png");
    assert!(out.contains(DEFAULT_MODEL));
    assert!(out.contains("a crab"));
    assert!(out.contains("https://fal.media/x.png"));
}

// ── schema ───────────────────────────────────────────────────────

#[test]
fn schema_requires_prompt_and_enumerates_sizes() {
    let schema = parameters_schema();
    assert_eq!(schema["required"], json!(["prompt"]));
    assert_eq!(schema["properties"]["size"]["enum"], json!(VALID_SIZES));
}
