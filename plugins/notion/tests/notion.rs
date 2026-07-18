//! Host tests for the pure Notion core — the same mapping/payload logic the
//! wasm component runs, exercised with plain `cargo test` (no token, no network,
//! no wasm).

use notion::notion::{
    build_complete_payload, build_query_body, build_recover_payload, build_rich_text_payload,
    build_status_filter, build_status_payload, build_status_update_payload, database_url,
    detect_status_type, extract_text_from_property, page_url, parse_pending, query_url,
    truncate_result, NotionConfig, MAX_RESULT_LENGTH,
};
use serde_json::json;

#[test]
fn config_parses_and_defaults() {
    let cfg = NotionConfig::from_json(
        r#"{"api_key":"secret_abc","database_id":"db123","status_property":"State"}"#,
    )
    .expect("valid config");
    assert_eq!(cfg.api_key, "secret_abc");
    assert_eq!(cfg.database_id, "db123");
    assert_eq!(cfg.status_property, "State");
    // Unspecified fields fall back to the native defaults.
    assert_eq!(cfg.input_property, "Input");
    assert_eq!(cfg.result_property, "Result");
    assert_eq!(cfg.poll_interval_secs, 5);
    assert_eq!(cfg.max_concurrent, 4);
    assert!(cfg.recover_stale);
    assert_eq!(cfg.api_base_url, "https://api.notion.com/v1");
    assert!(cfg.has_credentials());
}

#[test]
fn config_defaults_are_inert_without_credentials() {
    // A withheld ("{}") section yields inert defaults.
    let empty = NotionConfig::from_json("{}").expect("withheld config is valid");
    assert!(!empty.has_credentials());
    assert_eq!(empty.status_property, "Status");

    let malformed = NotionConfig::from_json("not json").expect_err("malformed JSON must fail");
    assert!(malformed.contains("notion config could not be parsed"));

    // Missing database_id alone is still not enough to reach the API.
    let no_db = NotionConfig::from_json(r#"{"api_key":"k"}"#).expect("valid partial config");
    assert!(!no_db.has_credentials());
}

#[test]
fn config_accepts_string_or_native_numbers_and_booleans() {
    let native = NotionConfig::from_json(
        r#"{"poll_interval_secs":12,"max_concurrent":3,"recover_stale":false}"#,
    )
    .expect("native scalar config");
    assert_eq!(native.poll_interval_secs, 12);
    assert_eq!(native.max_concurrent, 3);
    assert!(!native.recover_stale);

    let strings = NotionConfig::from_json(
        r#"{"poll_interval_secs":"30","max_concurrent":"8","recover_stale":"true"}"#,
    )
    .expect("host string-map config");
    assert_eq!(strings.poll_interval_secs, 30);
    assert_eq!(strings.max_concurrent, 8);
    assert!(strings.recover_stale);
}

#[test]
fn config_reports_the_invalid_field_without_discarding_the_error() {
    let number_error = NotionConfig::from_json(r#"{"poll_interval_secs":"often"}"#)
        .expect_err("invalid poll interval must fail");
    assert!(number_error.contains("poll_interval_secs"));
    assert!(number_error.contains("often"));

    let bool_error = NotionConfig::from_json(r#"{"recover_stale":"sometimes"}"#)
        .expect_err("invalid recovery flag must fail");
    assert!(bool_error.contains("recover_stale"));
    assert!(bool_error.contains("sometimes"));
}

#[test]
fn url_builders_trim_trailing_slash() {
    assert_eq!(
        query_url("https://api.notion.com/v1", "db1"),
        "https://api.notion.com/v1/databases/db1/query"
    );
    assert_eq!(
        database_url("https://api.notion.com/v1/", "db1"),
        "https://api.notion.com/v1/databases/db1"
    );
    assert_eq!(
        page_url("https://api.notion.com/v1", "page9"),
        "https://api.notion.com/v1/pages/page9"
    );
}

#[test]
fn detect_status_type_reads_schema() {
    let schema = json!({
        "properties": {
            "Status": { "type": "status" },
            "Input": { "type": "title" }
        }
    });
    assert_eq!(detect_status_type(&schema, "Status"), "status");
    // Absent property or type → select (native default).
    assert_eq!(detect_status_type(&schema, "Missing"), "select");
    assert_eq!(detect_status_type(&json!({}), "Status"), "select");
}

#[test]
fn status_filter_select_and_status_types() {
    assert_eq!(
        build_status_filter("Status", "select", "pending"),
        json!({ "property": "Status", "select": { "equals": "pending" } })
    );
    assert_eq!(
        build_status_filter("Status", "status", "running"),
        json!({ "property": "Status", "status": { "equals": "running" } })
    );
}

#[test]
fn status_payload_select_and_status_types() {
    assert_eq!(
        build_status_payload("select", "pending"),
        json!({ "select": { "name": "pending" } })
    );
    assert_eq!(
        build_status_payload("status", "done"),
        json!({ "status": { "name": "done" } })
    );
}

#[test]
fn rich_text_payload_construction() {
    let payload = build_rich_text_payload("test output");
    assert_eq!(
        payload["rich_text"][0]["text"]["content"].as_str().unwrap(),
        "test output"
    );
}

#[test]
fn query_body_wraps_filter() {
    let body = build_query_body("Status", "select", "pending");
    assert_eq!(
        body,
        json!({ "filter": { "property": "Status", "select": { "equals": "pending" } } })
    );
}

#[test]
fn status_update_payload_flips_only_status() {
    let body = build_status_update_payload("Status", "status", "running");
    assert_eq!(
        body,
        json!({ "properties": { "Status": { "status": { "name": "running" } } } })
    );
}

#[test]
fn complete_payload_writes_result_and_done() {
    let body = build_complete_payload("Status", "Result", "select", "the answer");
    assert_eq!(
        body["properties"]["Status"],
        json!({ "select": { "name": "done" } })
    );
    assert_eq!(
        body["properties"]["Result"]["rich_text"][0]["text"]["content"]
            .as_str()
            .unwrap(),
        "the answer"
    );
}

#[test]
fn recover_payload_resets_to_pending_with_note() {
    let body = build_recover_payload("Status", "Result", "status");
    assert_eq!(
        body["properties"]["Status"],
        json!({ "status": { "name": "pending" } })
    );
    assert_eq!(
        body["properties"]["Result"]["rich_text"][0]["text"]["content"]
            .as_str()
            .unwrap(),
        "Reset: poller restarted while task was running"
    );
}

#[test]
fn extract_text_from_title_property() {
    let prop = json!({
        "type": "title",
        "title": [ { "plain_text": "Hello " }, { "plain_text": "World" } ]
    });
    assert_eq!(extract_text_from_property(Some(&prop)), "Hello World");
}

#[test]
fn extract_text_from_rich_text_property() {
    let prop = json!({
        "type": "rich_text",
        "rich_text": [ { "plain_text": "task content" } ]
    });
    assert_eq!(extract_text_from_property(Some(&prop)), "task content");
}

#[test]
fn extract_text_from_none_or_unknown() {
    assert_eq!(extract_text_from_property(None), "");
    let number = json!({ "type": "number", "number": 42 });
    assert_eq!(extract_text_from_property(Some(&number)), "");
}

#[test]
fn parse_pending_maps_rows_to_inbound() {
    let resp = json!({
        "results": [
            {
                "id": "page-1",
                "properties": {
                    "Input": { "type": "title", "title": [ { "plain_text": "do a thing" } ] }
                }
            },
            {
                // No id — skipped.
                "properties": {
                    "Input": { "type": "title", "title": [ { "plain_text": "orphan" } ] }
                }
            }
        ]
    });
    let rows = parse_pending(&resp, "Input");
    assert_eq!(rows.len(), 1);
    let inb = &rows[0];
    assert_eq!(inb.id, "page-1");
    assert_eq!(inb.reply_target, "page-1");
    assert_eq!(inb.sender, "notion");
    assert_eq!(inb.content, "do a thing");
    assert_eq!(inb.timestamp, 0);
    assert!(inb.channel_alias.is_none());
    assert!(inb.thread_ts.is_none());
}

#[test]
fn parse_pending_empty_when_no_results() {
    assert!(parse_pending(&json!({}), "Input").is_empty());
    assert!(parse_pending(&json!({ "results": [] }), "Input").is_empty());
}

#[test]
fn parse_pending_keeps_empty_content_rows_for_caller_filtering() {
    let resp = json!({
        "results": [
            { "id": "page-empty", "properties": {} }
        ]
    });
    let rows = parse_pending(&resp, "Input");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].content, "");
}

#[test]
fn result_truncation_within_and_over_limit() {
    assert_eq!(truncate_result("hello world"), "hello world");

    let long = "a".repeat(MAX_RESULT_LENGTH + 100);
    let truncated = truncate_result(&long);
    assert!(truncated.len() <= MAX_RESULT_LENGTH);
    assert!(truncated.ends_with("... [output truncated]"));
}

#[test]
fn result_truncation_is_multibyte_safe() {
    let s: String = "\u{6E2C}".repeat(700); // 3-byte UTF-8 chars
    let truncated = truncate_result(&s);
    assert!(truncated.len() <= MAX_RESULT_LENGTH);
    assert!(truncated.ends_with("... [output truncated]"));
}
