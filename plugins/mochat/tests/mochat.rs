//! Host tests for the pure Mochat core — the same mapping/payload logic the
//! wasm component runs, exercised with plain `cargo test` (no token, no network,
//! no wasm).

use mochat::mochat::{
    build_send_body, extract_messages, health_url, is_send_ok, message_id, parse_message,
    receive_url, send_error, send_url, DedupSet, MochatConfig,
};
use serde_json::json;

#[test]
fn config_parses_and_defaults() {
    let cfg = MochatConfig::from_json(
        r#"{"enabled":true,"api_url":"https://mochat.example.com","api_token":"secret"}"#,
    );
    assert!(cfg.enabled);
    assert_eq!(cfg.api_url, "https://mochat.example.com");
    assert_eq!(cfg.api_token, "secret");
    assert_eq!(cfg.poll_interval_secs, 5);
    assert!(cfg.has_credentials());

    // A withheld ("{}") or malformed section yields inert defaults.
    let empty = MochatConfig::from_json("{}");
    assert_eq!(empty.api_url, "");
    assert_eq!(empty.api_token, "");
    assert!(!empty.has_credentials());
    assert_eq!(MochatConfig::from_json("not json").poll_interval_secs, 5);
}

#[test]
fn base_url_strips_trailing_slash() {
    let cfg = MochatConfig::from_json(r#"{"api_url":"https://mochat.example.com/"}"#);
    assert_eq!(cfg.base_url(), "https://mochat.example.com");
}

#[test]
fn credentials_require_both_url_and_token() {
    assert!(!MochatConfig::from_json(r#"{"api_url":"https://m.test"}"#).has_credentials());
    assert!(!MochatConfig::from_json(r#"{"api_token":"tok"}"#).has_credentials());
    assert!(
        MochatConfig::from_json(r#"{"api_url":"https://m.test","api_token":"tok"}"#)
            .has_credentials()
    );
}

#[test]
fn receive_url_appends_since_id_when_present() {
    assert_eq!(
        receive_url("https://m.test", None),
        "https://m.test/api/message/receive"
    );
    assert_eq!(
        receive_url("https://m.test", Some("")),
        "https://m.test/api/message/receive"
    );
    assert_eq!(
        receive_url("https://m.test", Some("42")),
        "https://m.test/api/message/receive?since_id=42"
    );
}

#[test]
fn send_and_health_urls() {
    assert_eq!(
        send_url("https://m.test"),
        "https://m.test/api/message/send"
    );
    assert_eq!(health_url("https://m.test"), "https://m.test/api/health");
}

#[test]
fn extract_messages_reads_data_or_messages() {
    let via_data = json!({ "data": [ { "id": "a" }, { "id": "b" } ] });
    assert_eq!(extract_messages(&via_data).len(), 2);

    let via_messages = json!({ "messages": [ { "id": "c" } ] });
    assert_eq!(extract_messages(&via_messages).len(), 1);

    let neither = json!({ "code": 0 });
    assert!(extract_messages(&neither).is_empty());
}

#[test]
fn message_id_prefers_message_id_then_id() {
    assert_eq!(message_id(&json!({ "messageId": "m1", "id": "x" })), "m1");
    assert_eq!(message_id(&json!({ "id": "i1" })), "i1");
    assert_eq!(message_id(&json!({ "content": {} })), "");
}

#[test]
fn parse_message_maps_object_content() {
    let msg = json!({
        "messageId": "m7",
        "fromUserId": "user123",
        "content": { "text": "  hello there  " },
        "timestamp": 1_700_000_000_u64,
    });
    let inb = parse_message(&msg).expect("maps");
    assert_eq!(inb.id, "m7");
    assert_eq!(inb.sender, "user123");
    assert_eq!(inb.reply_target, "user123");
    assert_eq!(inb.content, "hello there");
    assert_eq!(inb.timestamp, 1_700_000_000);
}

#[test]
fn parse_message_accepts_bare_string_content_and_sender_alias() {
    let msg = json!({ "id": "m8", "sender": "u2", "content": "hi" });
    let inb = parse_message(&msg).expect("maps");
    assert_eq!(inb.id, "m8");
    assert_eq!(inb.sender, "u2");
    assert_eq!(inb.content, "hi");
    assert_eq!(inb.timestamp, 0);
}

#[test]
fn parse_message_falls_back_to_unknown_sender_and_synthesizes_id() {
    let msg = json!({ "content": { "text": "orphan" } });
    let inb = parse_message(&msg).expect("maps");
    assert_eq!(inb.sender, "unknown");
    assert_eq!(inb.id, "mochat_unknown_0");
    assert_eq!(inb.content, "orphan");
}

#[test]
fn parse_message_skips_empty_content() {
    assert!(parse_message(&json!({ "id": "m9", "content": { "text": "   " } })).is_none());
    assert!(parse_message(&json!({ "id": "m9", "fromUserId": "u" })).is_none());
}

#[test]
fn send_body_has_native_shape() {
    let body = build_send_body("user123", "reply text");
    assert_eq!(body["toUserId"], json!("user123"));
    assert_eq!(body["msgType"], json!("text"));
    assert_eq!(body["content"]["text"], json!("reply text"));
}

#[test]
fn send_ok_accepts_zero_or_two_hundred() {
    assert!(is_send_ok(&json!({ "code": 0 })));
    assert!(is_send_ok(&json!({ "code": 200 })));
    assert!(!is_send_ok(&json!({ "code": 1 })));
    assert!(!is_send_ok(&json!({ "msg": "no code" })));
}

#[test]
fn send_error_uses_msg_or_message() {
    assert_eq!(
        send_error(&json!({ "code": 1, "msg": "boom" })),
        "mochat API error (code=1): boom"
    );
    assert_eq!(
        send_error(&json!({ "code": 42, "message": "nope" })),
        "mochat API error (code=42): nope"
    );
    assert_eq!(
        send_error(&json!({ "code": 7 })),
        "mochat API error (code=7): unknown error"
    );
}

#[test]
fn dedup_tracks_ids_but_ignores_empty() {
    let mut dedup = DedupSet::default();
    assert!(!dedup.is_duplicate("m1"));
    assert!(dedup.is_duplicate("m1"));
    assert!(!dedup.is_duplicate("m2"));
    // An empty id is never a duplicate and is not tracked.
    assert!(!dedup.is_duplicate(""));
    assert!(!dedup.is_duplicate(""));
}
