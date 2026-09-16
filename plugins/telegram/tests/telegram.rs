//! Host tests for the pure Telegram core — the same mapping/payload logic the
//! wasm component runs, exercised with plain `cargo test` (no token, no network,
//! no wasm).

use serde_json::json;
use telegram::telegram::{
    build_send_payload, chunk_text, extract_updates, is_user_allowed, next_offset, parse_update,
    split_recipient, TelegramConfig,
};

fn update(text: &str, chat_id: i64, message_id: i64, username: Option<&str>) -> serde_json::Value {
    json!({
        "update_id": 100,
        "message": {
            "message_id": message_id,
            "date": 1_700_000_000_u64,
            "chat": { "id": chat_id, "type": "private" },
            "from": { "id": 42, "username": username, "is_bot": false },
            "text": text,
        }
    })
}

#[test]
fn parses_a_text_message() {
    let inb = parse_update(&update("hello", 555, 7, Some("alice"))).expect("text update maps");
    assert_eq!(inb.id, "telegram_555_7");
    assert_eq!(inb.sender, "alice");
    assert_eq!(inb.reply_target, "555");
    assert_eq!(inb.content, "hello");
    assert_eq!(inb.timestamp, 1_700_000_000);
    assert_eq!(inb.thread_ts, None);
}

#[test]
fn falls_back_to_numeric_sender_without_username() {
    let inb = parse_update(&update("hi", 9, 1, None)).expect("maps");
    assert_eq!(inb.sender, "42");
}

#[test]
fn forum_topic_scopes_the_reply_target() {
    let mut u = update("in a topic", 555, 8, Some("bob"));
    u["message"]["message_thread_id"] = json!(1234);
    let inb = parse_update(&u).expect("maps");
    assert_eq!(inb.reply_target, "555:1234");
    assert_eq!(inb.thread_ts.as_deref(), Some("1234"));
}

#[test]
fn non_text_and_non_message_updates_are_skipped() {
    assert!(parse_update(&json!({ "update_id": 1, "poll": {} })).is_none());
    let no_text =
        json!({ "update_id": 1, "message": { "message_id": 1, "chat": {"id": 1}, "date": 0 } });
    assert!(parse_update(&no_text).is_none());
}

#[test]
fn offset_advances_past_the_last_update() {
    assert_eq!(next_offset(100), 101);
}

#[test]
fn allow_list_semantics() {
    assert!(is_user_allowed(&["alice".into()], &["*".into()]));
    assert!(!is_user_allowed(&["alice".into()], &[]));
    assert!(is_user_allowed(&["alice".into()], &["@Alice".into()]));
    assert!(is_user_allowed(
        &["42".into()],
        &["alice".into(), "42".into()]
    ));
    assert!(!is_user_allowed(&["mallory".into()], &["alice".into()]));
}

#[test]
fn recipient_splits_chat_and_thread() {
    assert_eq!(split_recipient("555"), ("555".to_string(), None));
    assert_eq!(
        split_recipient("555:1234"),
        ("555".to_string(), Some("1234".to_string()))
    );
}

#[test]
fn send_payload_is_plain_by_default_and_typed_when_configured() {
    let plain = build_send_payload("555", "hi", None, None);
    assert_eq!(plain["chat_id"], json!("555"));
    assert_eq!(plain["text"], json!("hi"));
    assert!(plain.get("parse_mode").is_none());

    let html = build_send_payload("555", "<b>hi</b>", Some("99"), Some("HTML"));
    assert_eq!(html["parse_mode"], json!("HTML"));
    assert_eq!(html["message_thread_id"], json!(99));
}

#[test]
fn long_text_is_chunked_under_the_limit() {
    let one = chunk_text("short", 4096);
    assert_eq!(one, vec!["short".to_string()]);

    let long: String = "x".repeat(10_000);
    let chunks = chunk_text(&long, 4096);
    assert!(chunks.len() >= 3);
    assert!(chunks.iter().all(|c| c.chars().count() <= 4096));
    assert_eq!(chunks.concat(), long);
}

#[test]
fn extract_updates_honors_ok_flag() {
    let ok = json!({ "ok": true, "result": [ { "update_id": 5 }, { "update_id": 6 } ] });
    let got = extract_updates(&ok);
    assert_eq!(
        got.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![5, 6]
    );

    let not_ok = json!({ "ok": false, "description": "unauthorized" });
    assert!(extract_updates(&not_ok).is_empty());
}

#[test]
fn config_parses_and_defaults() {
    let cfg = TelegramConfig::from_json(r#"{"bot_token":"123:abc","parse_mode":"HTML"}"#);
    assert_eq!(cfg.bot_token, "123:abc");
    assert_eq!(cfg.api_base_url, "https://api.telegram.org");
    assert_eq!(cfg.parse_mode.as_deref(), Some("HTML"));

    // A withheld ("{}") or malformed section yields inert defaults.
    assert_eq!(TelegramConfig::from_json("{}").bot_token, "");
    assert_eq!(TelegramConfig::from_json("not json").bot_token, "");
}
