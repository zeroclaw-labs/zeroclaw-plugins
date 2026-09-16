//! Host tests for the pure WeChat iLink core — the same mapping/payload logic
//! the wasm component runs, exercised with plain `cargo test` (no token, no
//! network, no wasm).

use serde_json::json;
use wechat::wechat::{
    base64_encode, build_getconfig_body, build_getupdates_body, build_send_body, context_token_of,
    extract_msgs, extract_text_from_items, is_session_expired, next_cursor, parse_message,
    response_error_code, sender_id, to_plain_text, wechat_uin, WeChatConfig, CHANNEL_VERSION,
    DEFAULT_API_BASE_URL, DEFAULT_CDN_BASE_URL, ITEM_TYPE_TEXT, ITEM_TYPE_VOICE,
    MESSAGE_STATE_FINISH, MESSAGE_TYPE_BOT, SESSION_EXPIRED_ERRCODE,
};

fn text_msg(from: &str, text: &str, message_id: u64, ctx: Option<&str>) -> serde_json::Value {
    json!({
        "from_user_id": from,
        "message_id": message_id,
        "create_time_ms": 1_700_000_000_000_u64,
        "context_token": ctx,
        "item_list": [
            { "type": ITEM_TYPE_TEXT, "text_item": { "text": text } }
        ]
    })
}

#[test]
fn config_parses_and_defaults() {
    let cfg = WeChatConfig::from_json(
        r#"{"enabled":true,"bot_token":"tok-123","api_base_url":"https://ilink.example.com/"}"#,
    );
    assert!(cfg.enabled);
    assert_eq!(cfg.token(), "tok-123");
    assert!(cfg.has_session());
    // Trailing slash trimmed on override.
    assert_eq!(cfg.api_base(), "https://ilink.example.com");
    // Unset CDN falls back to the default.
    assert_eq!(cfg.cdn_base(), DEFAULT_CDN_BASE_URL);

    // A withheld ("{}") or malformed section yields inert, unsessioned defaults.
    let empty = WeChatConfig::from_json("{}");
    assert!(!empty.has_session());
    assert_eq!(empty.api_base(), DEFAULT_API_BASE_URL);
    assert_eq!(WeChatConfig::from_json("not json").token(), "");
}

#[test]
fn native_mirror_section_without_token_is_unsessioned() {
    // A native [channels.wechat.<alias>] section (no bot_token) deserializes and
    // leaves the plugin without a session.
    let cfg = WeChatConfig::from_json(
        r#"{"enabled":true,"cdn_base_url":"https://cdn.example.com","state_dir":"/x","excluded_tools":["shell"]}"#,
    );
    assert!(!cfg.has_session());
    assert_eq!(cfg.cdn_base(), "https://cdn.example.com");
}

#[test]
fn parses_a_text_message() {
    let msg = text_msg("wxid_alice", "hello there", 42, Some("ctx-abc"));
    let inb = parse_message(&msg, Some("main")).expect("text message maps");
    assert_eq!(inb.id, "42");
    assert_eq!(inb.sender, "wxid_alice");
    assert_eq!(inb.reply_target, "wxid_alice");
    assert_eq!(inb.content, "hello there");
    assert_eq!(inb.channel_alias.as_deref(), Some("main"));
    assert_eq!(inb.timestamp, 1_700_000_000_000);
    assert_eq!(inb.thread_ts, None);
}

#[test]
fn synthesizes_id_when_message_id_absent() {
    let msg = json!({
        "from_user_id": "wxid_bob",
        "create_time_ms": 1_700_000_000_000_u64,
        "item_list": [ { "type": ITEM_TYPE_TEXT, "text_item": { "text": "hi" } } ]
    });
    let inb = parse_message(&msg, None).expect("maps");
    assert_eq!(inb.id, "wechat_wxid_bob_1700000000000");
    assert_eq!(inb.channel_alias, None);
}

#[test]
fn message_id_as_string_is_accepted() {
    let mut msg = text_msg("wxid_alice", "hi", 0, None);
    msg["message_id"] = json!("msg_str_id");
    let inb = parse_message(&msg, None).expect("maps");
    assert_eq!(inb.id, "msg_str_id");
}

#[test]
fn empty_sender_or_content_is_skipped() {
    let no_sender = json!({
        "from_user_id": "",
        "item_list": [ { "type": ITEM_TYPE_TEXT, "text_item": { "text": "hi" } } ]
    });
    assert!(parse_message(&no_sender, None).is_none());

    // No textual item (e.g. an image-only message) → skipped by this text plugin.
    let no_text = json!({
        "from_user_id": "wxid_alice",
        "item_list": [ { "type": 2, "image_item": {} } ]
    });
    assert!(parse_message(&no_text, None).is_none());
}

#[test]
fn extract_text_handles_ref_quote_and_voice() {
    // Plain text.
    let items = vec![json!({ "type": ITEM_TYPE_TEXT, "text_item": { "text": "plain" } })];
    assert_eq!(extract_text_from_items(&items), "plain");

    // Quoted (ref_msg) prefix.
    let quoted = vec![json!({
        "type": ITEM_TYPE_TEXT,
        "text_item": { "text": "reply body" },
        "ref_msg": { "title": "earlier" }
    })];
    assert_eq!(
        extract_text_from_items(&quoted),
        "[引用: earlier]\nreply body"
    );

    // Voice transcription.
    let voice = vec![json!({ "type": ITEM_TYPE_VOICE, "voice_item": { "text": "spoken words" } })];
    assert_eq!(extract_text_from_items(&voice), "spoken words");

    // Nothing textual.
    assert_eq!(extract_text_from_items(&[json!({ "type": 5 })]), "");
}

#[test]
fn error_codes_and_session_expiry() {
    assert_eq!(
        response_error_code(&json!({ "ret": 0, "errcode": 0 })),
        None
    );
    assert_eq!(response_error_code(&json!({ "ret": -14 })), Some(-14));
    assert_eq!(response_error_code(&json!({ "errcode": 500 })), Some(500));
    assert!(is_session_expired(SESSION_EXPIRED_ERRCODE));
    assert!(!is_session_expired(500));
}

#[test]
fn cursor_and_msgs_extraction() {
    let resp = json!({
        "get_updates_buf": "cursor-2",
        "msgs": [ text_msg("wxid_alice", "one", 1, Some("c1")) ]
    });
    assert_eq!(next_cursor(&resp).as_deref(), Some("cursor-2"));
    assert_eq!(extract_msgs(&resp).len(), 1);

    // Empty cursor is not advanced; missing msgs is empty.
    assert_eq!(next_cursor(&json!({ "get_updates_buf": "" })), None);
    assert!(extract_msgs(&json!({})).is_empty());
}

#[test]
fn sender_and_context_token_helpers() {
    let msg = text_msg("wxid_alice", "hi", 1, Some("ctx-9"));
    assert_eq!(sender_id(&msg).as_deref(), Some("wxid_alice"));
    assert_eq!(context_token_of(&msg).as_deref(), Some("ctx-9"));

    let no_ctx = text_msg("wxid_alice", "hi", 1, None);
    assert_eq!(context_token_of(&no_ctx), None);
    assert_eq!(sender_id(&json!({ "from_user_id": "" })), None);
}

#[test]
fn send_body_shape() {
    let body = build_send_body(
        "wxid_alice",
        "reply",
        "ctx-7",
        "zeroclaw-1",
        CHANNEL_VERSION,
    );
    assert_eq!(body["msg"]["to_user_id"], json!("wxid_alice"));
    assert_eq!(body["msg"]["from_user_id"], json!(""));
    assert_eq!(body["msg"]["client_id"], json!("zeroclaw-1"));
    assert_eq!(body["msg"]["context_token"], json!("ctx-7"));
    assert_eq!(body["msg"]["message_type"], json!(MESSAGE_TYPE_BOT));
    assert_eq!(body["msg"]["message_state"], json!(MESSAGE_STATE_FINISH));
    assert_eq!(body["msg"]["item_list"][0]["type"], json!(ITEM_TYPE_TEXT));
    assert_eq!(
        body["msg"]["item_list"][0]["text_item"]["text"],
        json!("reply")
    );
    assert_eq!(body["base_info"]["channel_version"], json!(CHANNEL_VERSION));
}

#[test]
fn getupdates_and_getconfig_body_shape() {
    let poll = build_getupdates_body("cur", 0, CHANNEL_VERSION);
    assert_eq!(poll["get_updates_buf"], json!("cur"));
    assert_eq!(poll["longpolling_timeout_ms"], json!(0));
    assert_eq!(poll["base_info"]["channel_version"], json!(CHANNEL_VERSION));

    let health = build_getconfig_body(CHANNEL_VERSION);
    assert_eq!(health["ilink_user_id"], json!(""));
    assert_eq!(health["context_token"], json!(""));
}

#[test]
fn base64_and_uin() {
    // Known RFC 4648 vectors.
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    // UIN is base64(decimal(seed as u32)); non-empty and padded-valid.
    let uin = wechat_uin(123_456_789);
    assert!(!uin.is_empty());
    assert_eq!(uin, base64_encode(b"123456789"));
}

#[test]
fn plain_text_strips_common_markdown() {
    assert_eq!(to_plain_text("plain line"), "plain line");
    assert_eq!(to_plain_text("# Heading"), "Heading");
    assert_eq!(to_plain_text("- bullet item"), "bullet item");
    assert_eq!(to_plain_text("> quoted"), "quoted");
    assert_eq!(
        to_plain_text("some **bold** and `code`"),
        "some bold and code"
    );

    // Fenced code: the ``` marker lines drop, the content stays.
    let fenced = "before\n```rust\nlet x = 1;\n```\nafter";
    assert_eq!(to_plain_text(fenced), "before\nlet x = 1;\nafter");
}
