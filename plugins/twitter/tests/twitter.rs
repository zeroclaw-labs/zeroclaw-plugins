//! Host tests for the pure X/Twitter core — the same mapping/payload logic the
//! wasm component runs, exercised with plain `cargo test` (no token, no network,
//! no wasm).

use serde_json::json;
use twitter::twitter::{
    advance_cursor, build_mentions_url, build_self_url, build_tweet_body, build_tweets_url,
    chunk_tweet, created_tweet_id, is_user_allowed, max_tweet_id, newest_id, parse_mentions,
    parse_self_handle, parse_self_id, reply_id_from_recipient, TwitterConfig, TWEET_MAX_CHARS,
};

fn mentions_response() -> serde_json::Value {
    // The X API returns newest-first.
    json!({
        "data": [
            { "id": "20", "text": "@bot second", "author_id": "999", "created_at": "2026-01-02T00:00:00.000Z" },
            { "id": "10", "text": "@bot first",  "author_id": "111", "created_at": "2026-01-01T00:00:00.000Z" }
        ],
        "meta": { "newest_id": "20", "oldest_id": "10", "result_count": 2 }
    })
}

#[test]
fn parses_the_authenticated_user() {
    let me = json!({ "data": { "id": "42", "name": "My Bot", "username": "mybot" } });
    assert_eq!(parse_self_id(&me).as_deref(), Some("42"));
    assert_eq!(parse_self_handle(&me).as_deref(), Some("@mybot"));
    // A handle is optional; an id-only response still yields the id.
    let id_only = json!({ "data": { "id": "42" } });
    assert_eq!(parse_self_id(&id_only).as_deref(), Some("42"));
    assert_eq!(parse_self_handle(&id_only), None);
}

#[test]
fn maps_mentions_oldest_first() {
    let inbs = parse_mentions(&mentions_response());
    assert_eq!(inbs.len(), 2);

    // Oldest first so buffer + pop_front preserves posting order.
    let first = &inbs[0];
    assert_eq!(first.id, "10");
    assert_eq!(first.sender, "111");
    assert_eq!(first.reply_target, "10");
    assert_eq!(first.content, "@bot first");
    assert_eq!(first.thread_ts, None);

    assert_eq!(inbs[1].id, "20");
    assert_eq!(inbs[1].sender, "999");
    assert_eq!(inbs[1].reply_target, "20");
}

#[test]
fn maps_no_data_to_empty() {
    assert!(parse_mentions(&json!({ "meta": { "result_count": 0 } })).is_empty());
    // An error body (no `data`) is treated as nothing new, not a panic.
    assert!(parse_mentions(&json!({ "title": "Too Many Requests", "status": 429 })).is_empty());
}

#[test]
fn tweet_without_id_or_text_is_skipped() {
    let resp = json!({ "data": [
        { "id": "1" },                         // no text
        { "text": "no id", "author_id": "5" }, // no id
        { "id": "3", "text": "ok", "author_id": "5" }
    ]});
    let inbs = parse_mentions(&resp);
    assert_eq!(inbs.len(), 1);
    assert_eq!(inbs[0].id, "3");
}

#[test]
fn author_id_missing_falls_back_to_unknown() {
    let resp = json!({ "data": [ { "id": "7", "text": "hi" } ] });
    let inbs = parse_mentions(&resp);
    assert_eq!(inbs[0].sender, "unknown");
}

#[test]
fn advances_cursor_from_meta_then_max_id() {
    assert_eq!(newest_id(&mentions_response()).as_deref(), Some("20"));
    assert_eq!(advance_cursor(&mentions_response()).as_deref(), Some("20"));

    // No meta → fall back to the numerically largest tweet id (snowflakes are
    // monotonic; longer/greater id wins even across digit counts).
    let no_meta = json!({ "data": [
        { "id": "1000000000000000009", "text": "a", "author_id": "1" },
        { "id": "999999999999999999",  "text": "b", "author_id": "1" }
    ]});
    assert_eq!(newest_id(&no_meta), None);
    assert_eq!(
        max_tweet_id(&no_meta).as_deref(),
        Some("1000000000000000009")
    );
    assert_eq!(
        advance_cursor(&no_meta).as_deref(),
        Some("1000000000000000009")
    );
}

#[test]
fn urls_are_built_for_each_endpoint() {
    assert_eq!(
        build_self_url("https://api.x.com/2"),
        "https://api.x.com/2/users/me"
    );
    assert_eq!(
        build_tweets_url("https://api.x.com/2"),
        "https://api.x.com/2/tweets"
    );

    let no_since = build_mentions_url("https://api.x.com/2", "42", None);
    assert_eq!(
        no_since,
        "https://api.x.com/2/users/42/mentions?tweet.fields=author_id,created_at&max_results=20"
    );

    let with_since = build_mentions_url("https://api.x.com/2/", "42", Some("100"));
    // A trailing slash on the base is trimmed; the cursor is appended.
    assert_eq!(
        with_since,
        "https://api.x.com/2/users/42/mentions?tweet.fields=author_id,created_at&max_results=20&since_id=100"
    );
    // An empty cursor is treated as absent.
    assert!(!build_mentions_url("https://api.x.com/2", "42", Some("")).contains("since_id"));
}

#[test]
fn reply_target_is_normalized() {
    assert_eq!(reply_id_from_recipient("123").as_deref(), Some("123"));
    assert_eq!(reply_id_from_recipient("tweet:123").as_deref(), Some("123"));
    assert_eq!(reply_id_from_recipient(""), None);
    assert_eq!(reply_id_from_recipient("  "), None);
}

#[test]
fn tweet_body_is_plain_by_default_and_threaded_when_replying() {
    let plain = build_tweet_body("hello", None);
    assert_eq!(plain["text"], json!("hello"));
    assert!(plain.get("reply").is_none());

    let reply = build_tweet_body("hello", Some("555"));
    assert_eq!(reply["reply"]["in_reply_to_tweet_id"], json!("555"));

    // An empty reply id posts a standalone tweet.
    let empty = build_tweet_body("hello", Some(""));
    assert!(empty.get("reply").is_none());
}

#[test]
fn created_tweet_id_reads_the_new_id() {
    let ok = json!({ "data": { "id": "1701", "text": "posted" } });
    assert_eq!(created_tweet_id(&ok).as_deref(), Some("1701"));
    // A failure body has no usable id.
    assert_eq!(
        created_tweet_id(&json!({ "errors": [ { "message": "bad" } ] })),
        None
    );
    assert_eq!(created_tweet_id(&json!({ "data": { "id": "" } })), None);
}

#[test]
fn long_text_is_chunked_under_the_tweet_limit() {
    let one = chunk_tweet("short", TWEET_MAX_CHARS);
    assert_eq!(one, vec!["short".to_string()]);

    let long = "word ".repeat(200); // 1000 chars
    let chunks = chunk_tweet(&long, TWEET_MAX_CHARS);
    assert!(chunks.len() >= 4);
    assert!(chunks.iter().all(|c| c.chars().count() <= TWEET_MAX_CHARS));
    assert_eq!(chunks.concat(), long);

    // A single over-long word is hard-split by char, still preserving content.
    let word = "a".repeat(700);
    let hard = chunk_tweet(&word, TWEET_MAX_CHARS);
    assert!(hard.iter().all(|c| c.chars().count() <= TWEET_MAX_CHARS));
    assert_eq!(hard.concat(), word);
}

#[test]
fn allow_list_semantics() {
    assert!(is_user_allowed(&["999".into()], &["*".into()]));
    assert!(!is_user_allowed(&["999".into()], &[]));
    assert!(is_user_allowed(&["mybot".into()], &["@MyBot".into()]));
    assert!(is_user_allowed(
        &["999".into()],
        &["mybot".into(), "999".into()]
    ));
    assert!(!is_user_allowed(&["555".into()], &["999".into()]));
}

#[test]
fn config_parses_and_defaults() {
    let cfg = TwitterConfig::from_json(r#"{"bearer_token":"AAAA","enabled":true}"#);
    assert_eq!(cfg.bearer_token, "AAAA");
    assert!(cfg.enabled);
    assert_eq!(cfg.api_base_url, "https://api.x.com/2");
    assert!(cfg.allowed_users.is_empty());
    assert!(cfg.excluded_tools.is_empty());

    // The native section deserializes cleanly (bearer_token/enabled/excluded_tools).
    let native = TwitterConfig::from_json(
        r#"{"enabled":true,"bearer_token":"tok","excluded_tools":["shell"]}"#,
    );
    assert_eq!(native.bearer_token, "tok");
    assert_eq!(native.excluded_tools, vec!["shell".to_string()]);

    // A withheld ("{}") or malformed section yields inert defaults.
    assert_eq!(TwitterConfig::from_json("{}").bearer_token, "");
    assert!(!TwitterConfig::from_json("{}").enabled);
    assert_eq!(TwitterConfig::from_json("not json").bearer_token, "");
}
