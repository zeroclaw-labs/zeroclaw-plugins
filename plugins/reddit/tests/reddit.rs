//! Host tests for the pure Reddit core — the same mapping/auth logic the wasm
//! component runs, exercised with plain `cargo test` (no token, no network, no
//! wasm).

use reddit::reddit::{
    base64_encode, basic_auth_header, extract_children, is_thing_fullname, item_fullname,
    join_fullnames, parse_item, parse_token_response, token_form, RedditConfig,
};
use serde_json::json;

fn item(
    name: &str,
    author: &str,
    body: &str,
    parent_id: Option<&str>,
    subreddit: Option<&str>,
    kind: Option<&str>,
) -> serde_json::Value {
    let mut v = json!({
        "name": name,
        "author": author,
        "body": body,
        "created_utc": 1_700_000_000.123_f64,
    });
    if let Some(p) = parent_id {
        v["parent_id"] = json!(p);
    }
    if let Some(s) = subreddit {
        v["subreddit"] = json!(s);
    }
    if let Some(k) = kind {
        v["type"] = json!(k);
    }
    v
}

#[test]
fn parses_a_comment_reply_to_the_parent_thing() {
    let it = item(
        "t1_abc123",
        "user1",
        "hello bot",
        Some("t1_parent1"),
        Some("rust"),
        Some("comment_reply"),
    );
    let inb = parse_item(&it, "testbot", &[]).expect("comment reply maps");
    assert_eq!(inb.id, "reddit_t1_abc123");
    assert_eq!(inb.sender, "user1");
    assert_eq!(inb.content, "hello bot");
    assert_eq!(inb.reply_target, "t1_parent1");
    assert_eq!(inb.thread_ts.as_deref(), Some("t1_parent1"));
    assert_eq!(inb.timestamp, 1_700_000_000_123);
}

#[test]
fn parses_a_dm_replying_to_the_author() {
    let it = item("t4_dm456", "user2", "private message", None, None, None);
    let inb = parse_item(&it, "testbot", &[]).expect("dm maps");
    assert_eq!(inb.sender, "user2");
    assert_eq!(inb.content, "private message");
    // DM reply goes back to the author, and there is no parent thread.
    assert_eq!(inb.reply_target, "user2");
    assert_eq!(inb.thread_ts, None);
}

#[test]
fn skips_self_authored_and_empty_items() {
    // Authored by the bot (case-insensitive) → dropped.
    let mine = item("t1_self", "TestBot", "my own message", None, None, None);
    assert!(parse_item(&mine, "testbot", &[]).is_none());

    // Empty body → dropped.
    let empty = item("t1_empty", "user1", "", None, None, None);
    assert!(parse_item(&empty, "testbot", &[]).is_none());
}

#[test]
fn subreddit_allow_list_gates_by_subreddit_but_not_dms() {
    let allow = vec!["rust".to_string()];

    let other = item("t1_other", "user1", "hi", None, Some("python"), None);
    assert!(parse_item(&other, "testbot", &allow).is_none());

    let matching = item("t1_match", "user1", "hi", None, Some("Rust"), None);
    assert!(parse_item(&matching, "testbot", &allow).is_some());

    // A DM (no subreddit) is always accepted even with an allow-list set.
    let dm = item("t4_dm", "user1", "hi", None, None, None);
    assert!(parse_item(&dm, "testbot", &allow).is_some());
}

#[test]
fn recipient_classification_routes_comment_vs_dm() {
    assert!(is_thing_fullname("t1_abc"));
    assert!(is_thing_fullname("t3_post"));
    assert!(is_thing_fullname("t4_msg"));
    assert!(!is_thing_fullname("someuser"));
}

#[test]
fn extract_children_reads_the_listing_and_fullnames() {
    let resp = json!({
        "kind": "Listing",
        "data": {
            "children": [
                { "kind": "t1", "data": { "name": "t1_a", "author": "u", "body": "x" } },
                { "kind": "t4", "data": { "name": "t4_b", "author": "v", "body": "y" } }
            ]
        }
    });
    let children = extract_children(&resp);
    assert_eq!(children.len(), 2);
    assert_eq!(item_fullname(&children[0]).as_deref(), Some("t1_a"));
    assert_eq!(item_fullname(&children[1]).as_deref(), Some("t4_b"));

    // A malformed / empty response yields no children.
    assert!(extract_children(&json!({})).is_empty());
}

#[test]
fn join_fullnames_is_comma_separated() {
    assert_eq!(
        join_fullnames(&["t1_a".to_string(), "t4_b".to_string()]),
        "t1_a,t4_b"
    );
    assert_eq!(join_fullnames(&[]), "");
}

#[test]
fn token_form_uses_the_refresh_grant() {
    let form = token_form("rt-123");
    assert_eq!(form[0], ("grant_type", "refresh_token".to_string()));
    assert_eq!(form[1], ("refresh_token", "rt-123".to_string()));
}

#[test]
fn token_response_extracts_or_rejects() {
    let ok = json!({ "access_token": "abc", "expires_in": 3600, "token_type": "bearer" });
    assert_eq!(parse_token_response(&ok).as_deref(), Some("abc"));

    let err = json!({ "error": "invalid_grant" });
    assert!(parse_token_response(&err).is_none());

    let blank = json!({ "access_token": "" });
    assert!(parse_token_response(&blank).is_none());
}

#[test]
fn base64_and_basic_auth_match_known_vectors() {
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    // "id:secret" → aWQ6c2VjcmV0
    assert_eq!(basic_auth_header("id", "secret"), "Basic aWQ6c2VjcmV0");
}

#[test]
fn config_parses_matches_native_fields_and_defaults() {
    let cfg = RedditConfig::from_json(
        r#"{"client_id":"cid","client_secret":"csec","refresh_token":"rt","username":"mybot","subreddits":["rust"],"enabled":true,"excluded_tools":["x"]}"#,
    );
    assert_eq!(cfg.client_id, "cid");
    assert_eq!(cfg.client_secret, "csec");
    assert_eq!(cfg.refresh_token, "rt");
    assert_eq!(cfg.username, "mybot");
    assert_eq!(cfg.subreddits, vec!["rust".to_string()]);
    assert!(cfg.has_credentials());

    // A withheld ("{}") or malformed section yields inert defaults.
    assert!(!RedditConfig::from_json("{}").has_credentials());
    assert!(!RedditConfig::from_json("not json").has_credentials());
}
