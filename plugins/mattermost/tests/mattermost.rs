//! Host tests for the pure Mattermost core — the same mapping/payload logic the
//! wasm component runs, exercised with plain `cargo test` (no token, no network,
//! no wasm).

use mattermost::mattermost::{
    build_send_body, extract_posts, parse_post, parse_self_user_id, parse_self_username,
    post_create_at, posts_poll_url, posts_url, split_recipient, MattermostConfig,
};
use serde_json::json;

fn post(id: &str, user: &str, message: &str, create_at: i64, root_id: &str) -> serde_json::Value {
    json!({
        "id": id,
        "channel_id": "chan1",
        "user_id": user,
        "message": message,
        "create_at": create_at,
        "root_id": root_id,
    })
}

#[test]
fn parses_a_basic_post_into_a_threaded_reply_target() {
    // thread_replies=true → a top-level post threads on its own id.
    let inb = parse_post(
        &post("p1", "user1", "hello world", 1_700_000_000_000, ""),
        "bot1",
        true,
    )
    .expect("post maps");
    assert_eq!(inb.id, "mattermost_p1");
    assert_eq!(inb.sender, "user1");
    assert_eq!(inb.content, "hello world");
    assert_eq!(inb.reply_target, "chan1:p1");
    assert_eq!(inb.timestamp, 1_700_000_000); // create_at ms → seconds
    assert_eq!(inb.thread_ts, None);
    assert_eq!(inb.channel_alias, None);
}

#[test]
fn top_level_post_without_thread_replies_targets_the_channel() {
    let inb = parse_post(
        &post("p1", "user1", "hi", 1_700_000_000_000, ""),
        "bot1",
        false,
    )
    .expect("maps");
    assert_eq!(inb.reply_target, "chan1");
    assert_eq!(inb.thread_ts, None);
}

#[test]
fn reply_in_an_existing_thread_stays_in_the_thread() {
    // Even with thread_replies=false, a post with a root_id keeps threading.
    let inb = parse_post(
        &post("p2", "user1", "reply", 1_700_000_000_000, "root9"),
        "bot1",
        false,
    )
    .expect("maps");
    assert_eq!(inb.reply_target, "chan1:root9");
    assert_eq!(inb.thread_ts.as_deref(), Some("root9"));
}

#[test]
fn skips_our_own_posts() {
    // user_id == self_user_id → dropped (self-loop guard).
    assert!(parse_post(
        &post("p1", "bot1", "my own message", 1_700_000_000_000, ""),
        "bot1",
        true
    )
    .is_none());
    // A blank self id disables the guard (identity not yet resolved).
    assert!(parse_post(
        &post("p1", "bot1", "still delivered", 1_700_000_000_000, ""),
        "",
        true
    )
    .is_some());
}

#[test]
fn skips_empty_body_posts() {
    // Joins / system posts / attachment-only posts have no text to deliver.
    assert!(parse_post(
        &post("p1", "user1", "", 1_700_000_000_000, ""),
        "bot1",
        true
    )
    .is_none());
}

#[test]
fn extract_posts_sorts_oldest_first() {
    let resp = json!({
        "order": ["p3", "p1", "p2"],
        "posts": {
            "p1": post("p1", "user1", "first", 1000, ""),
            "p2": post("p2", "user1", "second", 2000, ""),
            "p3": post("p3", "user1", "third", 3000, ""),
        }
    });
    let posts = extract_posts(&resp);
    let order: Vec<i64> = posts.iter().map(post_create_at).collect();
    assert_eq!(order, vec![1000, 2000, 3000]);

    // A response with no posts object yields an empty list.
    assert!(extract_posts(&json!({ "order": [] })).is_empty());
}

#[test]
fn recipient_splits_channel_and_root() {
    assert_eq!(split_recipient("chan1"), ("chan1".to_string(), None));
    assert_eq!(
        split_recipient("chan1:root9"),
        ("chan1".to_string(), Some("root9".to_string()))
    );
}

#[test]
fn send_body_omits_root_id_at_top_level_and_includes_it_in_threads() {
    let top = build_send_body("chan1", "hi", None);
    assert_eq!(top["channel_id"], json!("chan1"));
    assert_eq!(top["message"], json!("hi"));
    assert!(top.get("root_id").is_none());

    // An empty root is treated as "no thread".
    assert!(build_send_body("chan1", "hi", Some(""))
        .get("root_id")
        .is_none());

    let threaded = build_send_body("chan1", "reply", Some("root9"));
    assert_eq!(threaded["root_id"], json!("root9"));
}

#[test]
fn urls_join_cleanly_regardless_of_trailing_slash() {
    assert_eq!(
        posts_poll_url("https://mm.example.com/", "chan1", 42),
        "https://mm.example.com/api/v4/channels/chan1/posts?since=42"
    );
    assert_eq!(
        posts_url("https://mm.example.com"),
        "https://mm.example.com/api/v4/posts"
    );
}

#[test]
fn parses_self_identity() {
    let me = json!({ "id": "bot1", "username": "mybot" });
    assert_eq!(parse_self_user_id(&me).as_deref(), Some("bot1"));
    assert_eq!(parse_self_username(&me).as_deref(), Some("@mybot"));

    // Missing/blank fields yield None (identity best-effort).
    assert!(parse_self_user_id(&json!({ "username": "mybot" })).is_none());
    assert!(parse_self_username(&json!({ "id": "bot1", "username": "" })).is_none());
}

#[test]
fn config_parses_and_defaults() {
    let cfg = MattermostConfig::from_json(
        r#"{"url":"https://mm.example.com/","bot_token":"tok123","channel_ids":["chan1"]}"#,
    );
    assert_eq!(cfg.base_url(), "https://mm.example.com"); // trailing slash trimmed
    assert_eq!(cfg.token(), "tok123");
    assert_eq!(cfg.channel_id().as_deref(), Some("chan1"));
    assert!(cfg.thread_replies()); // defaults to true

    // channel_id skips blanks and the "*" auto-discovery wildcard.
    let disc = MattermostConfig::from_json(r#"{"channel_ids":["*","  ","chanX"]}"#);
    assert_eq!(disc.channel_id().as_deref(), Some("chanX"));
    assert!(MattermostConfig::from_json(r#"{"channel_ids":["*"]}"#)
        .channel_id()
        .is_none());

    // thread_replies=false is honored.
    assert!(!MattermostConfig::from_json(r#"{"thread_replies":false}"#).thread_replies());

    // A withheld ("{}") or malformed section yields inert defaults; unknown
    // native fields (login_id, mention_only, …) are ignored, not errors.
    let empty = MattermostConfig::from_json("{}");
    assert_eq!(empty.token(), "");
    assert!(empty.channel_id().is_none());
    assert_eq!(MattermostConfig::from_json("not json").token(), "");
    assert_eq!(
        MattermostConfig::from_json(r#"{"url":"x","login_id":"a","mention_only":true}"#).base_url(),
        "x"
    );
}
