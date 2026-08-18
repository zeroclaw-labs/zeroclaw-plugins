//! Host tests for the pure Bluesky core — the same mapping/payload logic the
//! wasm component runs, exercised with plain `cargo test` (no credentials, no
//! network, no wasm).

use bluesky::bluesky::{
    build_create_session, build_send_body, build_update_seen, decode_reply_target,
    extract_notifications, iso8601_to_millis, latest_indexed_at, millis_to_rfc3339,
    parse_notification, parse_session, truncate_post, xrpc_url, BlueskyConfig,
};
use serde_json::json;

/// A `listNotifications` entry. `record` is the subject post's record (its
/// `text`, and — for a reply — its own `reply.root`/`reply.parent`).
fn notif(
    reason: &str,
    handle: &str,
    did: &str,
    text: &str,
    is_read: bool,
    record_extra: serde_json::Value,
) -> serde_json::Value {
    let mut record = json!({ "text": text });
    if let Some(obj) = record_extra.as_object() {
        for (k, v) in obj {
            record[k] = v.clone();
        }
    }
    json!({
        "uri": format!("at://{did}/app.bsky.feed.post/abc123"),
        "cid": "bafyreipost123",
        "author": { "did": did, "handle": handle, "displayName": null },
        "reason": reason,
        "record": record,
        "isRead": is_read,
        "indexedAt": "2026-01-15T10:00:00.000Z",
    })
}

const SELF_DID: &str = "did:plc:testbot";

#[test]
fn parses_a_mention() {
    let n = notif(
        "mention",
        "user1.bsky.social",
        "did:plc:user1",
        "@testbot hello",
        false,
        json!({}),
    );
    let inb = parse_notification(&n, SELF_DID).expect("mention maps");
    assert_eq!(inb.sender, "user1.bsky.social");
    assert_eq!(inb.content, "@testbot hello");
    assert_eq!(inb.id, "bluesky_bafyreipost123");
    assert_eq!(inb.timestamp, iso8601_to_millis("2026-01-15T10:00:00.000Z"));
    // A mention is its own thread root: parent == root in the compound target.
    let parts: Vec<&str> = inb.reply_target.split('|').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "at://did:plc:user1/app.bsky.feed.post/abc123"); // parent uri
    assert_eq!(parts[1], "bafyreipost123"); // parent cid
    assert_eq!(parts[2], parts[0]); // root uri == parent uri
    assert_eq!(parts[3], parts[1]); // root cid == parent cid
    assert_eq!(inb.thread_ts.as_deref(), Some(parts[0]));
}

#[test]
fn reply_threads_on_the_conversation_root() {
    // A reply carries its own thread root in record.reply.root.
    let n = notif(
        "reply",
        "user2.bsky.social",
        "did:plc:user2",
        "thanks!",
        false,
        json!({
            "reply": {
                "root":   { "uri": "at://did:plc:orig/app.bsky.feed.post/root", "cid": "bafyreiroot" },
                "parent": { "uri": "at://did:plc:mid/app.bsky.feed.post/mid",  "cid": "bafyreimid"  }
            }
        }),
    );
    let inb = parse_notification(&n, SELF_DID).expect("reply maps");
    let parts: Vec<&str> = inb.reply_target.split('|').collect();
    assert_eq!(parts.len(), 4);
    // Parent is the notified post itself; root is the conversation root.
    assert_eq!(parts[0], "at://did:plc:user2/app.bsky.feed.post/abc123");
    assert_eq!(parts[1], "bafyreipost123");
    assert_eq!(parts[2], "at://did:plc:orig/app.bsky.feed.post/root");
    assert_eq!(parts[3], "bafyreiroot");
    assert_eq!(
        inb.thread_ts.as_deref(),
        Some("at://did:plc:orig/app.bsky.feed.post/root")
    );
}

#[test]
fn skips_read_notifications() {
    let n = notif(
        "mention",
        "u.bsky.social",
        "did:plc:u",
        "old",
        true,
        json!({}),
    );
    assert!(parse_notification(&n, SELF_DID).is_none());
}

#[test]
fn skips_own_posts() {
    let n = notif(
        "mention",
        "testbot.bsky.social",
        SELF_DID,
        "self",
        false,
        json!({}),
    );
    assert!(parse_notification(&n, SELF_DID).is_none());
}

#[test]
fn skips_non_mention_reasons() {
    for reason in ["like", "repost", "follow", "quote"] {
        let n = notif(reason, "u.bsky.social", "did:plc:u", "x", false, json!({}));
        assert!(
            parse_notification(&n, SELF_DID).is_none(),
            "{reason} should be skipped"
        );
    }
}

#[test]
fn skips_empty_text() {
    let n = notif(
        "mention",
        "u.bsky.social",
        "did:plc:u",
        "",
        false,
        json!({}),
    );
    assert!(parse_notification(&n, SELF_DID).is_none());
}

#[test]
fn decode_reply_target_handles_all_forms() {
    // 4-part compound (this plugin).
    let refs = decode_reply_target("puri|pcid|ruri|rcid").expect("4-part decodes");
    assert_eq!(refs.parent_uri, "puri");
    assert_eq!(refs.parent_cid, "pcid");
    assert_eq!(refs.root_uri, "ruri");
    assert_eq!(refs.root_cid, "rcid");

    // 2-part legacy form (native channel): parent == root.
    let refs = decode_reply_target("uri|cid").expect("2-part decodes");
    assert_eq!(refs.parent_uri, "uri");
    assert_eq!(refs.root_uri, "uri");
    assert_eq!(refs.root_cid, "cid");

    // No pipe → top-level post (no reply).
    assert!(decode_reply_target("just-a-handle").is_none());
    assert!(decode_reply_target("").is_none());
}

#[test]
fn send_body_top_level_has_no_reply() {
    let body = build_send_body(
        "did:plc:me",
        "hello world",
        "no-pipe",
        "2026-01-15T10:00:00.000Z",
    );
    assert_eq!(body["repo"], json!("did:plc:me"));
    assert_eq!(body["collection"], json!("app.bsky.feed.post"));
    assert_eq!(body["record"]["$type"], json!("app.bsky.feed.post"));
    assert_eq!(body["record"]["text"], json!("hello world"));
    assert_eq!(
        body["record"]["createdAt"],
        json!("2026-01-15T10:00:00.000Z")
    );
    assert!(body["record"].get("reply").is_none());
}

#[test]
fn send_body_threads_a_reply() {
    let target = "at://p/uri|pcid|at://r/uri|rcid";
    let body = build_send_body(
        "did:plc:me",
        "reply text",
        target,
        "2026-01-15T10:00:00.000Z",
    );
    assert_eq!(
        body["record"]["reply"]["parent"]["uri"],
        json!("at://p/uri")
    );
    assert_eq!(body["record"]["reply"]["parent"]["cid"], json!("pcid"));
    assert_eq!(body["record"]["reply"]["root"]["uri"], json!("at://r/uri"));
    assert_eq!(body["record"]["reply"]["root"]["cid"], json!("rcid"));
}

#[test]
fn truncates_at_the_post_limit() {
    assert_eq!(truncate_post("short"), "short");
    let long: String = "x".repeat(500);
    let out = truncate_post(&long);
    assert_eq!(out.chars().count(), 300);
    assert!(out.ends_with("..."));
}

#[test]
fn create_session_and_update_seen_bodies() {
    let cs = build_create_session("mybot.bsky.social", "app-pass");
    assert_eq!(cs["identifier"], json!("mybot.bsky.social"));
    assert_eq!(cs["password"], json!("app-pass"));

    let us = build_update_seen("2026-01-15T10:00:00.000Z");
    assert_eq!(us["seenAt"], json!("2026-01-15T10:00:00.000Z"));
}

#[test]
fn parses_session_response() {
    let ok = json!({
        "accessJwt": "jwt-abc",
        "refreshJwt": "refresh-abc",
        "did": "did:plc:me",
        "handle": "mybot.bsky.social"
    });
    let s = parse_session(&ok).expect("session parses");
    assert_eq!(s.access_jwt, "jwt-abc");
    assert_eq!(s.did, "did:plc:me");
    assert_eq!(s.handle, "mybot.bsky.social");

    // Missing required fields → None (inert).
    assert!(parse_session(&json!({ "handle": "x" })).is_none());
    assert!(parse_session(&json!({ "accessJwt": "", "did": "d" })).is_none());
}

#[test]
fn extracts_and_ranks_notifications() {
    let resp = json!({
        "notifications": [
            { "indexedAt": "2026-01-15T10:00:00.000Z" },
            { "indexedAt": "2026-01-15T12:30:00.000Z" },
            { "indexedAt": "2026-01-15T09:00:00.000Z" }
        ],
        "cursor": "next-page"
    });
    let notifs = extract_notifications(&resp);
    assert_eq!(notifs.len(), 3);
    assert_eq!(
        latest_indexed_at(&notifs).as_deref(),
        Some("2026-01-15T12:30:00.000Z")
    );

    assert!(extract_notifications(&json!({})).is_empty());
    assert!(latest_indexed_at(&[]).is_none());
}

#[test]
fn xrpc_url_joins_the_method() {
    assert_eq!(
        xrpc_url("https://bsky.social", "com.atproto.server.createSession"),
        "https://bsky.social/xrpc/com.atproto.server.createSession"
    );
    // A trailing slash on the base is trimmed.
    assert_eq!(
        xrpc_url(
            "https://pds.example.com/",
            "app.bsky.notification.listNotifications"
        ),
        "https://pds.example.com/xrpc/app.bsky.notification.listNotifications"
    );
}

#[test]
fn timestamp_conversion_round_trips() {
    // Known epoch: 2020-01-01T00:00:00Z == 1577836800 s.
    assert_eq!(
        iso8601_to_millis("2020-01-01T00:00:00.000Z"),
        1_577_836_800_000
    );
    assert_eq!(iso8601_to_millis("1970-01-01T00:00:00.000Z"), 0);
    assert_eq!(iso8601_to_millis("1970-01-01T00:00:01.500Z"), 1_500);
    // Fractional padding: ".1" → 100 ms, ".12" → 120 ms.
    assert_eq!(iso8601_to_millis("1970-01-01T00:00:00.1Z"), 100);
    assert_eq!(iso8601_to_millis("1970-01-01T00:00:00.12Z"), 120);
    // Unparseable → 0 (inert).
    assert_eq!(iso8601_to_millis("not-a-date"), 0);

    assert_eq!(millis_to_rfc3339(0), "1970-01-01T00:00:00.000Z");
    let s = "2026-01-15T10:00:00.000Z";
    assert_eq!(millis_to_rfc3339(iso8601_to_millis(s)), s);
}

#[test]
fn config_parses_matches_native_fields_and_defaults() {
    let cfg = BlueskyConfig::from_json(
        r#"{"handle":"mybot.bsky.social","app_password":"abc-123","enabled":true,"excluded_tools":["shell"]}"#,
    );
    assert_eq!(cfg.handle, "mybot.bsky.social");
    assert_eq!(cfg.app_password, "abc-123");
    // `service` defaults to the public PDS; native-only fields are ignored.
    assert_eq!(cfg.base_url(), "https://bsky.social");
    assert!(cfg.has_credentials());

    // Explicit service override, trailing slash trimmed by base_url().
    let cfg = BlueskyConfig::from_json(
        r#"{"handle":"h","app_password":"p","service":"https://pds.example.com/"}"#,
    );
    assert_eq!(cfg.base_url(), "https://pds.example.com");

    // A withheld ("{}") or malformed section yields inert defaults.
    assert!(!BlueskyConfig::from_json("{}").has_credentials());
    assert!(!BlueskyConfig::from_json("not json").has_credentials());
    assert_eq!(
        BlueskyConfig::from_json("{}").base_url(),
        "https://bsky.social"
    );
}
