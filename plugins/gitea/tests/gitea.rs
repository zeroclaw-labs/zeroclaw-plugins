//! Host tests for the pure Gitea core — the same config/mapping/time logic the
//! wasm component runs, exercised with plain `cargo test` (no token, no network,
//! no wasm). Complements the in-module unit tests by driving the core as an
//! external consumer, mirroring the poll pipeline end to end.

use gitea::gitea::{
    build_comment_body, chunk_text, comment_to_inbound, create_comment_url, notifications_url,
    rfc3339_to_unix, should_admit, unix_to_rfc3339, GiteaComment, GiteaConfig, IssueRef,
    NotificationThread, RepoRef,
};
use serde_json::json;

/// A serialized native `git` section (GitConfig-shaped) for a Gitea instance.
fn git_section() -> String {
    json!({
        "enabled": true,
        "provider": "gitea",
        "app_id": 0,
        "private_key_path": "",
        "api_base_url": "https://git.example.org/api/v1",
        "access_token": "tok",
        "repos": [],
        "poll_interval_secs": 30,
        "mention_only": true,
        "listen_to_bots": false,
        "events": {}
    })
    .to_string()
}

#[test]
fn config_from_native_git_section_is_active() {
    let cfg = GiteaConfig::from_json(&git_section());
    assert!(cfg.is_active());
    assert_eq!(
        cfg.base_url().as_deref(),
        Some("https://git.example.org/api/v1")
    );
    assert_eq!(cfg.token(), "tok");
    assert!(cfg.mention_only);
}

#[test]
fn github_section_leaves_plugin_inert() {
    let cfg = GiteaConfig::from_json(
        &json!({"provider": "github", "app_id": 12, "private_key_path": "/k.pem"}).to_string(),
    );
    assert!(
        !cfg.is_active(),
        "a GitHub git section must not activate the Gitea plugin"
    );
}

/// End-to-end poll shape: a notification thread → its latest comment JSON →
/// admitted inbound, exactly as `poll_message` assembles it.
#[test]
fn notification_and_comment_map_to_an_inbound() {
    let thread: NotificationThread = serde_json::from_value(json!({
        "id": 5,
        "repository": {"full_name": "forge/project"},
        "subject": {
            "title": "Bug",
            "url": "https://git.example.org/api/v1/repos/forge/project/issues/7",
            "latest_comment_url": "https://git.example.org/api/v1/repos/forge/project/issues/comments/99",
            "type": "Issue"
        },
        "updated_at": "2026-06-13T01:05:00Z"
    }))
    .unwrap();
    assert_eq!(
        thread.comment_url(),
        Some("https://git.example.org/api/v1/repos/forge/project/issues/comments/99")
    );
    let repo = thread.repo().expect("repo resolves from the notification");
    assert_eq!(repo, RepoRef::parse("forge/project").unwrap());

    let comment: GiteaComment = serde_json::from_value(json!({
        "id": 99,
        "body": "@mybot please take a look",
        "user": {"login": "alice"},
        "created_at": "2026-06-13T01:05:00Z",
        "issue_url": "https://git.example.org/api/v1/repos/forge/project/issues/7"
    }))
    .unwrap();

    assert!(should_admit(&comment, "mybot", true, false));
    let inb = comment_to_inbound(&comment, &repo).unwrap();
    assert_eq!(inb.id, "ghc_99");
    assert_eq!(inb.sender, "alice");
    assert_eq!(inb.reply_target, "forge/project#7");
    assert_eq!(inb.content, "@mybot please take a look");
    assert_eq!(
        inb.timestamp,
        rfc3339_to_unix("2026-06-13T01:05:00Z").unwrap() as u64
    );
}

#[test]
fn unmentioned_comment_is_dropped_under_mention_only() {
    let comment: GiteaComment = serde_json::from_value(json!({
        "id": 1,
        "body": "just chatting, no bot here",
        "user": {"login": "alice"},
        "created_at": "2026-06-13T01:05:00Z",
        "issue_url": "https://h/api/v1/repos/o/r/issues/1"
    }))
    .unwrap();
    assert!(!should_admit(&comment, "mybot", true, false));
    assert!(should_admit(&comment, "mybot", false, false));
}

#[test]
fn send_recipient_and_body_round_trip() {
    let target = IssueRef::parse("forge/project#7").unwrap();
    assert_eq!(
        create_comment_url(
            "https://git.example.org/api/v1",
            &target.repo,
            target.number
        ),
        "https://git.example.org/api/v1/repos/forge/project/issues/7/comments"
    );
    assert_eq!(build_comment_body("done"), json!({"body": "done"}));
}

#[test]
fn poll_url_and_cursor_time_round_trip() {
    let since = rfc3339_to_unix("2026-07-10T12:00:00Z").unwrap();
    let url = notifications_url("https://git.example.org/api/v1", &unix_to_rfc3339(since));
    assert_eq!(
        url,
        "https://git.example.org/api/v1/notifications?all=false&since=2026-07-10T12%3A00%3A00Z"
    );
}

#[test]
fn long_reply_is_chunked() {
    let text = "line\n".repeat(30_000); // 150k chars
    let chunks = chunk_text(&text, 60_000);
    assert!(chunks.len() >= 3);
    assert!(chunks.iter().all(|c| c.chars().count() <= 60_000));
    assert_eq!(chunks.concat(), text);
}

#[test]
fn url_path_drops_host_query_and_fragment() {
    assert_eq!(
        gitea::gitea::url_path("https://server.example.org/api/v1/notifications?since=1&token=x#f"),
        "/api/v1/notifications"
    );
    assert_eq!(gitea::gitea::url_path("https://server.example.org"), "/");
    assert_eq!(
        gitea::gitea::url_path("/relative/path?q=1"),
        "/relative/path"
    );
}

#[test]
fn url_path_ignores_a_slash_in_the_query_of_a_pathless_url() {
    assert_eq!(
        gitea::gitea::url_path("https://server.example.org?x=/y"),
        "/"
    );
}
