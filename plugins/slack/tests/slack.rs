//! Host tests for the pure Slack core — the same signature-verification and
//! payload-decode logic the wasm component runs, exercised from the crate
//! boundary with plain `cargo test` (no token, no network, no wasm).

use slack::slack::{
    build_send_body, chunk_text, compute_signature, parse_webhook, verify_signature, Inbound,
    SlackConfig, WebhookOutcome,
};

const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";

fn signed(ts: &str, body: &[u8]) -> Vec<(String, String)> {
    vec![
        ("x-slack-request-timestamp".to_string(), ts.to_string()),
        (
            "x-slack-signature".to_string(),
            compute_signature(SECRET, ts, body),
        ),
    ]
}

#[test]
fn end_to_end_message_event() {
    let ts = "1700000000";
    let body = br#"{"type":"event_callback","event":{"type":"message","user":"U9","channel":"C9","text":"ping","ts":"1700000000.001"}}"#;
    let out = parse_webhook(SECRET, "POST", &signed(ts, body), body, 1_700_000_000).unwrap();
    assert_eq!(
        out,
        WebhookOutcome::Messages(vec![Inbound {
            id: "slack_1700000000.001".to_string(),
            sender: "U9".to_string(),
            reply_target: "C9".to_string(),
            content: "ping".to_string(),
            timestamp: 1_700_000_000_001,
        }])
    );
}

#[test]
fn end_to_end_challenge_handshake() {
    let ts = "1700000000";
    let body = br#"{"type":"url_verification","challenge":"abc123"}"#;
    let out = parse_webhook(SECRET, "POST", &signed(ts, body), body, 1_700_000_000).unwrap();
    assert_eq!(out, WebhookOutcome::Challenge("abc123".to_string()));
}

#[test]
fn forged_signature_is_rejected_at_the_boundary() {
    let ts = "1700000000";
    let body = br#"{"type":"url_verification","challenge":"abc123"}"#;
    let headers = vec![
        ("x-slack-request-timestamp".to_string(), ts.to_string()),
        ("x-slack-signature".to_string(), "v0=deadbeef".to_string()),
    ];
    assert!(parse_webhook(SECRET, "POST", &headers, body, 1_700_000_000).is_err());
}

#[test]
fn config_and_send_body_round_trip() {
    let cfg = SlackConfig::from_json(r#"{"bot_token":"xoxb-x","signing_secret":"s"}"#);
    assert_eq!(
        cfg.post_message_url(),
        "https://slack.com/api/chat.postMessage"
    );
    let b = build_send_body("C1", "hi", None);
    assert_eq!(b["channel"], "C1");
    assert_eq!(b["text"], "hi");
}

#[test]
fn verify_and_chunk_are_public() {
    let ts = "1700000000";
    let body = b"{}";
    let sig = compute_signature(SECRET, ts, body);
    assert!(verify_signature(SECRET, ts, &sig, body, 1_700_000_000).is_ok());
    assert_eq!(chunk_text("ab", 1), vec!["a".to_string(), "b".to_string()]);
}
