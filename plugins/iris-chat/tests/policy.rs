use iris_chat::core::{parse_job, Config};
use serde_json::json;

#[test]
fn an_unapproved_sender_cannot_enter_the_agent() {
    let owner = "a".repeat(64);
    let config = Config::parse(&json!({"owner": owner}).to_string()).unwrap();
    let mut job = json!({"id":"message-1", "owner":"b".repeat(64), "text":"run a command", "created":1.0, "interrupted":false});
    assert!(parse_job(job.clone(), &config).is_err());
    job["owner"] = json!(owner);
    assert!(parse_job(job, &config).unwrap().is_some());
}

#[test]
fn empty_and_oversized_jobs_are_not_delivered() {
    let config = Config::parse(&json!({"owner":"a".repeat(64)}).to_string()).unwrap();
    assert!(parse_job(serde_json::Value::Null, &config)
        .unwrap()
        .is_none());
    let job = json!({"id":"message-1", "owner":"a".repeat(64), "text":"x".repeat(60001), "created":1.0, "interrupted":false});
    assert!(parse_job(job, &config).is_err());
}

#[test]
fn accepted_job_ids_fit_the_bridge_delivery_key_limit() {
    use iris_chat::core::{recovery_key, reply_key};
    let id = "x".repeat(300);
    let reply = reply_key(&id, "ack");
    let recovery = recovery_key(&id);
    assert!(reply.len() <= 300);
    assert!(recovery.len() <= 300);
    assert_eq!(reply, reply_key(&id, "ack"));
    assert_ne!(reply, reply_key(&id, "different reply"));
    assert_ne!(reply, reply_key(&"y".repeat(300), "ack"));
    assert_ne!(reply, recovery);
    assert_eq!(recovery_key("short"), "recovery:short");
}

#[test]
fn unicode_delivery_keys_preserve_previously_accepted_retry_ids() {
    use iris_chat::core::{recovery_key, reply_key};

    // "reply:", the separator, and the ASCII SHA-256 digest use 71 characters.
    let anchor = format!("é{}", "a".repeat(228));
    let reply = reply_key(&anchor, "ack");
    assert_eq!(reply.chars().count(), 300);
    assert_eq!(reply.len(), 301);
    assert!(reply.starts_with(&format!("reply:{anchor}:")));
    assert!(reply_key(&(anchor + "x"), "ack").starts_with("hash:"));

    let job = format!("é{}", "a".repeat(290));
    assert_eq!(recovery_key(&job), format!("recovery:{job}"));
    assert!(recovery_key(&(job + "x")).starts_with("hash:"));
}
