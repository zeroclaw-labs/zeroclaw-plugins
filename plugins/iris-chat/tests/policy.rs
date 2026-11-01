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
