use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub owner: String,
}

impl Config {
    pub fn parse(json: &str) -> Result<Self, String> {
        let config: Self = serde_json::from_str(json).map_err(|_| "invalid Iris configuration")?;
        if config.owner.len() != 64
            || !config
                .owner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("approved Iris contact must be a 64-character hex public ID".into());
        }
        Ok(config)
    }

    pub fn recipient(&self, recipient: &str) -> Result<(), String> {
        if recipient == self.owner {
            Ok(())
        } else {
            Err("unapproved Iris contact".into())
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Job {
    pub id: String,
    pub owner: String,
    pub text: String,
    pub created: f64,
    pub interrupted: bool,
}

pub fn parse_job(value: serde_json::Value, config: &Config) -> Result<Option<Job>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let job: Job = serde_json::from_value(value).map_err(|_| "invalid Iris message")?;
    config.recipient(&job.owner)?;
    if job.id.is_empty()
        || job.id.len() > 300
        || job.text.trim().is_empty()
        || job.text.len() > 60000
        || !job.created.is_finite()
        || job.created < 0.0
    {
        return Err("invalid Iris message fields".into());
    }
    Ok(Some(job))
}

pub fn reply_key(anchor: &str, text: &str) -> String {
    format!("reply:{anchor}:{:x}", Sha256::digest(text.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_paired_contact_can_send_or_receive() {
        let owner = "a".repeat(64);
        let config = Config::parse(&json!({"owner":owner}).to_string()).unwrap();
        assert!(config.recipient(&owner).is_ok());
        assert!(config.recipient(&"b".repeat(64)).is_err());
        assert!(parse_job(json!({"id":"m1","owner":"b".repeat(64),"text":"hello","created":1.0,"interrupted":false}), &config).is_err());
        assert!(parse_job(
            json!({"id":"m1","owner":owner,"text":"hello","created":1.0,"interrupted":false}),
            &config
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn retries_keep_the_delivery_identity_but_new_turns_do_not() {
        assert_eq!(reply_key("m1", "hello"), reply_key("m1", "hello"));
        assert_ne!(reply_key("m1", "hello"), reply_key("m2", "hello"));
    }
}
