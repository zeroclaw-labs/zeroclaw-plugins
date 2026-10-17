use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Activity {
    pub signature: String,
    pub slot: u64,
    pub kind: String,
}

pub fn redact_signature(signature: &str) -> String {
    if signature.len() <= 10 {
        return "[redacted]".into();
    }
    format!("{}…{}", &signature[..6], &signature[signature.len() - 4..])
}

pub fn summarize(items: &[Activity], limit: usize) -> Vec<String> {
    items
        .iter()
        .take(limit.min(20))
        .map(|a| {
            format!(
                "{} · slot {} · {}",
                redact_signature(&a.signature),
                a.slot,
                a.kind
            )
        })
        .collect()
}

pub fn activities_from_rpc(value: &Value) -> Result<Vec<Activity>, &'static str> {
    let rows = value.as_array().ok_or("signature result is not an array")?;
    rows.iter()
        .take(20)
        .map(|row| {
            Ok(Activity {
                signature: row
                    .get("signature")
                    .and_then(Value::as_str)
                    .ok_or("signature missing")?
                    .to_string(),
                slot: row
                    .get("slot")
                    .and_then(Value::as_u64)
                    .ok_or("slot missing")?,
                kind: if row.get("err").is_some_and(|v| !v.is_null()) {
                    "failed".into()
                } else {
                    "transaction".into()
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_and_redacted() {
        let a = Activity {
            signature: "1234567890abcdef".into(),
            slot: 7,
            kind: "transfer".into(),
        };
        let x = summarize(&[a], 99);
        assert_eq!(x.len(), 1);
        assert!(x[0].contains("123456…cdef"));
    }

    #[test]
    fn parses_bounded_rpc_signatures_and_marks_failures() {
        let value = serde_json::json!([
            {"signature":"1234567890abcdef","slot":9,"err":null},
            {"signature":"abcdef1234567890","slot":10,"err":{"code":1}}
        ]);
        let items = activities_from_rpc(&value).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind, "transaction");
        assert_eq!(items[1].kind, "failed");
    }
}
