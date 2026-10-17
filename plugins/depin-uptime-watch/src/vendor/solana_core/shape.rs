use crate::{CoreError, CoreResult};

pub fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

pub fn assert_budget(s: &str, max_chars: usize) -> CoreResult<()> {
    if s.chars().count() > max_chars {
        Err(CoreError::msg(format!(
            "output exceeds budget ({max_chars} chars)"
        )))
    } else {
        Ok(())
    }
}

/// Compact pubkey/signature for chat cards (`AbCdEfGh…wXyZ`).
pub fn short_id(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 12 {
        return value.to_string();
    }
    let head: String = chars.iter().take(8).collect();
    let tail: String = chars.iter().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{head}…{tail}")
}
