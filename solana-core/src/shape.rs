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
