//! Fail-closed injection filter. External strings are DATA, never instructions.
use crate::CoreError;

const PATTERNS: &[&str] = &[
    "ignore previous",
    "ignore all",
    "system:",
    "assistant:",
    "<tool",
    "tool_call",
    "disregard",
    "new instructions",
];

pub fn check_text(field: &str, value: &str, max_len: usize) -> Result<(), CoreError> {
    if value.len() > max_len {
        return Err(CoreError::Injection(format!("{field}: too long")));
    }
    let lower = value.to_lowercase();
    for p in PATTERNS {
        if lower.contains(p) {
            return Err(CoreError::Injection(format!(
                "{field}: instruction-like content"
            )));
        }
    }
    if value.chars().any(|c| c.is_control() && c != '\n') {
        return Err(CoreError::Injection(format!("{field}: control characters")));
    }
    Ok(())
}
