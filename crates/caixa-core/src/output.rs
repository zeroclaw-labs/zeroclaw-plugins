//! Shape tool outputs so they never flood the agent context window.

/// Soft ceiling (~200 tokens ≈ 800 chars for English/Portuguese mixed text).
pub const MAX_OUTPUT_CHARS: usize = 800;

pub fn shape_output(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= MAX_OUTPUT_CHARS {
        return s.to_string();
    }
    let truncated: String = s.chars().take(MAX_OUTPUT_CHARS.saturating_sub(1)).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_long() {
        let long = "x".repeat(2000);
        let out = shape_output(&long);
        assert!(out.chars().count() <= MAX_OUTPUT_CHARS);
        assert!(out.ends_with('…'));
    }
}
