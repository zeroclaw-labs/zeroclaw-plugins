//! Output shaping — trap #3 of the brief: "Return the 200 tokens the model
//! needs, not the 40KB the RPC sent. Judges will call execute and count
//! tokens." Every plugin passes its final output through here, and tests
//! assert the budget.

/// Rough token estimate (~4 chars/token heuristic — deliberately conservative).
pub fn approx_tokens(s: &str) -> usize {
    s.chars().count().div_ceil(4)
}

/// Default budget for tool output, per the brief's "~200 tokens" guidance.
pub const DEFAULT_BUDGET_TOKENS: usize = 200;

/// Clamp `s` to `max_tokens`, truncating at a char boundary with a marker.
pub fn clamp(s: &str, max_tokens: usize) -> String {
    if approx_tokens(s) <= max_tokens {
        return s.to_string();
    }
    let max_chars = max_tokens.saturating_mul(4).saturating_sub(2);
    let cut: String = s.chars().take(max_chars).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_strings_pass_through() {
        assert_eq!(clamp("hello", 200), "hello");
    }

    #[test]
    fn long_strings_are_clamped_to_budget() {
        let long = "x".repeat(10_000);
        let out = clamp(&long, DEFAULT_BUDGET_TOKENS);
        assert!(approx_tokens(&out) <= DEFAULT_BUDGET_TOKENS);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn budget_math() {
        assert_eq!(approx_tokens(""), 0);
        assert_eq!(approx_tokens("abcd"), 1);
        assert_eq!(approx_tokens("abcde"), 2);
    }
}
