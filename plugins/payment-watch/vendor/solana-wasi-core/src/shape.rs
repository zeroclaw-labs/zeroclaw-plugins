//! Output shaping: what the model reads after `execute` returns.
//!
//! The sponsor's trap #3: "Judges will call execute and count tokens." Every
//! tool result routed through [`ToolOutput`] is a compact, human-readable
//! summary — never raw RPC JSON.

use serde::Serialize;

/// Hard character budget for any tool output (~200 tokens ≈ 800 chars).
pub const MAX_OUTPUT_CHARS: usize = 900;

#[derive(Serialize)]
pub struct ToolOutput {
    pub status: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_tx_base64: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub details: Vec<String>,
}

impl ToolOutput {
    pub fn ok(summary: impl Into<String>) -> Self {
        Self {
            status: "ok".into(),
            summary: summary.into(),
            unsigned_tx_base64: None,
            details: Vec::new(),
        }
    }

    pub fn refused(summary: impl Into<String>) -> Self {
        Self {
            status: "refused".into(),
            summary: summary.into(),
            unsigned_tx_base64: None,
            details: Vec::new(),
        }
    }

    pub fn with_tx(mut self, tx_b64: String) -> Self {
        self.unsigned_tx_base64 = Some(tx_b64);
        self
    }

    pub fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.details.push(d.into());
        self
    }

    /// Serialize with the summary/details clamped to budget. The base64 tx is
    /// exempt (it is payload for the host approval gate, not model prose).
    pub fn render(mut self) -> String {
        self.summary = clamp(&self.summary, 300);
        let mut budget = MAX_OUTPUT_CHARS.saturating_sub(self.summary.len());
        self.details = self
            .details
            .into_iter()
            .filter_map(|d| {
                if budget == 0 {
                    return None;
                }
                let c = clamp(&d, budget.min(200));
                budget = budget.saturating_sub(c.len());
                Some(c)
            })
            .collect();
        serde_json::to_string(&self).unwrap_or_else(|_| "{\"status\":\"error\"}".into())
    }
}

pub fn clamp(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_stays_in_budget() {
        let huge = "x".repeat(10_000);
        let out = ToolOutput::ok(huge.clone()).with_detail(huge).render();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let prose_len = parsed["summary"].as_str().unwrap().len()
            + parsed["details"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::len).sum())
                .unwrap_or(0usize);
        assert!(prose_len <= MAX_OUTPUT_CHARS + 10);
    }

    #[test]
    fn tx_payload_survives_untruncated() {
        let tx = "A".repeat(2000);
        let out = ToolOutput::ok("built").with_tx(tx.clone()).render();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["unsigned_tx_base64"].as_str().unwrap(), tx);
    }

    #[test]
    fn clamp_respects_unicode() {
        assert_eq!(clamp("día", 10), "día");
        let c = clamp("ééééééééééééé", 5);
        assert!(c.chars().count() <= 5);
    }
}
