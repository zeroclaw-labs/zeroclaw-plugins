//! Pure guard API — decode → narrate → assess → verdict.
//! No WASM dependency; host-testable with `cargo test`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::core::narrate::narrate_transaction;
use crate::core::risk::{assess, max_severity, Finding, Severity};
use crate::core::tx::{decode_transaction_base64, DecodeError};

/// Structured verdict returned to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Allow,
    Hold,
    Reject,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardReport {
    pub verdict: Verdict,
    pub summary: String,
    pub narration: String,
    pub findings: Vec<Finding>,
    pub tx_version: String,
    pub instruction_count: usize,
    pub account_count: usize,
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    /// Reject on Critical findings (default true).
    pub reject_on_critical: bool,
    /// Hold on High findings when not rejecting (default true).
    pub hold_on_high: bool,
    /// Hold on Medium findings (default false — Medium alone → ALLOW with notes).
    pub hold_on_medium: bool,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            reject_on_critical: true,
            hold_on_high: true,
            hold_on_medium: false,
        }
    }
}

impl GuardConfig {
    /// Build from the flat `string -> string` section the host injects.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = section.get("reject_on_critical") {
            cfg.reject_on_critical = parse_bool(v, true);
        }
        if let Some(v) = section.get("hold_on_high") {
            cfg.hold_on_high = parse_bool(v, true);
        }
        if let Some(v) = section.get("hold_on_medium") {
            cfg.hold_on_medium = parse_bool(v, false);
        }
        cfg
    }
}

fn parse_bool(v: &str, default: bool) -> bool {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => true,
        "false" | "0" | "no" => false,
        _ => default,
    }
}

/// Analyze a base64-encoded Solana transaction and return a guard report.
pub fn analyze(transaction_base64: &str, cfg: &GuardConfig) -> Result<GuardReport, String> {
    let tx = decode_transaction_base64(transaction_base64).map_err(|e| e.to_string())?;
    let narration = narrate_transaction(&tx);
    let findings = assess(&tx);
    let verdict = verdict_from_findings(&findings, cfg);
    let summary = summary_line(verdict, &findings);

    let tx_version = match tx.version {
        crate::core::tx::TxVersion::Legacy => "legacy",
        crate::core::tx::TxVersion::V0 => "v0",
    }
    .to_string();

    Ok(GuardReport {
        verdict,
        summary,
        narration,
        findings,
        tx_version,
        instruction_count: tx.message.instructions.len(),
        account_count: tx.message.account_keys.len(),
    })
}

pub fn verdict_from_findings(findings: &[Finding], cfg: &GuardConfig) -> Verdict {
    match max_severity(findings) {
        Some(Severity::Critical) if cfg.reject_on_critical => Verdict::Reject,
        Some(Severity::Critical) => Verdict::Hold,
        Some(Severity::High) if cfg.hold_on_high => Verdict::Hold,
        Some(Severity::Medium) if cfg.hold_on_medium => Verdict::Hold,
        _ => Verdict::Allow,
    }
}

fn summary_line(verdict: Verdict, findings: &[Finding]) -> String {
    let top = findings.first().map(|f| f.code.as_str()).unwrap_or("NONE");
    match verdict {
        Verdict::Allow => {
            if findings.is_empty() {
                "ALLOW — no elevated risk signals".into()
            } else {
                format!("ALLOW — {top} noted, below hold/reject threshold")
            }
        }
        Verdict::Hold => format!("HOLD — review required ({top})"),
        Verdict::Reject => format!("REJECT — dangerous primitive detected ({top})"),
    }
}

/// Render the report as agent-friendly JSON (pretty).
pub fn report_json(report: &GuardReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Map decode errors into a stable tool error string.
pub fn format_decode_error(err: DecodeError) -> String {
    format!("failed to decode transaction: {err}")
}
