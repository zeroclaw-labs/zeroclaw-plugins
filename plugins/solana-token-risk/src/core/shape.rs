
use super::checks::{RiskLevel, RiskReport};

pub fn format_report(mint: &str, report: &RiskReport) -> String {
    let short = short_addr(mint);
    let badge = match report.level {
        RiskLevel::Red => "RED",
        RiskLevel::Amber => "AMBER",
        RiskLevel::Green => "GREEN",
    };
    let header = format!("{} - Token {}", badge, short);
    let mut parts = vec![header];
    for r in &report.reasons {
        parts.push(format!("- {}", r));
    }
    parts.join("\n")
}

fn short_addr(addr: &str) -> String {
    if addr.len() > 8 {
        format!("{}..{}", &addr[..4], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}
