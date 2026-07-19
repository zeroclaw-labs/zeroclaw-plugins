//! Pure T0 mint-risk core. No network in tests — callers inject MintFacts.

use crate::i18n::{self, Locale};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Green,
    Amber,
    Red,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Amber => "amber",
            Self::Red => "red",
        }
    }
}

/// Offline-injectable mint facts (from RPC/DAS later).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MintFacts {
    pub mint: String,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub supply: Option<u64>,
    pub decimals: Option<u8>,
    /// Token-2022 permanent delegate present.
    pub permanent_delegate: bool,
    /// Transfer hook / fee extension present.
    pub transfer_hook_or_fee: bool,
    pub is_token_2022: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskReport {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
    pub locale: String,
    pub summary: String,
    pub custody_tier: &'static str,
}

const INJECT_MARKERS: &[&str] = &[
    "ignore previous",
    "ignore all",
    "disregard instructions",
    "system prompt",
    "send all funds",
    "transfer everything",
    "exfiltrate",
    "private key",
    "seed phrase",
    "bypass safety",
    "jailbreak",
];

/// Fail-closed: adversarial natural-language payloads must not produce a risk opinion.
pub fn detect_prompt_injection(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    INJECT_MARKERS.iter().any(|m| lower.contains(m))
}

pub fn assess(facts: &MintFacts, locale_raw: &str) -> RiskReport {
    let locale = Locale::parse(locale_raw);
    let mut reasons: Vec<String> = Vec::new();
    let mut level = RiskLevel::Green;

    if facts.mint.trim().is_empty() || facts.mint.len() < 32 {
        reasons.push("mint_address_invalid_or_short".into());
        level = RiskLevel::Red;
    }

    if facts.mint_authority.is_some() {
        reasons.push("mint_authority_still_set".into());
        level = bump(level, RiskLevel::Amber);
    }

    if facts.freeze_authority.is_some() {
        reasons.push("freeze_authority_still_set".into());
        level = bump(level, RiskLevel::Amber);
    }

    if facts.permanent_delegate {
        reasons.push("token2022_permanent_delegate".into());
        level = bump(level, RiskLevel::Red);
    }

    if facts.transfer_hook_or_fee {
        reasons.push("token2022_transfer_hook_or_fee".into());
        level = bump(level, RiskLevel::Amber);
    }

    if facts.is_token_2022 && reasons.is_empty() {
        reasons.push("token2022_extensions_review_recommended".into());
        level = bump(level, RiskLevel::Amber);
    }

    if reasons.is_empty() {
        reasons.push("no_obvious_authority_or_extension_red_flags".into());
    }

    let label = i18n::risk_label(locale, level.as_str());
    let summary = format!(
        "[{label}] mint={} · reasons={}",
        truncate(&facts.mint, 12),
        reasons.join(",")
    );

    RiskReport {
        level,
        reasons,
        locale: format!("{locale:?}").to_ascii_lowercase(),
        summary,
        custody_tier: "T0",
    }
}

fn bump(current: RiskLevel, next: RiskLevel) -> RiskLevel {
    match (current, next) {
        (RiskLevel::Red, _) | (_, RiskLevel::Red) => RiskLevel::Red,
        (RiskLevel::Amber, _) | (_, RiskLevel::Amber) => RiskLevel::Amber,
        _ => RiskLevel::Green,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
