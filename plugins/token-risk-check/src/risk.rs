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

/// Honest LP signal — never invent "locked" without proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LpStatus {
    /// USDC/WSOL/etc. — LP check N/A for this tool's job.
    BluechipSkip,
    /// No on-chain LP proof fetched; do not assume safe liquidity.
    #[default]
    Unverified,
}

/// Offline-injectable mint facts (from RPC).
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
    /// Share of supply held by top-10 largest token accounts (0..100).
    pub top10_holder_pct: Option<f64>,
    /// Share held by the single largest account (0..100).
    pub largest_holder_pct: Option<f64>,
    pub lp_status: LpStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskReport {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
    pub locale: String,
    /// Short chat line (~200 tokens budget).
    pub summary: String,
    pub custody_tier: &'static str,
    pub top10_holder_pct: Option<f64>,
    pub largest_holder_pct: Option<f64>,
    pub lp_status: LpStatus,
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

/// Well-known mints where "LP status" is not the risk question.
const BLUECHIP_MINTS: &[&str] = &[
    "So11111111111111111111111111111111111111112",  // WSOL
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // USDC
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // USDT
];

pub fn is_bluechip_mint(mint: &str) -> bool {
    BLUECHIP_MINTS.contains(&mint)
}

/// Fail-closed: adversarial natural-language payloads must not produce a risk opinion.
pub fn detect_prompt_injection(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    INJECT_MARKERS.iter().any(|m| lower.contains(m))
}

pub fn assess(facts: &MintFacts, locale_raw: &str) -> RiskReport {
    let locale = Locale::parse(locale_raw);
    let mut reasons: Vec<String> = Vec::new();
    let mut level = RiskLevel::Green;

    let mut facts = facts.clone();
    if is_bluechip_mint(&facts.mint) {
        facts.lp_status = LpStatus::BluechipSkip;
    }

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

    if facts.is_token_2022
        && !facts.permanent_delegate
        && !facts.transfer_hook_or_fee
        && reasons.iter().all(|r| r != "mint_address_invalid_or_short")
    {
        // Mild caution only when no worse flags yet.
        if matches!(level, RiskLevel::Green) {
            reasons.push("token2022_extensions_review_recommended".into());
            level = bump(level, RiskLevel::Amber);
        }
    }

    if let Some(top10) = facts.top10_holder_pct {
        if top10 >= 90.0 {
            reasons.push(format!("holder_top10_extreme:{top10:.1}%"));
            level = bump(level, RiskLevel::Red);
        } else if top10 >= 70.0 {
            reasons.push(format!("holder_top10_high:{top10:.1}%"));
            level = bump(level, RiskLevel::Amber);
        }
    }

    if let Some(largest) = facts.largest_holder_pct {
        if largest >= 50.0 {
            reasons.push(format!("largest_holder_extreme:{largest:.1}%"));
            level = bump(level, RiskLevel::Red);
        } else if largest >= 30.0 {
            reasons.push(format!("largest_holder_high:{largest:.1}%"));
            level = bump(level, RiskLevel::Amber);
        }
    }

    match facts.lp_status {
        LpStatus::Unverified => {
            reasons.push("lp_liquidity_unverified".into());
            level = bump(level, RiskLevel::Amber);
        }
        LpStatus::BluechipSkip => {
            reasons.push("lp_check_skipped_bluechip".into());
        }
    }

    if reasons.is_empty() {
        reasons.push("no_obvious_authority_or_extension_red_flags".into());
    }

    // Cap reasons for context-window budget.
    if reasons.len() > 6 {
        reasons.truncate(6);
        reasons.push("reasons_truncated".into());
    }

    let label = i18n::risk_label(locale, level.as_str());
    let conc = match (facts.top10_holder_pct, facts.largest_holder_pct) {
        (Some(t), Some(l)) => format!(" top10={t:.0}% largest={l:.0}%"),
        (Some(t), None) => format!(" top10={t:.0}%"),
        _ => String::new(),
    };
    let summary = format!(
        "[{label}] {}{} · {}",
        truncate(&facts.mint, 8),
        conc,
        reasons
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join(",")
    );

    RiskReport {
        level,
        reasons,
        locale: format!("{locale:?}").to_ascii_lowercase(),
        summary,
        custody_tier: "T0",
        top10_holder_pct: facts.top10_holder_pct,
        largest_holder_pct: facts.largest_holder_pct,
        lp_status: facts.lp_status,
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

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn concentration_red() {
        let f = MintFacts {
            mint: "TokenMint11111111111111111111111111111111111".into(),
            top10_holder_pct: Some(95.0),
            largest_holder_pct: Some(60.0),
            lp_status: LpStatus::Unverified,
            ..Default::default()
        };
        let r = assess(&f, "en");
        assert_eq!(r.level, RiskLevel::Red);
    }

    #[test]
    fn bluechip_skips_lp_amber() {
        let f = MintFacts {
            mint: "So11111111111111111111111111111111111111112".into(),
            lp_status: LpStatus::Unverified,
            top10_holder_pct: Some(10.0),
            largest_holder_pct: Some(5.0),
            ..Default::default()
        };
        let r = assess(&f, "en");
        assert_eq!(r.lp_status, LpStatus::BluechipSkip);
        assert!(!r.reasons.iter().any(|x| x == "lp_liquidity_unverified"));
    }
}
