//! Pure risk-assessment core. No wit-bindgen or wasm dependency, so it compiles
//! and tests on the host with a plain `cargo test`; the wasm component reuses the
//! exact same logic through `lib.rs`.
//!
//! The scoring turns the *facts* decoded by `zeroclaw-solana-core` (mint
//! authorities, Token-2022 extensions, holder concentration) into a
//! Red / Amber / Green verdict. Every rule is a pure function of its inputs, so
//! the verdict is deterministic and fully unit-tested against synthetic mints.
//!
//! ## The key nuance
//!
//! A Token-2022 `TransferHook` extension can be *present but disabled*: the
//! extension exists on the mint yet its `program_id` is null (the PYUSD case).
//! A present-but-disabled hook runs no code and blocks no sells, so it MUST NOT
//! raise the risk level. Only an *active* hook (non-null program) is critical.
//! Many naive analyzers flag the mere presence of the extension; this one reads
//! the bytes and reports the disabled hook as a neutral note.

use zeroclaw_solana_core::{ExtensionRisks, Mint};

/// A transfer fee at or above this many basis points (10%) is treated as
/// punitive (critical) rather than a merely notable fee.
const PUNITIVE_FEE_BPS: u16 = 1000;

/// A single top holder above this share of supply is flagged (may legitimately
/// be a liquidity pool or program vault, hence the hedged wording).
const TOP1_CONCENTRATION_WARN: f64 = 0.50;

/// Overall risk classification for a token mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// No authority or extension can seize, freeze, block, or dilute holders.
    Green,
    /// Notable but non-fatal powers exist (active authorities, moderate fees,
    /// concentration). The token is usable but not trustless.
    Amber,
    /// A power exists that can seize, freeze, block sells, or punitively tax;
    /// treat as unsafe to hold or trade.
    Red,
}

impl RiskLevel {
    /// The traffic-light emoji for this level.
    pub fn emoji(self) -> &'static str {
        match self {
            RiskLevel::Green => "\u{1F7E2}", // 🟢
            RiskLevel::Amber => "\u{1F7E1}", // 🟡
            RiskLevel::Red => "\u{1F534}",   // 🔴
        }
    }

    /// The uppercase label for this level.
    pub fn label(self) -> &'static str {
        match self {
            RiskLevel::Green => "GREEN",
            RiskLevel::Amber => "AMBER",
            RiskLevel::Red => "RED",
        }
    }
}

/// The result of assessing a mint: an overall level plus the ordered,
/// human-readable reasons behind it (criticals first, then warnings, then any
/// neutral notes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

impl Verdict {
    /// Render a compact summary: the traffic-light emoji and level on the first
    /// line, then one bullet per reason. Designed to fit in ~150 tokens so it
    /// can be dropped straight into a chat reply or a model's context.
    pub fn summary(&self) -> String {
        let mut out = format!("{} {}", self.level.emoji(), self.level.label());
        for reason in &self.reasons {
            out.push_str("\n\u{2022} "); // "\n• "
            out.push_str(reason);
        }
        out
    }
}

/// Assess a decoded mint plus its Token-2022 extension facts and (optionally)
/// its top-holder concentration into a [`Verdict`].
///
/// `top1_pct` / `top5_pct` are the combined supply fraction (`0.0..=1.0`) held
/// by the largest 1 and 5 token accounts, or `None` when holder data could not
/// be fetched. An unavailable data source is reported as a neutral note, never
/// as a clean bill of health.
pub fn assess(
    mint: &Mint,
    ext: &ExtensionRisks,
    top1_pct: Option<f64>,
    top5_pct: Option<f64>,
) -> Verdict {
    let mut criticals: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // ── CRITICAL → Red ──────────────────────────────────────────────────────
    if ext.permanent_delegate.is_some() {
        criticals.push("Permanent delegate can seize or burn any holder's tokens".to_string());
    }
    if ext.transfer_hook_program.is_some() {
        criticals.push(
            "Active transfer-hook runs arbitrary code on every transfer and can block sells"
                .to_string(),
        );
    }
    if ext.non_transferable {
        criticals.push("Non-transferable (soulbound), cannot be sold".to_string());
    }
    if ext.default_frozen {
        criticals.push("New accounts are frozen by default".to_string());
    }
    if ext.paused {
        criticals.push("Transfers are currently paused".to_string());
    }
    if let Some(bps) = ext.transfer_fee_bps {
        if bps >= PUNITIVE_FEE_BPS {
            criticals.push(format!("Punitive transfer fee: {}", fmt_bps(bps)));
        }
    }

    // ── WARNING → at least Amber ────────────────────────────────────────────
    if mint.mint_authority.is_some() {
        warnings.push("Mint authority active, supply can be inflated".to_string());
    }
    if mint.freeze_authority.is_some() {
        warnings.push("Freeze authority active, accounts can be frozen".to_string());
    }
    if let Some(bps) = ext.transfer_fee_bps {
        if bps > 0 && bps < PUNITIVE_FEE_BPS {
            warnings.push(format!("Transfer fee {}", fmt_bps(bps)));
        }
    }
    if ext.transfer_fee_authority.is_some() {
        warnings.push("Transfer fee can still be raised".to_string());
    }
    if ext.transfer_fee_changed {
        warnings.push("Transfer fee has been changed before".to_string());
    }
    if ext.mint_close_authority.is_some() {
        warnings.push("Mint can be closed by an authority".to_string());
    }
    if let Some(p1) = top1_pct {
        if p1 > TOP1_CONCENTRATION_WARN {
            warnings.push(match top5_pct {
                Some(p5) => format!(
                    "Top holder holds {} of supply; top 5 hold {} (may include LP/pools)",
                    fmt_frac(p1),
                    fmt_frac(p5)
                ),
                None => format!(
                    "Top holder holds {} of supply (may include LP/pools)",
                    fmt_frac(p1)
                ),
            });
        }
    }
    if ext.amount_rescaled {
        warnings.push("Displayed balance rescaled by an authority".to_string());
    }
    if ext.confidential {
        warnings.push("Confidential transfers, opaque balances".to_string());
    }

    // ── NEUTRAL notes (never raise the level) ───────────────────────────────
    if ext.transfer_hook_present_but_disabled {
        notes.push("Transfer-hook extension present but disabled (no program set)".to_string());
    }
    if top1_pct.is_none() {
        notes.push("Holder concentration data unavailable".to_string());
    }

    let level = if !criticals.is_empty() {
        RiskLevel::Red
    } else if !warnings.is_empty() {
        RiskLevel::Amber
    } else {
        RiskLevel::Green
    };

    let mut reasons = Vec::with_capacity(criticals.len() + warnings.len() + notes.len() + 1);
    reasons.extend(criticals);
    reasons.extend(warnings);
    if level == RiskLevel::Green {
        reasons.push(positive_summary(mint));
    }
    reasons.extend(notes);

    Verdict { level, reasons }
}

/// The positive one-liner shown for a clean (Green) mint.
fn positive_summary(mint: &Mint) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if mint.mint_authority.is_none() {
        parts.push("mint authority renounced");
    }
    if mint.freeze_authority.is_none() {
        parts.push("no freeze authority");
    }
    parts.push("no risky extensions");
    capitalize(&parts.join("; "))
}

/// Format basis points as a trimmed percentage, e.g. `269 -> "2.69%"`,
/// `1000 -> "10%"`, `50 -> "0.5%"`.
fn fmt_bps(bps: u16) -> String {
    fmt_pct(f64::from(bps) / 100.0)
}

/// Format a supply fraction (`0.0..=1.0`) as a trimmed percentage, e.g.
/// `0.6 -> "60%"`, `0.523 -> "52.3%"`.
fn fmt_frac(frac: f64) -> String {
    fmt_pct(frac * 100.0)
}

/// Format a percentage value with up to two decimals, trimming trailing zeros
/// and a trailing decimal point.
fn fmt_pct(pct: f64) -> String {
    let s = format!("{pct:.2}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    format!("{trimmed}%")
}

/// Uppercase the first character of `s`.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_solana_core::Pubkey;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    /// A classic SPL mint with the given authorities and no extensions.
    fn mint(mint_authority: Option<Pubkey>, freeze_authority: Option<Pubkey>) -> Mint {
        Mint {
            mint_authority,
            supply: 1_000_000_000,
            decimals: 6,
            is_initialized: true,
            freeze_authority,
            is_token_2022: false,
            has_extensions: false,
        }
    }

    #[test]
    fn green_when_renounced_usdc_like_but_no_authorities() {
        // Renounced mint, no freeze, no extensions, low concentration.
        let v = assess(
            &mint(None, None),
            &ExtensionRisks::default(),
            Some(0.12),
            Some(0.40),
        );
        assert_eq!(v.level, RiskLevel::Green);
        assert_eq!(v.reasons.len(), 1);
        assert!(v.reasons[0].contains("renounced"));
        assert!(v.reasons[0].contains("no freeze authority"));
        assert!(v.summary().starts_with("\u{1F7E2} GREEN"));
    }

    #[test]
    fn amber_when_mint_authority_active() {
        let v = assess(
            &mint(Some(pk(1)), None),
            &ExtensionRisks::default(),
            Some(0.1),
            Some(0.3),
        );
        assert_eq!(v.level, RiskLevel::Amber);
        assert!(v
            .reasons
            .iter()
            .any(|r| r.contains("Mint authority active")));
        // Green positive line must NOT be present on an Amber verdict.
        assert!(!v.reasons.iter().any(|r| r.contains("renounced")));
    }

    #[test]
    fn amber_when_freeze_authority_active() {
        let v = assess(
            &mint(None, Some(pk(2))),
            &ExtensionRisks::default(),
            None,
            None,
        );
        assert_eq!(v.level, RiskLevel::Amber);
        assert!(v
            .reasons
            .iter()
            .any(|r| r.contains("Freeze authority active")));
    }

    #[test]
    fn red_when_permanent_delegate_present() {
        let ext = ExtensionRisks {
            permanent_delegate: Some(pk(9)),
            ..Default::default()
        };
        let v = assess(&mint(None, None), &ext, Some(0.1), Some(0.2));
        assert_eq!(v.level, RiskLevel::Red);
        assert!(v.reasons[0].contains("seize or burn"));
        assert!(v.summary().starts_with("\u{1F534} RED"));
    }

    #[test]
    fn disabled_hook_is_not_red_and_not_a_warning() {
        // THE differentiator: a present-but-disabled transfer hook (null program)
        // must not raise the level. With everything else clean, the mint is Green
        // and the hook is reported only as a neutral note.
        let ext = ExtensionRisks {
            transfer_hook_present_but_disabled: true,
            ..Default::default()
        };
        let v = assess(&mint(None, None), &ext, Some(0.05), Some(0.2));
        assert_eq!(v.level, RiskLevel::Green);
        assert!(v.reasons.iter().any(|r| r.contains("disabled")));
        // No reason should claim an active hook.
        assert!(!v.reasons.iter().any(|r| r.contains("Active transfer-hook")));
    }

    #[test]
    fn active_hook_is_red() {
        let ext = ExtensionRisks {
            transfer_hook_program: Some(pk(7)),
            ..Default::default()
        };
        let v = assess(&mint(None, None), &ext, None, None);
        assert_eq!(v.level, RiskLevel::Red);
        assert!(v.reasons.iter().any(|r| r.contains("Active transfer-hook")));
    }

    #[test]
    fn punitive_fee_is_red_moderate_fee_is_amber() {
        let punitive = ExtensionRisks {
            transfer_fee_bps: Some(1500), // 15%
            ..Default::default()
        };
        let v = assess(&mint(None, None), &punitive, Some(0.1), Some(0.2));
        assert_eq!(v.level, RiskLevel::Red);
        assert!(v
            .reasons
            .iter()
            .any(|r| r.contains("Punitive transfer fee: 15%")));

        let moderate = ExtensionRisks {
            transfer_fee_bps: Some(269), // 2.69%
            ..Default::default()
        };
        let v = assess(&mint(None, None), &moderate, Some(0.1), Some(0.2));
        assert_eq!(v.level, RiskLevel::Amber);
        assert!(v.reasons.iter().any(|r| r.contains("Transfer fee 2.69%")));
    }

    #[test]
    fn top_holder_concentration_is_amber_and_folds_top5() {
        let v = assess(
            &mint(None, None),
            &ExtensionRisks::default(),
            Some(0.62),
            Some(0.88),
        );
        assert_eq!(v.level, RiskLevel::Amber);
        let reason = v
            .reasons
            .iter()
            .find(|r| r.contains("Top holder"))
            .expect("concentration reason");
        assert!(reason.contains("62%"));
        assert!(reason.contains("top 5 hold 88%"));
    }

    #[test]
    fn missing_holder_data_is_a_neutral_note_only() {
        // Renounced + no data → still Green, with an explicit "unavailable" note.
        let v = assess(&mint(None, None), &ExtensionRisks::default(), None, None);
        assert_eq!(v.level, RiskLevel::Green);
        assert!(v.reasons.iter().any(|r| r.contains("unavailable")));
    }

    #[test]
    fn bern_like_changed_and_mutable_fee_is_amber() {
        let ext = ExtensionRisks {
            transfer_fee_bps: Some(269),
            transfer_fee_authority: Some(pk(5)),
            transfer_fee_changed: true,
            ..Default::default()
        };
        let v = assess(&mint(Some(pk(1)), None), &ext, Some(0.3), Some(0.6));
        assert_eq!(v.level, RiskLevel::Amber);
        assert!(v.reasons.iter().any(|r| r.contains("can still be raised")));
        assert!(v
            .reasons
            .iter()
            .any(|r| r.contains("has been changed before")));
    }

    #[test]
    fn fmt_pct_trims_cleanly() {
        assert_eq!(fmt_bps(1000), "10%");
        assert_eq!(fmt_bps(269), "2.69%");
        assert_eq!(fmt_bps(50), "0.5%");
        assert_eq!(fmt_frac(0.6), "60%");
        assert_eq!(fmt_frac(0.523), "52.3%");
    }
}
