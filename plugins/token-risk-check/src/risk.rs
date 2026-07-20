//! Risk scoring: mint facts + concentration → red/amber/green with reasons.
//!
//! Philosophy: this tool reports *capabilities*, not intent. A freeze
//! authority on a regulated stablecoin is expected; the same authority on an
//! anonymous memecoin is a rug lever. We phrase each finding so the model and
//! the human can apply that context, and we never say "safe" — the ceiling is
//! "no red flags in the checks performed".

use crate::holders::Concentration;
use crate::mint::{Extension, MintFacts};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Red,
    Amber,
    Green,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub level: Level,
    pub critical: Vec<String>,
    pub warning: Vec<String>,
    pub ok: Vec<String>,
}

/// Concentration thresholds, in percent of supply.
const TOP1_RED: f64 = 50.0;
const TOP1_AMBER: f64 = 20.0;
const TOP5_AMBER: f64 = 60.0;

/// Transfer fee thresholds, in basis points.
const FEE_RED_BPS: u16 = 500; // >5% per transfer is honeypot economics
const FEE_NOTE_BPS: u16 = 0;

pub fn assess(facts: &MintFacts, conc: Option<&Concentration>) -> Verdict {
    let mut critical = Vec::new();
    let mut warning = Vec::new();
    let mut ok = Vec::new();

    // ── authorities ──
    match &facts.mint_authority {
        Some(auth) => warning.push(format!(
            "mint authority active ({}) — issuer can mint more supply; normal for centralized stablecoins, a rug lever for community tokens",
            short(auth)
        )),
        None => ok.push("mint authority revoked (fixed supply)".to_string()),
    }
    match &facts.freeze_authority {
        Some(auth) => warning.push(format!(
            "freeze authority active ({}) — issuer can freeze any holder's account",
            short(auth)
        )),
        None => ok.push("freeze authority revoked".to_string()),
    }

    // ── extensions ──
    let mut hook_dormant = false;
    for ext in &facts.extensions {
        match ext {
            Extension::PermanentDelegate { delegate } => critical.push(format!(
                "permanent delegate ({}) can transfer or burn ANY holder's tokens",
                short(delegate)
            )),
            Extension::TransferHook { program: Some(p) } => critical.push(format!(
                "transfer hook program {} runs on every transfer and can block or tax sells",
                short(p)
            )),
            Extension::TransferHook { program: None } => hook_dormant = true,
            Extension::DefaultStateFrozen => critical.push(
                "new token accounts start FROZEN — buyers cannot move tokens until the issuer thaws them".to_string(),
            ),
            Extension::TransferFee { max_bps } if *max_bps > FEE_RED_BPS => critical.push(
                format!("transfer fee up to {}% taken on every transfer", bps_pct(*max_bps)),
            ),
            Extension::TransferFee { max_bps } if *max_bps > FEE_NOTE_BPS => warning.push(
                format!("transfer fee up to {}% on transfers", bps_pct(*max_bps)),
            ),
            Extension::TransferFee { .. } => {}
            Extension::NonTransferable => critical.push(
                "non-transferable (soulbound) — tokens cannot be sold or moved".to_string(),
            ),
            Extension::Pausable => critical.push(
                "transfers can be PAUSED by an authority at any time".to_string(),
            ),
            Extension::MintCloseAuthority => warning.push(
                "mint close authority set — the mint account can be closed and later re-created".to_string(),
            ),
            Extension::InterestBearing => warning.push(
                "interest-bearing config — displayed amounts grow by a rate the authority controls".to_string(),
            ),
            Extension::ScaledUiAmount => warning.push(
                "scaled UI amounts — displayed balances can be rescaled by an authority".to_string(),
            ),
            Extension::ConfidentialTransfers => warning.push(
                "confidential transfers enabled — balances/flows partially opaque".to_string(),
            ),
            Extension::TokenMetadata { mutable: true, .. } => warning.push(
                "token metadata is mutable (name/symbol can be changed)".to_string(),
            ),
            Extension::TokenMetadata { .. } => {}
            Extension::MetadataPointer => {}
            Extension::Unknown { label } => warning.push(format!(
                "unrecognized token-2022 extension ({label}) — cannot rule out new control surface",
            )),
        }
    }
    if hook_dormant {
        warning.push(
            "transfer hook configured but no program set (dormant, can be activated)".to_string(),
        );
    }
    if facts.extensions.is_empty() {
        ok.push("no token-2022 extension traps".to_string());
    }

    // ── concentration ──
    match conc {
        Some(c) => {
            if c.top1_pct >= TOP1_RED {
                critical.push(format!("top account holds {:.1}% of supply", c.top1_pct));
            } else if c.top1_pct >= TOP1_AMBER || c.top5_pct >= TOP5_AMBER {
                warning.push(format!(
                    "concentrated supply: top account {:.1}%, top5 {:.1}%",
                    c.top1_pct, c.top5_pct
                ));
            } else {
                ok.push(format!(
                    "supply reasonably distributed (top account {:.1}%)",
                    c.top1_pct
                ));
            }
        }
        None => warning.push(
            "holder concentration unavailable (RPC method disabled or zero supply)".to_string(),
        ),
    }

    let level = if !critical.is_empty() {
        Level::Red
    } else if !warning.is_empty() {
        Level::Amber
    } else {
        Level::Green
    };

    Verdict {
        level,
        critical,
        warning,
        ok,
    }
}

fn bps_pct(bps: u16) -> String {
    let pct = f64::from(bps) / 100.0;
    if (pct - pct.trunc()).abs() < f64::EPSILON {
        format!("{:.0}", pct)
    } else {
        format!("{:.2}", pct)
    }
}

/// `7xKXtg2C…9fLmZq` style shortening for addresses in prose.
pub fn short(addr: &str) -> String {
    if addr.len() <= 12 {
        addr.to_string()
    } else {
        format!("{}…{}", &addr[..4], &addr[addr.len() - 4..])
    }
}
