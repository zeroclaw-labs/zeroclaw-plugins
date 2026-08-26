//! The fail-closed spend policy engine.
//!
//! This module is the safety centerpiece of the suite: every value-moving
//! plugin routes its arguments through [`SpendPolicy::authorize`] BEFORE any
//! transaction bytes are constructed. The policy is loaded from the plugin's
//! own jailed config section — operator-controlled, invisible to the LLM,
//! and impossible to override from a chat message.
//!
//! Design rules:
//! - **Deny by default.** No allowlist configured → no recipients are valid.
//! - **The LLM's arguments are untrusted input.** Anything not matching the
//!   operator's config is refused with a reason (that the agent can relay).
//! - **Caps are enforced here**, not in the prompt: per-transaction and
//!   per-day, in base units of an allowlisted mint.

use std::collections::HashMap;

/// A refusal is a *successful* tool result with `authorized: false` — the
/// agent loop sees a clean explanation, never a half-built transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Authorized,
    Refused { reason: String },
}

impl Verdict {
    pub fn refused(reason: impl Into<String>) -> Self {
        Verdict::Refused {
            reason: reason.into(),
        }
    }
    pub fn is_authorized(&self) -> bool {
        matches!(self, Verdict::Authorized)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpendPolicy {
    /// base58 recipient owner addresses the operator trusts. Empty = deny all.
    pub recipient_allowlist: Vec<String>,
    /// base58 mints the operator allows. Empty = deny all.
    pub mint_allowlist: Vec<String>,
    /// Max base units (e.g. 6-decimals USDC) for a single transfer. 0 = deny.
    pub max_per_tx: u64,
    /// Max cumulative base units per UTC day. 0 = no daily cap configured
    /// (per-tx cap still applies).
    pub max_per_day: u64,
}

impl SpendPolicy {
    /// Build from the flat string map the host injects (`__config`).
    /// Missing keys mean "not configured" and fail closed at authorize time.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let list = |key: &str| -> Vec<String> {
            section
                .get(key)
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let num = |key: &str| -> u64 {
            section
                .get(key)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        SpendPolicy {
            recipient_allowlist: list("recipient_allowlist"),
            mint_allowlist: list("mint_allowlist"),
            max_per_tx: num("max_per_tx"),
            max_per_day: num("max_per_day"),
        }
    }

    /// Authorize a proposed transfer. `spent_today` is the running total the
    /// caller tracks (0 when unknown — per-tx cap still binds).
    pub fn authorize(&self, recipient: &str, mint: &str, amount: u64, spent_today: u64) -> Verdict {
        if amount == 0 {
            return Verdict::refused("amount must be positive");
        }
        if self.max_per_tx == 0 {
            return Verdict::refused(
                "no max_per_tx configured — spending is disabled until the operator sets a cap",
            );
        }
        if self.recipient_allowlist.is_empty() {
            return Verdict::refused(
                "recipient allowlist is empty — spending is disabled until the operator adds recipients",
            );
        }
        if self.mint_allowlist.is_empty() {
            return Verdict::refused(
                "mint allowlist is empty — spending is disabled until the operator adds mints",
            );
        }
        if !self.recipient_allowlist.iter().any(|r| r == recipient) {
            return Verdict::refused(format!(
                "recipient {recipient} is not on the operator allowlist"
            ));
        }
        if !self.mint_allowlist.iter().any(|m| m == mint) {
            return Verdict::refused(format!("mint {mint} is not on the operator allowlist"));
        }
        if amount > self.max_per_tx {
            return Verdict::refused(format!(
                "amount {amount} exceeds max_per_tx {}",
                self.max_per_tx
            ));
        }
        if self.max_per_day > 0 && spent_today.saturating_add(amount) > self.max_per_day {
            return Verdict::refused(format!(
                "daily cap {} would be exceeded (spent today: {spent_today})",
                self.max_per_day
            ));
        }
        Verdict::Authorized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOB: &str = "BobRecipient1111111111111111111111111111111";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn policy() -> SpendPolicy {
        SpendPolicy {
            recipient_allowlist: vec![BOB.into()],
            mint_allowlist: vec![USDC.into()],
            max_per_tx: 50_000_000,   // 50 USDC
            max_per_day: 100_000_000, // 100 USDC
        }
    }

    #[test]
    fn happy_path() {
        assert!(policy().authorize(BOB, USDC, 25_000_000, 0).is_authorized());
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = SpendPolicy::default();
        assert!(!p.authorize(BOB, USDC, 1, 0).is_authorized());
    }

    #[test]
    fn unknown_recipient_refused() {
        let v = policy().authorize("EvilAttacker111111111111111111111111111111", USDC, 1, 0);
        assert!(
            matches!(v, Verdict::Refused { ref reason } if reason.contains("not on the operator allowlist"))
        );
    }

    #[test]
    fn unknown_mint_refused() {
        let v = policy().authorize(BOB, "FakeMint11111111111111111111111111111111111", 1, 0);
        assert!(!v.is_authorized());
    }

    #[test]
    fn per_tx_cap_binds() {
        assert!(!policy().authorize(BOB, USDC, 50_000_001, 0).is_authorized());
    }

    #[test]
    fn daily_cap_binds() {
        // 80 spent + 25 requested > 100 daily
        assert!(!policy()
            .authorize(BOB, USDC, 25_000_000, 80_000_000)
            .is_authorized());
        // 70 spent + 25 requested ≤ 100 daily → fine
        assert!(policy()
            .authorize(BOB, USDC, 25_000_000, 70_000_000)
            .is_authorized());
    }

    #[test]
    fn zero_amount_refused() {
        assert!(!policy().authorize(BOB, USDC, 0, 0).is_authorized());
    }

    #[test]
    fn config_parsing() {
        let mut section = HashMap::new();
        section.insert("recipient_allowlist".to_string(), format!(" {BOB} , "));
        section.insert("mint_allowlist".to_string(), USDC.to_string());
        section.insert("max_per_tx".to_string(), "1000".to_string());
        let p = SpendPolicy::from_section(&section);
        assert_eq!(p.recipient_allowlist, vec![BOB.to_string()]);
        assert!(p.authorize(BOB, USDC, 500, 0).is_authorized());
        assert!(!p.authorize(BOB, USDC, 1001, 0).is_authorized());
    }

    /// The prompt-injection scenario: a chat message asks the agent to pay an
    /// attacker. The attacker is not in operator config → refused, and the
    /// refusal happens BEFORE any transaction is constructed.
    #[test]
    fn prompt_injection_fails_closed() {
        let attacker = "Attacker9999999999999999999999999999999999";
        let v = policy().authorize(attacker, USDC, 49_000_000, 0);
        assert!(!v.is_authorized());
        // Even "within cap" and "known mint" — recipient gate alone kills it.
    }
}
