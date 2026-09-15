//! Operator policy + hardcoded blocked-instruction baseline.
//!
//! All financial policy lives here (see Clarification 1A): spending caps,
//! mint allowlist, recipient allowlist, expected delegates. The signer
//! (`solana-keychain-sign`) enforces NONE of this — it only checks envelope
//! guards (size, ix-count, fee-payer match).
//!
//! # Hardcoded baseline (Clarification 1B)
//!
//! The `approve` family is blocked unconditionally in v0. Operators may ADD
//! entries via `blocked_instructions_extra`; they cannot REMOVE the baseline.
//! An `approve(attacker, u64::MAX)` hands away transfer authority for the
//! entire token account — every per-call cap this plugin enforces becomes
//! meaningless. See `builder` module docs for the full rationale.

use std::collections::HashMap;

// ─── well-known program IDs ─────────────────────────────────────────────────

pub const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const SPL_TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

// ─── hardcoded blocked baseline ────────────────────────────────────────────

/// `(program_id, instruction_name)` pairs that cannot be removed via config.
/// See module docs and Clarification 1B for rationale.
pub const HARDCODED_BLOCKED: &[(&str, &str)] = &[
    (SPL_TOKEN_PROGRAM, "approve"),
    (SPL_TOKEN_PROGRAM, "approve_checked"),
    (SPL_TOKEN_PROGRAM, "set_authority"),
    (SPL_TOKEN_PROGRAM, "close_account"),
    (SPL_TOKEN_2022_PROGRAM, "approve"),
    (SPL_TOKEN_2022_PROGRAM, "approve_checked"),
    (SPL_TOKEN_2022_PROGRAM, "set_authority"),
    (SPL_TOKEN_2022_PROGRAM, "close_account"),
];

// ─── resolved policy ────────────────────────────────────────────────────────

/// Financial + blocked-instruction policy resolved from the flat config
/// section. Built once per `execute` call via [`PolicyConfig::from_section`].
#[derive(Debug, Clone, Default)]
pub struct PolicyConfig {
    pub rpc_url: String,
    pub signer_pubkey: String,
    /// mint base58 → cap in BASE units (USDC 6dp → 100000000 = 100 USDC).
    pub per_call_outflow_cap: HashMap<String, u64>,
    pub mint_allowlist: Vec<String>,
    /// Empty = allow any recipient (still subject to cap + mint allowlist).
    pub recipient_allowlist: Vec<String>,
    /// Delegates expected on the signer's token accounts (e.g. Tributary PDA).
    pub expected_delegates_allowlist: Vec<String>,
    /// Operator-added `(program_id, instruction_name)` pairs beyond baseline.
    pub blocked_instructions_extra: Vec<(String, String)>,
}

impl PolicyConfig {
    /// Parse the flat `__config` section the host injects. Absent or empty
    /// keys fall back to safe defaults (empty lists, zero caps).
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        Self {
            rpc_url: section.get("rpc_url").cloned().unwrap_or_default(),
            signer_pubkey: section.get("signer_pubkey").cloned().unwrap_or_default(),
            per_call_outflow_cap: parse_outflow_caps(section.get("per_call_outflow_cap")),
            mint_allowlist: parse_list(section.get("mint_allowlist")),
            recipient_allowlist: parse_list(section.get("recipient_allowlist")),
            expected_delegates_allowlist: parse_list(section.get("expected_delegates_allowlist")),
            blocked_instructions_extra: parse_blocked_extra(
                section.get("blocked_instructions_extra"),
            ),
        }
    }

    /// True if the instruction is in the hardcoded baseline OR the operator's
    /// extras. The baseline cannot be removed — see [`HARDCODED_BLOCKED`].
    pub fn is_blocked(&self, program_id: &str, instruction_name: &str) -> bool {
        if HARDCODED_BLOCKED
            .iter()
            .any(|(p, i)| *p == program_id && *i == instruction_name)
        {
            return true;
        }
        self.blocked_instructions_extra
            .iter()
            .any(|(p, i)| p == program_id && i == instruction_name)
    }

    /// True if a mint is allowed to appear in any token-balance diff.
    pub fn is_mint_allowed(&self, mint: &str) -> bool {
        self.mint_allowlist.iter().any(|m| m == mint)
    }

    /// True if `amount` base units is within the per-call cap for `mint`.
    /// Mints without an explicit cap entry are treated as cap = 0 (deny).
    pub fn is_within_cap(&self, mint: &str, amount: u64) -> bool {
        self.per_call_outflow_cap
            .get(mint)
            .map(|&cap| amount <= cap)
            .unwrap_or(false)
    }

    /// True if `recipient` may receive tokens. Empty allowlist = allow any.
    pub fn is_recipient_allowed(&self, recipient: &str) -> bool {
        self.recipient_allowlist.is_empty()
            || self.recipient_allowlist.iter().any(|r| r == recipient)
    }

    /// True if `delegate` is an expected delegate on the signer's accounts.
    pub fn is_delegate_expected(&self, delegate: &str) -> bool {
        self.expected_delegates_allowlist
            .iter()
            .any(|d| d == delegate)
    }
}

// ─── parsers ────────────────────────────────────────────────────────────────

/// `None` or empty → empty vec. Otherwise comma-separated, trimmed, filtered.
fn parse_list(raw: Option<&String>) -> Vec<String> {
    let s = match raw {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(),
    };
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// JSON `{"mint":"base_units"}` → HashMap. Values are strings in config to
/// avoid JSON number precision loss on large u64; parsed to u64 here.
fn parse_outflow_caps(raw: Option<&String>) -> HashMap<String, u64> {
    let s = match raw {
        Some(s) if !s.is_empty() => s,
        _ => return HashMap::new(),
    };
    // ponytail: parse as HashMap<String,String> then convert — avoids
    // serde_json's f64 intermediary for large u64 values.
    let raw_map: HashMap<String, String> = match serde_json::from_str(s) {
        Ok(m) => m,
        Err(_) => return HashMap::new(),
    };
    raw_map
        .into_iter()
        .filter_map(|(mint, amt_str)| {
            let amt: u64 = amt_str.trim().parse().ok()?;
            Some((mint, amt))
        })
        .collect()
}

/// `"program:instruction,program2:instruction2"` → Vec<(String, String)>.
/// Malformed pairs are silently dropped (ponytail: config errors are noisy
/// at the host layer; the plugin treats unparseable entries as absent).
fn parse_blocked_extra(raw: Option<&String>) -> Vec<(String, String)> {
    let s = match raw {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(),
    };
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, ':');
            let prog = parts.next()?.trim();
            let ix = parts.next()?.trim();
            if prog.is_empty() || ix.is_empty() {
                return None;
            }
            Some((prog.to_string(), ix.to_string()))
        })
        .collect()
}

// ─── self-check ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn baseline_blocked_with_empty_config() {
        let cfg = PolicyConfig::from_section(&HashMap::new());
        for &(p, i) in HARDCODED_BLOCKED {
            assert!(
                cfg.is_blocked(p, i),
                "baseline {p}:{i} must block with empty config"
            );
        }
    }

    #[test]
    fn non_blocked_instructions_pass() {
        let cfg = PolicyConfig::from_section(&HashMap::new());
        assert!(!cfg.is_blocked(SPL_TOKEN_PROGRAM, "transfer"));
        assert!(!cfg.is_blocked(SPL_TOKEN_2022_PROGRAM, "transfer"));
    }

    #[test]
    fn extra_blocked_adds_beyond_baseline() {
        let cfg = PolicyConfig::from_section(&section(&[(
            "blocked_instructions_extra",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA:transfer",
        )]));
        // baseline still present
        assert!(cfg.is_blocked(SPL_TOKEN_PROGRAM, "approve"));
        // extra now blocks transfer too
        assert!(cfg.is_blocked(SPL_TOKEN_PROGRAM, "transfer"));
    }

    #[test]
    fn outflow_cap_parses_string_amounts() {
        let cfg = PolicyConfig::from_section(&section(&[(
            "per_call_outflow_cap",
            r#"{"EPjFWcc5TestMint":"100000000"}"#,
        )]));
        assert_eq!(
            cfg.per_call_outflow_cap.get("EPjFWcc5TestMint"),
            Some(&100_000_000u64)
        );
        assert!(cfg.is_within_cap("EPjFWcc5TestMint", 99_999_999));
        assert!(!cfg.is_within_cap("EPjFWcc5TestMint", 100_000_001));
    }

    #[test]
    fn empty_recipient_allowlist_allows_any() {
        let cfg = PolicyConfig::from_section(&HashMap::new());
        assert!(cfg.is_recipient_allowed("AnyAddress"));
    }

    #[test]
    fn non_empty_recipient_allowlist_restricts() {
        let cfg =
            PolicyConfig::from_section(&section(&[("recipient_allowlist", "Allowed1,Allowed2")]));
        assert!(cfg.is_recipient_allowed("Allowed1"));
        assert!(!cfg.is_recipient_allowed("Attacker"));
    }

    #[test]
    fn malformed_blocked_extra_silently_dropped() {
        let cfg = PolicyConfig::from_section(&section(&[(
            "blocked_instructions_extra",
            "goodprog:goodix,:noprogram,noinst:",
        )]));
        assert_eq!(cfg.blocked_instructions_extra.len(), 1);
        assert_eq!(
            cfg.blocked_instructions_extra[0],
            ("goodprog".to_string(), "goodix".to_string())
        );
    }
}
