//! The deterministic policy engine — the heart of Safe Hands.
//!
//! Pure functions only: no I/O, no wasm, no clocks, no floats. The engine takes
//! a [`Policy`] (parsed from the operator's host-injected config) plus the
//! decoded facts of one transaction and returns a [`Verdict`] with machine
//! reason codes. Every rule is total: any input the engine cannot fully
//! explain degrades to a stricter outcome, never to ALLOW.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The four-state verdict. ALLOW permits autonomous execution; REVIEW requires
/// a human; DENY forbids; UNKNOWN means insufficient evidence (fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Allow,
    Review,
    Deny,
    Unknown,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Allow => "ALLOW",
            Verdict::Review => "REVIEW",
            Verdict::Deny => "DENY",
            Verdict::Unknown => "UNKNOWN",
        }
    }
}

/// A policy-driven outcome for a class of evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Deny,
    Review,
}

/// Per-asset spend policy. Amounts are raw smallest-unit decimal strings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetPolicy {
    pub decimals: u8,
    pub max_per_tx_raw: String,
}

impl AssetPolicy {
    fn max_raw(&self) -> Result<u128, String> {
        self.max_per_tx_raw
            .parse::<u128>()
            .map_err(|_| format!("invalid max_per_tx_raw: {:?}", self.max_per_tx_raw))
    }
}

/// Token-2022 extension rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token2022Policy {
    pub permanent_delegate: Outcome,
    pub transfer_hook: Outcome,
    pub transfer_fee: Outcome,
    pub default_frozen: Outcome,
}

/// Fee ceilings (lamports, raw).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeePolicy {
    pub max_priority_fee_lamports: u64,
    pub max_transaction_fee_lamports: u64,
    pub max_account_creation_lamports: u64,
}

/// Velocity rule (count of ALLOW verdicts in the trailing window).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VelocityPolicy {
    pub max_allow_per_hour: u32,
    /// Caller-supplied count for the current window (from operator config or
    /// the operator's own bookkeeping — the plugin itself is stateless).
    #[serde(default)]
    pub allow_count_so_far: u32,
}

/// The full operator policy document (v1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    pub default_action: String,
    pub assets: BTreeMap<String, AssetPolicy>,
    pub allowed_recipients: BTreeSet<String>,
    /// Nonce accounts the operator explicitly permits for durable-nonce
    /// transactions. Empty (the default) means no durable transaction is ever
    /// permitted, so existing policies keep their exact behavior.
    #[serde(default)]
    pub allowed_nonce_accounts: BTreeSet<String>,
    pub allowed_instructions: BTreeMap<String, BTreeSet<String>>,
    pub unknown_program: Outcome,
    pub unknown_instruction: Outcome,
    pub missing_intent: Outcome,
    pub durable_nonce: Outcome,
    #[serde(default)]
    pub velocity: Option<VelocityPolicy>,
    #[serde(default)]
    pub fee: Option<FeePolicy>,
    #[serde(default = "default_true")]
    pub require_unsigned: bool,
    #[serde(default = "default_max_bytes")]
    pub max_transaction_bytes: usize,
    pub token_2022: Token2022Policy,
    pub simulation: SimulationPolicy,
}

fn default_true() -> bool {
    true
}
fn default_max_bytes() -> usize {
    1232
}

/// Simulation requirements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulationPolicy {
    pub required: bool,
    pub max_slot_age: u64,
}

/// The operator policy, parsed + validated. Construct via [`Policy::from_json`].
impl Policy {
    /// Parse and validate a policy document. Strict: unknown top-level keys,
    /// malformed amounts, or `require_unsigned = false` are hard errors —
    /// ambiguous configuration is never honored.
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        let raw: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("policy_json is not valid JSON: {e}"))?;
        let obj = raw
            .as_object()
            .ok_or_else(|| "policy_json must be a JSON object".to_string())?;
        const KNOWN: [&str; 17] = [
            "version",
            "default_action",
            "assets",
            "allowed_recipients",
            "allowed_nonce_accounts",
            "allowed_instructions",
            "unknown_program",
            "unknown_instruction",
            "missing_intent",
            "durable_nonce",
            "velocity",
            "fee",
            "require_unsigned",
            "max_transaction_bytes",
            "token_2022",
            "simulation",
            "comment",
        ];
        let unknown: Vec<&String> = obj
            .keys()
            .filter(|k| !KNOWN.contains(&k.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(format!(
                "unknown policy keys: {}; refusing ambiguous configuration",
                unknown
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if obj.contains_key("fee") {
            return Err(
                "fee policy is unsupported in safe v0.1: complete fee/rent evidence is unavailable"
                    .to_string(),
            );
        }
        let policy: Policy =
            serde_json::from_value(raw).map_err(|e| format!("policy_json schema error: {e}"))?;
        if !policy.require_unsigned {
            return Err("require_unsigned is a firewall invariant and cannot be disabled".into());
        }
        if policy.default_action != "deny" {
            return Err("default_action must be \"deny\" — Safe Hands is deny-by-default".into());
        }
        for (name, asset) in &policy.assets {
            asset.max_raw().map_err(|e| format!("asset {name}: {e}"))?;
        }
        Ok(policy)
    }

    /// Canonical SHA-256 of the policy (BTree ordering makes this stable).
    pub fn sha256(&self) -> String {
        let canonical = serde_json::to_string(self).expect("policy is serializable");
        hex_sha256(canonical.as_bytes())
    }
}

/// One decoded instruction: program label + recognized instruction name.
#[derive(Clone, Debug)]
pub struct IxFact {
    /// Canonical program label ("system", "spl_token", "token_2022", "memo",
    /// "associated_token", "compute_budget", "squads") or "unknown:<base58>".
    pub program: String,
    /// Recognized instruction name, if the discriminator is known.
    pub name: Option<String>,
}

/// One value movement, in raw units. `mint: None` means native SOL.
#[derive(Clone, Debug)]
pub struct TransferFact {
    pub mint: Option<String>,
    pub amount_raw: u128,
    pub recipient: String,
}

/// Token-2022 extension presence on involved mints.
#[derive(Clone, Debug, Default)]
pub struct Token2022Flags {
    pub permanent_delegate: bool,
    pub transfer_hook: bool,
    pub transfer_fee: bool,
    pub default_frozen: bool,
}

/// Declared intent supplied by the caller (matched against reality).
#[derive(Clone, Debug, Deserialize)]
pub struct Intent {
    pub action: String,
    pub mint: Option<String>,
    pub amount_raw: String,
    pub recipient: String,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Every fact the engine sees about one transaction. Built by the caller from
/// decoded bytes + simulation; the engine itself never touches RPC.
#[derive(Clone, Debug, Default)]
pub struct TxFacts {
    pub signed: bool,
    pub byte_len: usize,
    pub instructions: Vec<IxFact>,
    /// Strict UTF-8 contents of every decoded Memo instruction, in order.
    pub memos: Vec<String>,
    pub transfers: Vec<TransferFact>,
    pub durable_nonce_used: bool,
    /// The nonce account named by an `AdvanceNonceAccount` instruction, when
    /// one is present and its accounts could be resolved. `None` while
    /// `durable_nonce_used` is true means the nonce could not be identified,
    /// which must never be treated as permission.
    pub nonce_account: Option<String>,
    /// Whether `AdvanceNonceAccount` was instruction index 0. The Solana
    /// runtime requires it to be first; anything else is a malformed durable
    /// transaction and is refused rather than partially honored.
    pub nonce_is_first_instruction: bool,
    pub authority_change: bool,
    pub token2022: Token2022Flags,
    pub priority_fee_lamports: u64,
    pub estimated_fee_lamports: u64,
    pub account_creation_lamports: u64,
    pub simulation_ok: bool,
    pub intent: Option<Intent>,
}

/// The engine's report: verdict + machine codes + matched rule ids.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub reason_codes: Vec<String>,
    pub matched_rules: Vec<String>,
}

const MAX_REASONS: usize = 6;

/// Evaluate one transaction against one policy. Total and deterministic.
pub fn evaluate(policy: &Policy, facts: &TxFacts) -> Report {
    // Every finding is (severity, reason_code, rule_id). Severity precedence is
    // resolved at the end: Deny > Unknown > Review > Allow.
    let mut findings: Vec<(Verdict, &'static str, &'static str)> = Vec::new();
    macro_rules! deny {
        ($c:expr, $r:expr) => {
            findings.push((Verdict::Deny, $c, $r))
        };
    }
    macro_rules! review {
        ($c:expr, $r:expr) => {
            findings.push((Verdict::Review, $c, $r))
        };
    }
    macro_rules! unknown {
        ($c:expr, $r:expr) => {
            findings.push((Verdict::Unknown, $c, $r))
        };
    }

    // 1. Signature state: pre-sign policy requires zero-filled signatures.
    if policy.require_unsigned && facts.signed {
        deny!("SH-DENY-SIGNED-001", "REQUIRE_UNSIGNED");
    }

    // 2. Canonical packet bound.
    if facts.byte_len > policy.max_transaction_bytes {
        deny!("SH-DENY-TOOBIG-002", "MAX_TX_BYTES");
    }

    // 3. Safe v0.1 instruction invariants cannot be relaxed by operator
    // configuration: Token-2022 is unsupported, and classic SPL Token permits
    // only TransferChecked (plain Transfer omits the mint from its accounts).
    for ix in &facts.instructions {
        if ix.program == "token_2022" {
            deny!("SH-DENY-T22-060", "SAFE_V01_TOKEN_2022");
            continue;
        }
        // Squads is used only by the outer proposal transaction constructed
        // after authorization. An inner draft may not invoke Squads: generic
        // Squads instructions can create accounts or charge the vault through
        // CPI without appearing in decoded transfer totals.
        if ix.program == "squads" {
            deny!("SH-DENY-SQUADS-INNER-063", "SAFE_V01_NO_INNER_SQUADS");
            continue;
        }
        if ix.program == "spl_token" {
            match ix.name.as_deref() {
                Some("transfer_checked") => {}
                Some("transfer") => {
                    deny!("SH-DENY-SPL-PLAIN-061", "SAFE_V01_SPL_TRANSFER")
                }
                _ => deny!("SH-DENY-SPL-IX-062", "SAFE_V01_SPL_TRANSFER_CHECKED_ONLY"),
            }
            if ix.name.as_deref() != Some("transfer_checked") {
                continue;
            }
        }

        if ix.program.starts_with("unknown:") {
            match policy.unknown_program {
                Outcome::Deny => deny!("SH-DENY-PROGRAM-011", "UNKNOWN_PROGRAM"),
                Outcome::Review => review!("SH-REVIEW-PROGRAM-013", "UNKNOWN_PROGRAM"),
            }
            continue;
        }
        let allowed_names = policy.allowed_instructions.get(&ix.program);
        match (allowed_names, &ix.name) {
            (Some(names), Some(name)) if names.contains(name) => {}
            _ => match policy.unknown_instruction {
                Outcome::Deny => deny!("SH-DENY-IX-012", "UNKNOWN_INSTRUCTION"),
                Outcome::Review => review!("SH-REVIEW-IX-014", "UNKNOWN_INSTRUCTION"),
            },
        }
    }

    // 4. Durable nonce: a delayed-execution pattern, and the reason an
    //    approval-gated payment survives a human going to lunch. It is
    //    permitted only when the operator named this exact nonce account in
    //    host policy AND the runtime's own rule — AdvanceNonceAccount must be
    //    instruction 0 — actually holds. Everything else falls through to the
    //    configured outcome, so a policy without `allowed_nonce_accounts`
    //    behaves exactly as it did before this existed.
    if facts.durable_nonce_used {
        let permitted = facts
            .nonce_account
            .as_ref()
            .is_some_and(|account| policy.allowed_nonce_accounts.contains(account));
        if !permitted {
            match policy.durable_nonce {
                Outcome::Deny => deny!("SH-DENY-NONCE-010", "DURABLE_NONCE"),
                Outcome::Review => review!("SH-REVIEW-NONCE-009", "DURABLE_NONCE"),
            }
        } else if !facts.nonce_is_first_instruction {
            // Allowlisted, but malformed: the runtime would reject it and a
            // half-honored durable transaction is never emitted.
            deny!("SH-DENY-NONCE-011", "DURABLE_NONCE_NOT_FIRST");
        }
    }

    // 5. Authority changes are always denied.
    if facts.authority_change {
        deny!("SH-DENY-AUTH-022", "AUTHORITY_CHANGE");
    }

    // 6. Token-2022 extension rules.
    let t22 = &facts.token2022;
    if t22.permanent_delegate {
        match policy.token_2022.permanent_delegate {
            Outcome::Deny => deny!("SH-DENY-T22-DELEGATE-020", "T22_PERMANENT_DELEGATE"),
            Outcome::Review => review!("SH-REVIEW-T22-DELEGATE-024", "T22_PERMANENT_DELEGATE"),
        }
    }
    if t22.transfer_hook {
        match policy.token_2022.transfer_hook {
            Outcome::Deny => deny!("SH-DENY-T22-HOOK-023", "T22_TRANSFER_HOOK"),
            Outcome::Review => review!("SH-REVIEW-T22-HOOK-021", "T22_TRANSFER_HOOK"),
        }
    }
    if t22.transfer_fee {
        match policy.token_2022.transfer_fee {
            Outcome::Deny => deny!("SH-DENY-T22-FEE-025", "T22_TRANSFER_FEE"),
            Outcome::Review => review!("SH-REVIEW-T22-FEE-026", "T22_TRANSFER_FEE"),
        }
    }
    if t22.default_frozen {
        match policy.token_2022.default_frozen {
            Outcome::Deny => deny!("SH-DENY-T22-FROZEN-027", "T22_DEFAULT_FROZEN"),
            Outcome::Review => review!("SH-REVIEW-T22-FROZEN-028", "T22_DEFAULT_FROZEN"),
        }
    }

    // 7. Transfers: recipient allowlist, mint allowlist, and the aggregate
    // per-transaction cap for each asset. Checking instructions one by one
    // would let a caller split one spend into several individually-at-cap
    // transfers inside the same transaction.
    let mut asset_totals: std::collections::BTreeMap<String, Option<u128>> =
        std::collections::BTreeMap::new();
    for tr in &facts.transfers {
        if !recipient_allowed(policy, tr) {
            deny!("SH-DENY-RECIPIENT-003", "RECIPIENT_ALLOWLIST");
        }
        let asset_key = tr.mint.clone().unwrap_or_else(|| "SOL".to_string());
        let total = asset_totals.entry(asset_key).or_insert(Some(0));
        *total = total.and_then(|current| current.checked_add(tr.amount_raw));
    }
    for (asset_key, total) in &asset_totals {
        match (policy.assets.get(asset_key), total) {
            (Some(asset), Some(total)) => match asset.max_raw() {
                Ok(max) if *total <= max => {}
                _ => deny!("SH-DENY-CAP-001", "PER_TX_CAP"),
            },
            (Some(_), None) => deny!("SH-DENY-CAP-001", "PER_TX_CAP"),
            (None, _) => deny!("SH-DENY-MINT-002", "MINT_ALLOWLIST"),
        }
    }

    // 8. Reserved future fee/rent enforcement. Policy::from_json rejects the
    // fee section in safe v0.1 because complete evidence is not yet available.
    //
    // This block is therefore unreachable through the public API: no policy
    // that parses can carry `fee`. `cargo mutants` surfaces survivors here for
    // exactly that reason — the comparisons cannot be exercised without
    // constructing a Policy by hand. They are left in place rather than
    // deleted so the shape is ready when fee evidence lands, and left untested
    // rather than tested through a back door, because a test that reaches code
    // operators cannot reach would assert nothing about the shipped product.
    if let Some(fee) = &policy.fee {
        if facts.priority_fee_lamports > fee.max_priority_fee_lamports
            || facts.estimated_fee_lamports > fee.max_transaction_fee_lamports
        {
            deny!("SH-DENY-FEE-030", "FEE_CAP");
        }
        if facts.account_creation_lamports > fee.max_account_creation_lamports {
            deny!("SH-DENY-RENT-031", "ACCOUNT_CREATION_CAP");
        }
    }

    // 9. Intent binding: the tx must BE what the caller declared.
    match &facts.intent {
        None => match policy.missing_intent {
            Outcome::Deny => deny!("SH-DENY-NOINTENT-006", "MISSING_INTENT"),
            Outcome::Review => review!("SH-REVIEW-NOINTENT-005", "MISSING_INTENT"),
        },
        Some(intent) => {
            let intent_mint = intent.mint.clone().unwrap_or_else(|| "SOL".to_string());
            let intent_amount = intent.amount_raw.parse::<u128>();
            if facts.transfers.is_empty() {
                deny!("SH-INTENT-MATCH-030", "INTENT_MISMATCH");
            }
            let action_matches_transfer_kind = !facts.transfers.is_empty()
                && facts
                    .transfers
                    .iter()
                    .all(|transfer| match transfer.mint.as_ref() {
                        None => intent.action == "transfer" && intent.mint.is_none(),
                        Some(_) => intent.action == "spl_transfer" && intent.mint.is_some(),
                    });
            if !action_matches_transfer_kind {
                deny!("SH-INTENT-ACTION-034", "INTENT_ACTION_MISMATCH");
            }
            for tr in &facts.transfers {
                let tr_mint = tr.mint.clone().unwrap_or_else(|| "SOL".to_string());
                if !recipient_matches_intent(&intent.recipient, tr) {
                    deny!("SH-INTENT-RECIPIENT-031", "INTENT_MISMATCH");
                }
                if tr_mint != intent_mint {
                    deny!("SH-INTENT-MINT-032", "INTENT_MISMATCH");
                }
            }
            let total = facts
                .transfers
                .iter()
                .try_fold(0u128, |sum, tr| sum.checked_add(tr.amount_raw));
            if !matches!((intent_amount, total), (Ok(expected), Some(actual)) if expected == actual)
            {
                deny!("SH-INTENT-AMOUNT-033", "INTENT_MISMATCH");
            }
            let memo_matches = match (&intent.memo, facts.memos.as_slice()) {
                (None, []) => true,
                (Some(expected), [actual]) => expected == actual,
                _ => false,
            };
            if !memo_matches {
                deny!("SH-INTENT-MEMO-035", "INTENT_MEMO_MISMATCH");
            }
        }
    }

    // 10. Velocity: bursts escalate to a human (drains are fast, humans are slow).
    if let Some(velocity) = &policy.velocity {
        if velocity.allow_count_so_far >= velocity.max_allow_per_hour {
            review!("SH-REVIEW-VELOCITY-041", "VELOCITY");
        }
    }

    // 11. Simulation evidence is mandatory when configured.
    if policy.simulation.required && !facts.simulation_ok {
        unknown!("SH-UNKNOWN-SIM-051", "SIMULATION_REQUIRED");
    }

    let verdict = if findings.iter().any(|(v, _, _)| *v == Verdict::Deny) {
        Verdict::Deny
    } else if findings.iter().any(|(v, _, _)| *v == Verdict::Unknown) {
        Verdict::Unknown
    } else if findings.iter().any(|(v, _, _)| *v == Verdict::Review) {
        Verdict::Review
    } else {
        Verdict::Allow
    };

    let reason_codes: Vec<String> = findings
        .iter()
        .take(MAX_REASONS)
        .map(|(_, c, _)| c.to_string())
        .collect();
    let matched_rules: Vec<String> = findings.iter().map(|(_, _, r)| r.to_string()).collect();

    Report {
        verdict,
        reason_codes,
        matched_rules,
    }
}

/// hex SHA-256 of bytes.
pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// ATA-aware recipient check. Agents pay wallets, but tokens land in
/// Associated Token Accounts — so a classic SPL transfer whose destination is
/// the ATA of an allowed wallet for the same mint is legitimate.
fn recipient_allowed(policy: &Policy, tr: &TransferFact) -> bool {
    if policy.allowed_recipients.contains(&tr.recipient) {
        return true;
    }
    let Some(mint_str) = tr.mint.as_ref() else {
        return false;
    };
    let Ok(mint) = crate::crypto::parse_pubkey(mint_str) else {
        return false;
    };
    let Ok(token_program) = crate::crypto::parse_pubkey(crate::crypto::TOKEN_PROGRAM) else {
        return false;
    };
    policy.allowed_recipients.iter().any(|wallet| {
        let Ok(wallet) = crate::crypto::parse_pubkey(wallet) else {
            return false;
        };
        crate::crypto::ata_address(&wallet, &token_program, &mint).to_string() == tr.recipient
    })
}

/// Intent recipient matching, ATA-aware: the declared wallet matches a transfer
/// to that wallet OR to the ATA of that wallet for the transfer's mint.
fn recipient_matches_intent(intent_recipient: &str, tr: &TransferFact) -> bool {
    if tr.recipient == intent_recipient {
        return true;
    }
    let Some(mint_str) = tr.mint.as_ref() else {
        return false;
    };
    let (Ok(mint), Ok(wallet)) = (
        crate::crypto::parse_pubkey(mint_str),
        crate::crypto::parse_pubkey(intent_recipient),
    ) else {
        return false;
    };
    let Ok(program) = crate::crypto::parse_pubkey(crate::crypto::TOKEN_PROGRAM) else {
        return false;
    };
    crate::crypto::ata_address(&wallet, &program, &mint).to_string() == tr.recipient
}

/// Convenience: policy from the host-injected flat config map.
/// Empty/missing policy_json is a hard error (fail closed by design).
pub fn policy_from_config(
    config: &std::collections::HashMap<String, String>,
) -> Result<Policy, String> {
    match config.get("policy_json") {
        Some(raw) if !raw.trim().is_empty() => Policy::from_json(raw),
        _ => Err("no policy configured — fail closed".to_string()),
    }
}

#[cfg(test)]
mod tests;

/// Machine-checked proofs of the authorization invariants. Compiled only
/// under `cargo kani`, so a normal build and `cargo test` are unaffected.
#[cfg(kani)]
mod proofs;
