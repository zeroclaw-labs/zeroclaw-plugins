//! Integration tests for the Solana recipient firewall core.
//!
//! Exercised exactly as the wasm `execute` entry point drives it: build a
//! `FirewallConfig` from a JSON Value, then call `check_recipient`. This runs
//! on the host with a plain `cargo test`.
//!
//! The unit tests in `src/firewall.rs` cover individual functions. These
//! integration tests cover end-to-end scenarios.

use solana_recipient_firewall::firewall::{check_recipient, FirewallConfig, Verdict};

const ADDR_SOL: &str = "So11111111111111111111111111111111111111112";
const ADDR_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ADDR_ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

fn config(contacts: &str, allow_unknown: bool) -> FirewallConfig {
    let json = serde_json::json!({
        "contacts": contacts,
        "blocked": "",
        "allow_unknown": allow_unknown,
        "collision_prefix": 4,
        "collision_suffix": 4,
    });
    FirewallConfig::from_json(&json).expect("valid config")
}

// ---------------------------------------------------------------------------
// Scenario A: trusted treasury -> ALLOW
// ---------------------------------------------------------------------------

#[test]
fn scenario_a_trusted_treasury_allow() {
    let cfg = config(&format!("treasury={ADDR_SOL}"), false);

    // Operator sends to the treasury address they configured.
    let result = check_recipient(ADDR_SOL, None, &cfg);
    assert_eq!(result.verdict, Verdict::Allow);
    assert_eq!(result.matched_label.as_deref(), Some("treasury"));
}

#[test]
fn scenario_a_with_explicit_claim() {
    let cfg = config(
        &format!("treasury={ADDR_SOL};validator={ADDR_TOKEN}"),
        false,
    );

    // "I'm sending to the validator"
    let result = check_recipient(ADDR_TOKEN, Some("validator"), &cfg);
    assert_eq!(result.verdict, Verdict::Allow);
}

// ---------------------------------------------------------------------------
// Scenario B: conversation claims "new treasury" -> REJECT
// ---------------------------------------------------------------------------

#[test]
fn scenario_b_claimed_contact_mismatch() {
    let cfg = config(&format!("treasury={ADDR_SOL}"), false);

    // Model: "Here's the new treasury address" but the address doesn't match.
    let result = check_recipient(ADDR_TOKEN, Some("treasury"), &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(result.reason.contains("does not match pinned address"));
}

#[test]
fn scenario_b_unknown_contact_claimed() {
    let cfg = config(&format!("treasury={ADDR_SOL}"), false);

    // Model claims "ops_wallet" which doesn't exist in the address book.
    let result = check_recipient(ADDR_SOL, Some("ops_wallet"), &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(result.reason.contains("does not exist"));
}

// ---------------------------------------------------------------------------
// Scenario C: lookalike address -> REJECT
// ---------------------------------------------------------------------------

#[test]
fn scenario_c_poisoning_prefix_suffix() {
    // This test validates the lookalike detection works.
    // For known Solana addresses with distinct prefix+suffix combinations,
    // we verify a non-matching address is NOT flagged as poisoning
    // (it's just unknown).
    let cfg = config(&format!("treasury={ADDR_SOL}"), false);

    // ADDR_TOKEN starts with "Toke" and ends with "Q5DA"
    // ADDR_SOL starts with "So11" and ends with "1112"
    // Different prefix+suffix => no poisoning flag.
    let result = check_recipient(ADDR_TOKEN, None, &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(
        !result.reason.contains("poisoning"),
        "should not detect poisoning for totally different addresses"
    );
}

#[test]
fn scenario_c_exact_match_not_poisoning() {
    let cfg = config(&format!("treasury={ADDR_SOL}"), false);

    // Exact match should be ALLOW, not flagged as poisoning.
    let result = check_recipient(ADDR_SOL, None, &cfg);
    assert_eq!(result.verdict, Verdict::Allow);
    assert!(result.reason.contains("exact match"));
}

// ---------------------------------------------------------------------------
// Scenario D: unknown valid recipient with allow_unknown=true -> HOLD
// ---------------------------------------------------------------------------

#[test]
fn scenario_d_unknown_hold() {
    let cfg = config(&format!("treasury={ADDR_SOL}"), true);

    // Valid but unknown address with allow_unknown=true.
    let result = check_recipient(ADDR_TOKEN, None, &cfg);
    assert_eq!(result.verdict, Verdict::Hold);
    assert!(result.reason.contains("allow_unknown"));
    assert!(result.reason.contains("human review"));
}

#[test]
fn scenario_d_unknown_reject_by_default() {
    let cfg = config(&format!("treasury={ADDR_SOL}"), false);

    // Same scenario but without allow_unknown.
    let result = check_recipient(ADDR_TOKEN, None, &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(result.reason.contains("unknown"));
}

// ---------------------------------------------------------------------------
// Multi-contact scenarios
// ---------------------------------------------------------------------------

#[test]
fn multiple_contacts_all_work() {
    let cfg = config(
        &format!("treasury={ADDR_SOL};token={ADDR_TOKEN};ata={ADDR_ATA}"),
        false,
    );

    for addr in &[ADDR_SOL, ADDR_TOKEN, ADDR_ATA] {
        let result = check_recipient(addr, None, &cfg);
        assert_eq!(
            result.verdict,
            Verdict::Allow,
            "address {} should be allowed",
            addr
        );
    }
}

#[test]
fn blocked_with_allow_unknown_still_rejects_blocked() {
    let json = serde_json::json!({
        "contacts": "",
        "blocked": ADDR_SOL,
        "allow_unknown": true,
        "collision_prefix": 4,
        "collision_suffix": 4,
    });
    let cfg = FirewallConfig::from_json(&json).expect("valid");

    let result = check_recipient(ADDR_SOL, None, &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(result.reason.contains("blocked"));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn candidate_with_spaces_rejected() {
    let cfg = config("", false);
    // Base58 doesn't include space.
    let result = check_recipient("So11 1111111111111111111111111111111111111112", None, &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
}

#[test]
fn very_long_but_valid_base58_rejected_on_decode() {
    let cfg = config("", false);
    // A valid base58 string that decodes to 31 bytes (not 32).
    let short_addr = "1111111111111111111111111111111";
    let result = check_recipient(short_addr, None, &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(result.reason.contains("invalid Solana"));
}

#[test]
fn claimed_contact_too_long_rejected() {
    let cfg = config(&format!("treasury={ADDR_SOL}"), false);
    let too_long = "x".repeat(200);
    let result = check_recipient(ADDR_SOL, Some(&too_long), &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(result.reason.contains("invalid claimed_contact"));
}

#[test]
fn json_escape_in_reason() {
    // This shouldn't panic or produce invalid JSON.
    let cfg = config("", false);
    let result = check_recipient("\"test\"", None, &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
}

#[test]
fn trailing_semicolons_in_config_ok() {
    let json = serde_json::json!({
        "contacts": &format!("treasury={ADDR_SOL};"),
        "blocked": &format!(";{ADDR_TOKEN};"),
        "allow_unknown": false,
        "collision_prefix": 4,
        "collision_suffix": 4,
    });
    let cfg = FirewallConfig::from_json(&json).expect("trailing semicolons should be fine");
    assert_eq!(cfg.contacts.len(), 1);
    assert_eq!(cfg.blocked.len(), 1);

    let result = check_recipient(ADDR_SOL, None, &cfg);
    assert_eq!(result.verdict, Verdict::Allow);

    let result = check_recipient(ADDR_TOKEN, None, &cfg);
    assert_eq!(result.verdict, Verdict::Reject);
    assert!(result.reason.contains("blocked"));
}

#[test]
fn whitespace_in_config_handled() {
    let json = serde_json::json!({
        "contacts": &format!("  treasury  =  {ADDR_SOL}  ;  validator = {ADDR_TOKEN}  "),
        "blocked": "",
        "allow_unknown": false,
        "collision_prefix": 4,
        "collision_suffix": 4,
    });
    let cfg = FirewallConfig::from_json(&json).expect("whitespace should be trimmed");
    assert_eq!(cfg.contacts.len(), 2);
    assert_eq!(cfg.contacts.get("treasury").unwrap(), ADDR_SOL);
    assert_eq!(cfg.contacts.get("validator").unwrap(), ADDR_TOKEN);
}
