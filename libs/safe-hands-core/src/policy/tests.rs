//! Boundary matrix for the policy engine. Every rule, every edge, offline.

use super::*;

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIP: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const OTHER: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";

fn demo_policy_json() -> String {
    format!(
        r#"{{
        "version": "1.0.0",
        "default_action": "deny",
        "assets": {{
            "SOL": {{"decimals": 9, "max_per_tx_raw": "100000000"}},
            "{USDC}": {{"decimals": 6, "max_per_tx_raw": "25000000"}}
        }},
        "allowed_recipients": ["{RECIP}"],
        "allowed_instructions": {{
            "system": ["transfer"],
            "spl_token": ["transfer", "transfer_checked"],
            "associated_token": ["create_idempotent"],
            "memo": ["memo"]
        }},
        "unknown_program": "deny",
        "unknown_instruction": "deny",
        "missing_intent": "review",
        "durable_nonce": "review",
        "token_2022": {{"permanent_delegate": "deny", "transfer_hook": "review",
                        "transfer_fee": "review", "default_frozen": "deny"}},
        "simulation": {{"required": true, "max_slot_age": 32}}
    }}"#
    )
}

fn policy() -> Policy {
    Policy::from_json(&demo_policy_json()).expect("demo policy parses")
}

fn usdc_transfer(amount: u128, recipient: &str) -> TxFacts {
    TxFacts {
        byte_len: 400,
        simulation_ok: true,
        instructions: vec![
            IxFact {
                program: "associated_token".into(),
                name: Some("create_idempotent".into()),
            },
            IxFact {
                program: "spl_token".into(),
                name: Some("transfer_checked".into()),
            },
            IxFact {
                program: "memo".into(),
                name: Some("memo".into()),
            },
        ],
        transfers: vec![TransferFact {
            mint: Some(USDC.into()),
            amount_raw: amount,
            recipient: recipient.into(),
        }],
        intent: Some(Intent {
            action: "spl_transfer".into(),
            mint: Some(USDC.into()),
            amount_raw: amount.to_string(),
            recipient: recipient.into(),
        }),
        ..Default::default()
    }
}

#[test]
fn happy_path_allows() {
    let r = evaluate(&policy(), &usdc_transfer(25_000_000, RECIP));
    assert_eq!(r.verdict, Verdict::Allow, "reasons: {:?}", r.reason_codes);
}

#[test]
fn at_cap_allows_one_over_denies() {
    let p = policy();
    let at = evaluate(&p, &usdc_transfer(25_000_000, RECIP));
    assert_eq!(at.verdict, Verdict::Allow);
    let over = evaluate(&p, &usdc_transfer(25_000_001, RECIP));
    assert_eq!(over.verdict, Verdict::Deny);
    assert!(over
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-DENY-CAP")));
}

#[test]
fn empty_config_fails_closed() {
    let cfg = std::collections::HashMap::new();
    assert!(policy_from_config(&cfg).is_err());
}

#[test]
fn malformed_policy_rejected() {
    assert!(Policy::from_json("not json").is_err());
    assert!(Policy::from_json("[]").is_err());
    assert!(Policy::from_json(r#"{"version":"1"}"#).is_err());
    // unknown key
    let bad = demo_policy_json().replace("\"version\"", "\"vers10n\"");
    assert!(Policy::from_json(&bad).is_err());
    // require_unsigned=false is an invariant violation
    let bad2 = demo_policy_json().replace(
        "\"default_action\": \"deny\"",
        "\"default_action\": \"deny\", \"require_unsigned\": false",
    );
    assert!(Policy::from_json(&bad2).is_err());
}

#[test]
fn unknown_program_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.instructions.push(IxFact {
        program: "unknown:BadProgram111".into(),
        name: None,
    });
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-DENY-PROGRAM")));
}

#[test]
fn unknown_instruction_in_allowed_program_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.instructions.push(IxFact {
        program: "spl_token".into(),
        name: Some("approve".into()),
    });
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r.reason_codes.iter().any(|c| c.starts_with("SH-DENY-IX")));
}

#[test]
fn unrecognized_instruction_name_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.instructions.push(IxFact {
        program: "system".into(),
        name: None,
    });
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
}

#[test]
fn wrong_recipient_denies() {
    let r = evaluate(&policy(), &usdc_transfer(1_000, OTHER));
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-DENY-RECIPIENT")));
}

#[test]
fn wrong_mint_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.transfers[0].mint = Some("So11111111111111111111111111111111111111112".into());
    f.intent = None;
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r.reason_codes.iter().any(|c| c.starts_with("SH-DENY-MINT")));
}

#[test]
fn signed_input_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.signed = true;
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-DENY-SIGNED")));
}

#[test]
fn durable_nonce_reviews_by_default() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.durable_nonce_used = true;
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Review);
    assert!(r
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-REVIEW-NONCE")));
}

#[test]
fn authority_change_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.authority_change = true;
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
}

#[test]
fn t22_delegate_denies_hook_reviews() {
    let p = policy();
    let mut f1 = usdc_transfer(1_000, RECIP);
    f1.token2022.permanent_delegate = true;
    assert_eq!(evaluate(&p, &f1).verdict, Verdict::Deny);
    let mut f2 = usdc_transfer(1_000, RECIP);
    f2.token2022.transfer_hook = true;
    assert_eq!(evaluate(&p, &f2).verdict, Verdict::Review);
}

#[test]
fn missing_intent_reviews_mismatch_denies() {
    let p = policy();
    let mut no_intent = usdc_transfer(1_000, RECIP);
    no_intent.intent = None;
    assert_eq!(evaluate(&p, &no_intent).verdict, Verdict::Review);

    let mut wrong_amount = usdc_transfer(1_000, RECIP);
    wrong_amount.intent = Some(Intent {
        action: "spl_transfer".into(),
        mint: Some(USDC.into()),
        amount_raw: "500".into(), // declared 500, tx moves 1000
        recipient: RECIP.into(),
    });
    let r = evaluate(&p, &wrong_amount);
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r.reason_codes.iter().any(|c| c.starts_with("SH-INTENT")));
}

#[test]
fn extra_unrelated_transfer_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.transfers.push(TransferFact {
        mint: Some(USDC.into()),
        amount_raw: 1,
        recipient: OTHER.into(),
    });
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
}

#[test]
fn missing_simulation_unknown() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.simulation_ok = false;
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Unknown);
    assert!(r
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-UNKNOWN-SIM")));
}

#[test]
fn deny_beats_review_precedence() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.durable_nonce_used = true; // review
    f.authority_change = true; // deny
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
}

#[test]
fn velocity_reviews_when_exceeded() {
    let mut p = policy();
    p.velocity = Some(VelocityPolicy {
        max_allow_per_hour: 6,
        allow_count_so_far: 6,
    });
    let r = evaluate(&p, &usdc_transfer(1_000, RECIP));
    assert_eq!(r.verdict, Verdict::Review);
    assert!(r
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-REVIEW-VELOCITY")));
}

#[test]
fn fee_caps_enforced_when_configured() {
    let mut p = policy();
    p.fee = Some(FeePolicy {
        max_priority_fee_lamports: 1_000_000,
        max_transaction_fee_lamports: 5_000_000,
        max_account_creation_lamports: 3_000_000,
    });
    let mut f = usdc_transfer(1_000, RECIP);
    f.priority_fee_lamports = 9_000_000;
    let r = evaluate(&p, &f);
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(r.reason_codes.iter().any(|c| c.starts_with("SH-DENY-FEE")));
}

#[test]
fn policy_hash_is_stable() {
    let h1 = policy().sha256();
    // same content, keys in different order -> different document, but our
    // canonical struct must hash identically after parsing
    let reordered = demo_policy_json().replace(
        "\"version\": \"1.0.0\",\n        \"default_action\": \"deny\",",
        "\"default_action\": \"deny\",\n        \"version\": \"1.0.0\",",
    );
    let h2 = Policy::from_json(&reordered)
        .expect("reordered parses")
        .sha256();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}
