//! The model is not fooled — it is cooperating with the attacker.
//!
//! Every prompt-injection test in this repository assumes a model that has
//! been *tricked*: it is still trying to do its job and has been given bad
//! information. The ROADMAP names the harder case as untested — a model that
//! has been compromised outright, and is now constructing evidence on the
//! attacker's behalf.
//!
//! That distinction matters because the compromised model does not produce
//! contradictions for a checker to notice. It supplies a transaction, an
//! intent that matches it exactly, a simulation that passed, and effect
//! evidence that agrees with both. Every consistency check the engine can
//! perform against the caller's own story succeeds. Nothing is out of place.
//!
//! What it cannot supply is the operator's policy: caps, the recipient
//! allowlist and the asset list arrive from host config, which the host injects
//! and strips from caller arguments. So the property under test is not "can the
//! engine spot a lie" — against a competent liar it cannot — but:
//!
//! **A perfectly consistent story that violates operator policy is still
//! refused, and the reason cited is the policy, not the inconsistency.**
//!
//! If any test here ever fails, intent matching has been promoted from a
//! *second* check into a substitute for the first one, and a compromised model
//! would be able to authorize itself.

use safe_hands_core::policy::{evaluate, Intent, Policy, TransferFact, TxFacts, Verdict};

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// On the operator's allowlist.
const ALLOWED: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
/// Not on it. The attacker's address.
const ATTACKER: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
/// The per-tx cap for USDC in the shipped merchant policy.
const CAP: u128 = 25_000_000;

fn merchant_policy() -> Policy {
    Policy::from_json(
        r#"{
          "version": "1.0.0",
          "default_action": "deny",
          "assets": {
            "SOL": { "decimals": 9, "max_per_tx_raw": "2000000000" },
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {
              "decimals": 6, "max_per_tx_raw": "25000000"
            }
          },
          "allowed_recipients": ["9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"],
          "allowed_instructions": {
            "system": ["transfer"],
            "spl_token": ["transfer_checked"],
            "associated_token": ["create_idempotent"],
            "memo": ["memo"]
          },
          "unknown_program": "deny",
          "unknown_instruction": "deny",
          "missing_intent": "review",
          "durable_nonce": "review",
          "token_2022": {
            "permanent_delegate": "deny",
            "transfer_hook": "deny",
            "transfer_fee": "deny",
            "default_frozen": "deny"
          },
          "simulation": { "required": true, "max_slot_age": 32 }
        }"#,
    )
    .expect("merchant policy parses")
}

/// A transfer, plus an intent that describes it perfectly.
///
/// This is the compromised model's best move: tell the truth about what the
/// transaction does, so that every cross-check the engine performs agrees.
fn consistent_story(amount: u128, recipient: &str) -> TxFacts {
    TxFacts {
        signed: false,
        transfers: vec![TransferFact {
            mint: Some(USDC.into()),
            amount_raw: amount,
            recipient: recipient.into(),
        }],
        // The caller also asserts that simulation succeeded. A compromised
        // model would.
        simulation_ok: true,
        intent: Some(Intent {
            action: "spl_transfer".into(),
            mint: Some(USDC.into()),
            amount_raw: amount.to_string(),
            recipient: recipient.into(),
            memo: None,
        }),
        ..Default::default()
    }
}

#[test]
fn the_control_case_is_allowed_or_these_tests_prove_nothing() {
    let report = evaluate(&merchant_policy(), &consistent_story(1_000_000, ALLOWED));
    assert_eq!(
        report.verdict,
        Verdict::Allow,
        "a compliant transfer with a matching intent must be ALLOW, \
         otherwise the refusals below are not evidence of anything"
    );
}

#[test]
fn a_truthful_intent_cannot_authorize_an_unlisted_recipient() {
    let report = evaluate(&merchant_policy(), &consistent_story(1_000_000, ATTACKER));
    assert_ne!(
        report.verdict,
        Verdict::Allow,
        "an intent that honestly describes a transfer to an unlisted recipient \
         must not authorize it: {report:?}"
    );
}

#[test]
fn a_truthful_intent_cannot_authorize_an_over_cap_transfer() {
    let report = evaluate(&merchant_policy(), &consistent_story(CAP + 1, ALLOWED));
    assert_ne!(
        report.verdict,
        Verdict::Allow,
        "an intent that honestly declares an over-cap amount must not \
         authorize it: {report:?}"
    );
}

#[test]
fn a_truthful_intent_cannot_authorize_an_unlisted_asset() {
    let mut facts = consistent_story(1_000_000, ALLOWED);
    let rogue = "So11111111111111111111111111111111111111112";
    facts.transfers[0].mint = Some(rogue.into());
    if let Some(intent) = facts.intent.as_mut() {
        intent.mint = Some(rogue.into());
    }
    let report = evaluate(&merchant_policy(), &facts);
    assert_ne!(
        report.verdict,
        Verdict::Allow,
        "a mint absent from the policy's asset list must not be spendable \
         merely because the intent agrees it is being spent: {report:?}"
    );
}

/// Fragmenting the spend does not help either, and the intent declaring the
/// true aggregate does not make it worse — the aggregate rule is what fires.
#[test]
fn a_truthful_intent_cannot_authorize_a_split_over_cap_spend() {
    let mut facts = consistent_story(CAP, ALLOWED);
    facts.transfers = vec![
        TransferFact {
            mint: Some(USDC.into()),
            amount_raw: CAP,
            recipient: ALLOWED.into(),
        },
        TransferFact {
            mint: Some(USDC.into()),
            amount_raw: 1,
            recipient: ALLOWED.into(),
        },
    ];
    if let Some(intent) = facts.intent.as_mut() {
        intent.amount_raw = (CAP + 1).to_string();
    }
    let report = evaluate(&merchant_policy(), &facts);
    assert_ne!(
        report.verdict,
        Verdict::Allow,
        "splitting an over-cap spend across two honest transfers must not \
         authorize it: {report:?}"
    );
}

/// The caller asserting a successful simulation does not launder a policy
/// violation. Simulation answers "would the runtime accept this", never
/// "should the operator".
#[test]
fn asserting_a_passing_simulation_does_not_launder_a_violation() {
    let mut facts = consistent_story(1_000_000, ATTACKER);
    facts.simulation_ok = true;
    let report = evaluate(&merchant_policy(), &facts);
    assert_ne!(
        report.verdict,
        Verdict::Allow,
        "simulation is not authorization: {report:?}"
    );
}

/// Two independent gates, and defeating one is not defeating both.
///
/// Here the model tells the truth about the recipient — so intent matching is
/// satisfied — and the transfer is still refused. The point is that a
/// compromised model gains nothing by being consistent, which is the only
/// thing it can control.
#[test]
fn consistency_earns_nothing_when_the_policy_says_no() {
    let honest = consistent_story(1_000_000, ATTACKER);
    let honest_report = evaluate(&merchant_policy(), &honest);

    // The same violation, this time with an intent that lies about it.
    let mut lying = honest.clone();
    if let Some(intent) = lying.intent.as_mut() {
        intent.recipient = ALLOWED.into();
    }
    let lying_report = evaluate(&merchant_policy(), &lying);

    assert_ne!(honest_report.verdict, Verdict::Allow);
    assert_ne!(lying_report.verdict, Verdict::Allow);
}
