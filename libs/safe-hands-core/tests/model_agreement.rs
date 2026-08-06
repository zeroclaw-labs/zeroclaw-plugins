//! The bridge from the proofs to the shipped engine.
//!
//! Twelve Kani harnesses prove properties of `resolved::verdict()`. That is
//! only a statement about `policy::evaluate()` — the function operators
//! actually run — if the two agree. The in-crate agreement tests check exactly
//! that, and an independent reviewer showed they could not do it: both build
//! every input from one helper whose instruction list is hard-coded, so
//! **17 of 34 boolean fields were never exercised**, and `has_unknown_program`
//! was one of them.
//!
//! Inside that blind spot sat a real divergence. `evaluate()` forgives an
//! unfamiliar program when the operator has named it and effect analysis
//! produced evidence; `resolve()` had no such carve-out and denied
//! unconditionally. On the repository's own ALLOW fixture the engine said
//! `Allow` and the model said `Deny`.
//!
//! Every divergence found ran model-*stricter*, so nothing was exploitable.
//! But the transfer argument is one-directional: reading "the model can never
//! ALLOW X" as a claim about the engine needs *engine-ALLOW ⇒ model-ALLOW*, and
//! that was false. On the admitted-program path — the one place the engine
//! deliberately permits a program nobody decoded — the proofs said nothing.
//!
//! So this file varies the instruction list, which is what the existing
//! agreement tests never do.

use safe_hands_core::effects::Movement;
use safe_hands_core::policy::{evaluate, resolved, Intent, IxFact, Policy, TransferFact, TxFacts};

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const ALLOWED: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const ADMITTED: &str = "Stake11111111111111111111111111111111111111";

fn policy_with_effects(required: bool, admit: bool) -> Policy {
    let admitted = if admit {
        format!(r#""{ADMITTED}""#)
    } else {
        String::new()
    };
    Policy::from_json(&format!(
        r#"{{
          "version": "1.0.0",
          "default_action": "deny",
          "assets": {{
            "SOL": {{ "decimals": 9, "max_per_tx_raw": "2000000000" }},
            "{USDC}": {{ "decimals": 6, "max_per_tx_raw": "25000000" }}
          }},
          "allowed_recipients": ["{ALLOWED}"],
          "allowed_instructions": {{
            "system": ["transfer"],
            "spl_token": ["transfer_checked"],
            "memo": ["memo"]
          }},
          "unknown_program": "deny",
          "unknown_instruction": "deny",
          "missing_intent": "review",
          "durable_nonce": "review",
          "token_2022": {{
            "permanent_delegate": "deny", "transfer_hook": "deny",
            "transfer_fee": "deny", "default_frozen": "deny"
          }},
          "simulation": {{ "required": true, "max_slot_age": 32 }},
          "effects": {{
            "required": {required},
            "guarded": ["{ALLOWED}"],
            "max_outflow_raw": {{ "{USDC}": "25000000" }},
            "admitted_programs": [{admitted}]
          }}
        }}"#
    ))
    .expect("policy parses")
}

/// Facts carrying one instruction from an unfamiliar program.
fn unknown_program_facts(with_effects: bool) -> TxFacts {
    TxFacts {
        instructions: vec![IxFact {
            program: format!("unknown:{ADMITTED}"),
            name: None,
        }],
        simulation_ok: true,
        effects: with_effects.then(|| {
            vec![Movement {
                owner: ALLOWED.into(),
                asset: USDC.into(),
                out_raw: 1_000_000,
                in_raw: 0,
            }]
        }),
        intent: Some(Intent {
            action: "effect".into(),
            mint: Some(USDC.into()),
            amount_raw: "1000000".into(),
            recipient: ALLOWED.into(),
            memo: None,
        }),
        transfers: vec![TransferFact {
            mint: Some(USDC.into()),
            amount_raw: 1_000_000,
            recipient: ALLOWED.into(),
        }],
        ..Default::default()
    }
}

fn assert_agrees(label: &str, policy: &Policy, facts: &TxFacts) {
    let engine = evaluate(policy, facts).verdict;
    let model = resolved::resolve(policy, facts).verdict();
    assert_eq!(
        engine, model,
        "{label}: engine said {engine:?}, model said {model:?} — the twelve proofs \
         do not transfer to the engine while these disagree"
    );
}

/// The exact case that was divergent, pinned.
#[test]
fn the_model_agrees_on_an_admitted_program_with_evidence() {
    assert_agrees(
        "admitted program, effects required and present",
        &policy_with_effects(true, true),
        &unknown_program_facts(true),
    );
}

/// Every combination of the three conditions the carve-out depends on.
///
/// Naming without evidence is a blank cheque; evidence without naming would
/// admit any program that stayed under a cap. Both halves have to be checked
/// in both implementations, so all eight corners are walked here.
#[test]
fn the_model_agrees_across_every_admission_corner() {
    for required in [false, true] {
        for admit in [false, true] {
            // The schema refuses admitted_programs without required, on the
            // grounds that it would admit unknown programs with nothing
            // bounding them. That corner is unreachable, not untested.
            if admit && !required {
                continue;
            }
            for evidence in [false, true] {
                assert_agrees(
                    &format!("required={required} admit={admit} evidence={evidence}"),
                    &policy_with_effects(required, admit),
                    &unknown_program_facts(evidence),
                );
            }
        }
    }
}

/// A program the operator never named must still be refused by both, whatever
/// the effects policy says. The positive control for the case above.
#[test]
fn an_unnamed_program_is_refused_by_both() {
    let policy = policy_with_effects(true, false);
    let facts = unknown_program_facts(true);
    let engine = evaluate(&policy, &facts).verdict;
    assert_ne!(
        engine,
        safe_hands_core::policy::Verdict::Allow,
        "a program the operator never admitted must not be allowed"
    );
    assert_agrees("unnamed program", &policy, &facts);
}

/// An unlisted instruction from a *known* program — the other field the
/// existing agreement tests never reach, because their instruction list is
/// fixed.
#[test]
fn the_model_agrees_on_an_unlisted_instruction() {
    let policy = policy_with_effects(false, false);
    let mut facts = unknown_program_facts(false);
    facts.instructions = vec![IxFact {
        program: "system".into(),
        name: Some("assign".into()),
    }];
    assert_agrees("unlisted instruction on a known program", &policy, &facts);
}
