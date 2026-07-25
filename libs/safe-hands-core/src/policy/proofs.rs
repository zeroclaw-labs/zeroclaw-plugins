//! Machine-checked proofs of the authorization invariants.
//!
//! The test suite checks that the engine refuses the cases we thought of.
//! These harnesses check that it refuses cases *nobody* thought of: Kani
//! explores the decision space symbolically and reports a concrete
//! counterexample if any input reaches `ALLOW` when it must not.
//!
//! Run them (Linux/macOS; Kani has no Windows build):
//!
//! ```sh
//! cargo kani --manifest-path libs/safe-hands-core/Cargo.toml
//! ```
//!
//! **What is symbolic:** every boolean risk flag, the nonce-account class, the
//! presence of an intent, and the amount — chosen over the cap boundary and
//! the `u128` extremes.
//!
//! **What is concrete:** the policy document and the addresses. Intent binding
//! compares a decimal *string* to the transfer amount, so a fully symbolic
//! `u128` would force Kani to reason about symbolic-length string formatting.
//! Pinning the amounts to `{cap-1, cap, cap+1, 0, u128::MAX}` keeps the strings
//! concrete while still covering the boundary, which is where an off-by-one in
//! a spend cap would actually live.

use super::*;

const ALLOWED: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const ATTACKER: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const NONCE_OK: &str = "41bWd8Nqz6oLBKUdVwWPDP27NgFsvXM7V2sCoYRCo5Th";
const NONCE_BAD: &str = "So11111111111111111111111111111111111111112";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const CAP: u128 = 25_000_000;

fn proof_policy() -> Policy {
    Policy::from_json(&format!(
        r#"{{"version":"1.0.0","default_action":"deny",
        "assets":{{"{USDC}":{{"decimals":6,"max_per_tx_raw":"{CAP}"}}}},
        "allowed_recipients":["{ALLOWED}"],
        "allowed_nonce_accounts":["{NONCE_OK}"],
        "allowed_instructions":{{"spl_token":["transfer_checked"],
                                 "associated_token":["create_idempotent"],
                                 "system":["advance_nonce"],"memo":["memo"]}},
        "unknown_program":"deny","unknown_instruction":"deny",
        "missing_intent":"review","durable_nonce":"review",
        "token_2022":{{"permanent_delegate":"deny","transfer_hook":"deny",
                       "transfer_fee":"deny","default_frozen":"deny"}},
        "simulation":{{"required":true,"max_slot_age":32}}}}"#
    ))
    .expect("proof policy parses")
}

/// Symbolic choice over the amounts where a cap bug would hide.
fn symbolic_amount() -> (u128, &'static str) {
    match kani::any::<u8>() % 5 {
        0 => (CAP - 1, "24999999"),
        1 => (CAP, "25000000"),
        2 => (CAP + 1, "25000001"),
        3 => (0, "0"),
        _ => (
            u128::MAX,
            "340282366920938463463374607431768211455",
        ),
    }
}

/// A fact set whose every decision-relevant field is symbolic, carrying an
/// intent that genuinely matches the transfer — so nothing but the rule under
/// test can be what blocks `ALLOW`. Without this the proofs would pass
/// vacuously on a missing-intent review.
fn symbolic_facts(recipient: &str) -> TxFacts {
    let (amount_raw, amount_str) = symbolic_amount();

    TxFacts {
        signed: kani::any(),
        durable_nonce_used: kani::any(),
        authority_change: kani::any(),
        nonce_is_first_instruction: kani::any(),
        simulation_ok: kani::any(),
        byte_len: 1024,
        nonce_account: match kani::any::<u8>() % 3 {
            0 => Some(NONCE_OK.to_string()),
            1 => Some(NONCE_BAD.to_string()),
            _ => None,
        },
        token2022: Token2022Flags {
            permanent_delegate: kani::any(),
            transfer_hook: kani::any(),
            transfer_fee: kani::any(),
            default_frozen: kani::any(),
        },
        transfers: vec![TransferFact {
            mint: Some(USDC.to_string()),
            amount_raw,
            recipient: recipient.to_string(),
        }],
        intent: Some(Intent {
            action: "spl_transfer".to_string(),
            mint: Some(USDC.to_string()),
            amount_raw: amount_str.to_string(),
            recipient: recipient.to_string(),
            memo: None,
        }),
        ..TxFacts::default()
    }
}

/// **No input makes the engine pay an address the operator never allowlisted.**
///
/// This is the invariant the whole product rests on, and the one a prompt
/// injection would have to break. Everything else about the transaction is
/// symbolic and the intent matches perfectly — only the recipient is wrong.
#[kani::proof]
#[kani::unwind(4)]
fn unlisted_recipient_is_never_allowed() {
    let report = evaluate(&proof_policy(), &symbolic_facts(ATTACKER));
    assert!(report.verdict != Verdict::Allow);
}

/// **No amount above the per-transaction cap is ever allowed**, including at
/// the exact boundary and at `u128::MAX`.
#[kani::proof]
#[kani::unwind(4)]
fn over_cap_is_never_allowed() {
    let facts = symbolic_facts(ALLOWED);
    kani::assume(facts.transfers[0].amount_raw > CAP);
    let report = evaluate(&proof_policy(), &facts);
    assert!(report.verdict != Verdict::Allow);
}

/// **An already-signed transaction is never allowed.** The engine authorizes
/// drafts; anything carrying signatures has escaped the unsigned invariant.
#[kani::proof]
#[kani::unwind(4)]
fn signed_input_is_never_allowed() {
    let mut facts = symbolic_facts(ALLOWED);
    facts.signed = true;
    let report = evaluate(&proof_policy(), &facts);
    assert!(report.verdict != Verdict::Allow);
}

/// **A durable-nonce transaction reaches `ALLOW` only with both operator
/// opt-ins present**: an allowlisted nonce account, and `AdvanceNonceAccount`
/// genuinely at instruction zero. Either one missing must block it.
#[kani::proof]
#[kani::unwind(4)]
fn durable_nonce_needs_both_opt_ins() {
    let facts = symbolic_facts(ALLOWED);
    kani::assume(facts.durable_nonce_used);
    let allowlisted = facts.nonce_account.as_deref() == Some(NONCE_OK);
    kani::assume(!allowlisted || !facts.nonce_is_first_instruction);
    let report = evaluate(&proof_policy(), &facts);
    assert!(report.verdict != Verdict::Allow);
}

/// **Any Token-2022 extension flag keeps a transfer away from `ALLOW`.**
#[kani::proof]
#[kani::unwind(4)]
fn token_2022_extensions_are_never_allowed() {
    let facts = symbolic_facts(ALLOWED);
    kani::assume(
        facts.token2022.permanent_delegate
            || facts.token2022.transfer_hook
            || facts.token2022.transfer_fee
            || facts.token2022.default_frozen,
    );
    let report = evaluate(&proof_policy(), &facts);
    assert!(report.verdict != Verdict::Allow);
}

/// **An authority-changing instruction is never allowed.**
#[kani::proof]
#[kani::unwind(4)]
fn authority_change_is_never_allowed() {
    let mut facts = symbolic_facts(ALLOWED);
    facts.authority_change = true;
    let report = evaluate(&proof_policy(), &facts);
    assert!(report.verdict != Verdict::Allow);
}

/// **The engine is total: no input panics.**
///
/// A panic inside an authorization path is not merely a crash — it is an
/// unhandled decision, and a caller that reads "no verdict" as "no objection"
/// fails open. Reaching the assertion at all is the property.
#[kani::proof]
#[kani::unwind(4)]
fn evaluate_is_total() {
    let recipient = if kani::any() { ALLOWED } else { ATTACKER };
    let report = evaluate(&proof_policy(), &symbolic_facts(recipient));
    assert!(matches!(
        report.verdict,
        Verdict::Allow | Verdict::Review | Verdict::Deny | Verdict::Unknown
    ));
}
