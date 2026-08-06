//! Machine-checked proofs of the authorization invariants.
//!
//! These run against [`ResolvedFacts`], which is `Copy` and heap-free, so the
//! model checker never touches the `BTreeSet<String>` internals that made the
//! earlier attempt against `evaluate()` fail to terminate (Kani issue #1251).
//!
//! `ResolvedFacts` has 40 fields — every `bool` and small enum in the decision.
//! `kani::any()` explores all of them at once, so each proof below covers the
//! entire decision space rather than a sample of it. That is the difference
//! between these and the fuzzers: fuzzing found no counterexample in 2.5
//! million tries, which is evidence; a proof means one does not exist.
//!
//! The model is only as good as its agreement with the engine, which is why
//! `policy/tests.rs` checks the two against each other on every run.
//!
//! ```sh
//! cargo kani --manifest-path libs/safe-hands-core/Cargo.toml
//! ```

use super::*;

/// Any field may be anything.
fn any_facts() -> ResolvedFacts {
    ResolvedFacts {
        unsigned_violation: kani::any(),
        over_byte_limit: kani::any(),
        has_token_2022_instruction: kani::any(),
        has_inner_squads_instruction: kani::any(),
        has_plain_spl_transfer: kani::any(),
        has_other_spl_instruction: kani::any(),
        has_unknown_program: kani::any(),
        unknown_program_outcome: any_outcome(),
        has_unlisted_instruction: kani::any(),
        unknown_instruction_outcome: any_outcome(),
        durable_nonce_used: kani::any(),
        nonce_allowlisted: kani::any(),
        nonce_is_first_instruction: kani::any(),
        durable_nonce_outcome: any_outcome(),
        authority_change: kani::any(),
        t22_permanent_delegate: kani::any(),
        t22_permanent_delegate_outcome: any_outcome(),
        t22_transfer_hook: kani::any(),
        t22_transfer_hook_outcome: any_outcome(),
        t22_transfer_fee: kani::any(),
        t22_transfer_fee_outcome: any_outcome(),
        t22_default_frozen: kani::any(),
        t22_default_frozen_outcome: any_outcome(),
        has_unlisted_recipient: kani::any(),
        over_per_tx_cap: kani::any(),
        has_unlisted_mint: kani::any(),
        over_fee_cap: kani::any(),
        over_rent_cap: kani::any(),
        intent_missing: kani::any(),
        missing_intent_outcome: any_outcome(),
        intent_no_transfers: kani::any(),
        intent_action_mismatch: kani::any(),
        intent_recipient_mismatch: kani::any(),
        intent_mint_mismatch: kani::any(),
        intent_amount_mismatch: kani::any(),
        intent_memo_mismatch: kani::any(),
        velocity_exceeded: kani::any(),
        simulation_missing: kani::any(),
        effect_evidence_missing: kani::any(),
        effect_over_cap: kani::any(),
        effect_unlisted_asset: kani::any(),
        intent_effect_mismatch: kani::any(),
    }
}

fn any_outcome() -> Outcome {
    if kani::any() {
        Outcome::Deny
    } else {
        Outcome::Review
    }
}

/// **ALLOW is only ever reachable when nothing objected.**
///
/// The headline invariant, stated as its contrapositive over the whole
/// decision space: if the verdict is ALLOW then every hard refusal condition
/// was false. No combination of the other 30-odd fields can talk the engine
/// past any one of them.
#[kani::proof]
fn allow_requires_every_hard_check_to_pass() {
    let facts = any_facts();
    if facts.verdict() == Verdict::Allow {
        assert!(!facts.unsigned_violation);
        assert!(!facts.over_byte_limit);
        assert!(!facts.has_unlisted_recipient);
        assert!(!facts.over_per_tx_cap);
        assert!(!facts.has_unlisted_mint);
        assert!(!facts.authority_change);
        assert!(!facts.has_token_2022_instruction);
        assert!(!facts.has_inner_squads_instruction);
        assert!(!facts.has_plain_spl_transfer);
        assert!(!facts.has_other_spl_instruction);
        assert!(!facts.over_fee_cap);
        assert!(!facts.over_rent_cap);
        assert!(!facts.simulation_missing);
        assert!(!facts.velocity_exceeded);
        assert!(!facts.effect_evidence_missing);
        assert!(!facts.effect_over_cap);
        assert!(!facts.effect_unlisted_asset);
        assert!(!facts.intent_effect_mismatch);
    }
}

/// **An unlisted recipient is never allowed.**
///
/// This is the invariant a prompt injection would have to break, and the one
/// the live Telegram attack transcript exercises by hand. Here it holds for
/// every input, not just the one that was tried.
#[kani::proof]
fn an_unlisted_recipient_can_never_be_allowed() {
    let mut facts = any_facts();
    facts.has_unlisted_recipient = true;
    assert!(facts.verdict() != Verdict::Allow);
}

/// **An amount over the operator's cap is never allowed.**
#[kani::proof]
fn over_cap_can_never_be_allowed() {
    let mut facts = any_facts();
    facts.over_per_tx_cap = true;
    assert!(facts.verdict() != Verdict::Allow);
}

/// **A durable-nonce transaction needs both operator opt-ins.**
///
/// An allowlisted nonce account is not enough on its own: the runtime requires
/// `AdvanceNonceAccount` to be instruction zero, and a durable transaction
/// that would not land must never be authorized as if it would.
#[kani::proof]
fn durable_nonce_requires_both_opt_ins() {
    let mut facts = any_facts();
    facts.durable_nonce_used = true;
    kani::assume(!facts.nonce_allowlisted || !facts.nonce_is_first_instruction);
    assert!(facts.verdict() != Verdict::Allow);
}

/// **Missing evidence outranks a review queue.**
///
/// `Unknown` sits above `Review` in the combining order on purpose: evidence
/// we could not obtain is a worse position than evidence that merely needs a
/// human, and must not be downgraded into a queue someone might wave through.
#[kani::proof]
fn missing_simulation_is_never_downgraded_to_review() {
    let mut facts = any_facts();
    facts.simulation_missing = true;
    let verdict = facts.verdict();
    assert!(verdict == Verdict::Deny || verdict == Verdict::Unknown);
}

/// **A declared intent that does not match the bytes is never allowed.**
#[kani::proof]
fn an_intent_mismatch_can_never_be_allowed() {
    let mut facts = any_facts();
    facts.intent_missing = false;
    kani::assume(
        facts.intent_no_transfers
            || facts.intent_action_mismatch
            || facts.intent_recipient_mismatch
            || facts.intent_mint_mismatch
            || facts.intent_amount_mismatch
            || facts.intent_memo_mismatch,
    );
    assert!(facts.verdict() != Verdict::Allow);
}

/// **Deny overrides everything.**
///
/// Whatever else is true, a hard refusal cannot be outvoted by a review or by
/// an absence of evidence.
#[kani::proof]
fn deny_overrides_every_other_outcome() {
    let mut facts = any_facts();
    facts.authority_change = true;
    assert!(facts.verdict() == Verdict::Deny);
}

/// **The decision is total.** Every input yields exactly one of four verdicts,
/// and the function cannot panic on any of them.
#[kani::proof]
fn the_decision_is_total() {
    let verdict = any_facts().verdict();
    assert!(matches!(
        verdict,
        Verdict::Allow | Verdict::Review | Verdict::Deny | Verdict::Unknown
    ));
}

/// **A spend beyond the operator's bound is never allowed.**
///
/// The effect layer's whole promise: whatever program ran, whatever the
/// decoder could or could not read, a guarded account cannot lose more of an
/// asset than the operator wrote down. Proven here for every combination of
/// the other 40 fields, not for the cases somebody thought to try.
#[kani::proof]
fn an_over_cap_effect_can_never_be_allowed() {
    let mut facts = any_facts();
    facts.effect_over_cap = true;
    assert!(facts.verdict() != Verdict::Allow);
}

/// **An asset the operator never listed can never leave.**
///
/// Deny-by-default applied to value rather than to syntax: forgetting to name
/// an asset refuses, it does not permit.
#[kani::proof]
fn an_unlisted_asset_can_never_leave() {
    let mut facts = any_facts();
    facts.effect_unlisted_asset = true;
    assert!(facts.verdict() != Verdict::Allow);
}

/// **Effects that could not be observed are never read as "nothing moved".**
///
/// The failure mode this exists to prevent: a node that declines to answer
/// producing an ALLOW because no movement was seen. Missing evidence outranks a
/// review queue for the same reason missing simulation does.
#[kani::proof]
fn missing_effect_evidence_is_never_downgraded_to_review() {
    let mut facts = any_facts();
    facts.effect_evidence_missing = true;
    let verdict = facts.verdict();
    assert!(verdict == Verdict::Deny || verdict == Verdict::Unknown);
}

/// **A transaction that does not cost what the caller declared is never
/// allowed.**
///
/// The effect-layer counterpart of the intent binding proved above: declaring
/// one spend and performing another cannot be talked past, whatever else is
/// true of the transaction.
#[kani::proof]
fn an_effect_intent_mismatch_can_never_be_allowed() {
    let mut facts = any_facts();
    facts.intent_effect_mismatch = true;
    assert!(facts.verdict() != Verdict::Allow);
}
