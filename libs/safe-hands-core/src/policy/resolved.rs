//! A heap-free model of the authorization decision.
//!
//! # Why this exists
//!
//! `evaluate()` decides by walking `BTreeSet<String>` allowlists, `BTreeMap`
//! asset tables, and owned `String` addresses. That is the right shape for
//! production and the wrong shape for a model checker: Kani could not finish a
//! single proof against it, because CBMC has to symbolically model the
//! B-tree's node linking on every lookup. That is not a flaw in our harness —
//! it is Kani's own issue #1251, "Hang on BTreeMap and VecMap insertion",
//! open since 2022.
//!
//! So the decision is split in two:
//!
//! - [`resolve`] does all the collection and string work, turning a policy and
//!   a transaction into a flat set of answered questions. It allocates, it
//!   parses base58, it walks allowlists — and it makes no decisions.
//! - [`ResolvedFacts::verdict`] decides. It is `Copy`, contains nothing but
//!   `bool` and small enums, touches no heap, and is therefore something a
//!   model checker can exhaust rather than merely sample.
//!
//! The production path in `evaluate()` is untouched: it still produces the
//! reason codes operators read, in the order they have always been produced,
//! because that order is committed to by `decision_id`. What this adds is a
//! second, independent statement of the same rules that a machine can check —
//! and a property test asserting the two never disagree.
//!
//! That pairing is the technique AWS uses for Cedar in `cedar-spec`: rather
//! than verify the production authorizer directly, they check it against a
//! separate model on generated inputs. We arrived at the same answer from the
//! other direction, by watching CBMC fail to terminate.

use super::{Outcome, Policy, TxFacts, Verdict};

/// Every question the policy asks, already answered.
///
/// Deliberately `Copy` and heap-free. If a field here ever needs to be a
/// `String` or a collection, it belongs in [`resolve`] instead — the whole
/// value of this type is that a model checker can enumerate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedFacts {
    // 1. Signature state.
    pub unsigned_violation: bool,
    // 2. Packet bound.
    pub over_byte_limit: bool,
    // 3. Instruction invariants that operator config cannot relax.
    pub has_token_2022_instruction: bool,
    pub has_inner_squads_instruction: bool,
    pub has_plain_spl_transfer: bool,
    pub has_other_spl_instruction: bool,
    pub has_unknown_program: bool,
    pub unknown_program_outcome: Outcome,
    pub has_unlisted_instruction: bool,
    pub unknown_instruction_outcome: Outcome,
    // 4. Durable nonce.
    pub durable_nonce_used: bool,
    pub nonce_allowlisted: bool,
    pub nonce_is_first_instruction: bool,
    pub durable_nonce_outcome: Outcome,
    // 5. Authority change.
    pub authority_change: bool,
    // 6. Token-2022 extensions.
    pub t22_permanent_delegate: bool,
    pub t22_permanent_delegate_outcome: Outcome,
    pub t22_transfer_hook: bool,
    pub t22_transfer_hook_outcome: Outcome,
    pub t22_transfer_fee: bool,
    pub t22_transfer_fee_outcome: Outcome,
    pub t22_default_frozen: bool,
    pub t22_default_frozen_outcome: Outcome,
    // 7. Transfers.
    pub has_unlisted_recipient: bool,
    pub over_per_tx_cap: bool,
    pub has_unlisted_mint: bool,
    // 8. Fee/rent (unreachable through `Policy::from_json` in v0.1).
    pub over_fee_cap: bool,
    pub over_rent_cap: bool,
    // 9. Intent binding.
    pub intent_missing: bool,
    pub missing_intent_outcome: Outcome,
    pub intent_no_transfers: bool,
    pub intent_action_mismatch: bool,
    pub intent_recipient_mismatch: bool,
    pub intent_mint_mismatch: bool,
    pub intent_amount_mismatch: bool,
    pub intent_memo_mismatch: bool,
    // 10. Velocity.
    pub velocity_exceeded: bool,
    // 11. Simulation.
    pub simulation_missing: bool,
}

impl ResolvedFacts {
    /// A fact set with nothing wrong with it: the shape that earns `ALLOW`.
    pub fn clean() -> Self {
        Self {
            unsigned_violation: false,
            over_byte_limit: false,
            has_token_2022_instruction: false,
            has_inner_squads_instruction: false,
            has_plain_spl_transfer: false,
            has_other_spl_instruction: false,
            has_unknown_program: false,
            unknown_program_outcome: Outcome::Deny,
            has_unlisted_instruction: false,
            unknown_instruction_outcome: Outcome::Deny,
            durable_nonce_used: false,
            nonce_allowlisted: false,
            nonce_is_first_instruction: false,
            durable_nonce_outcome: Outcome::Review,
            authority_change: false,
            t22_permanent_delegate: false,
            t22_permanent_delegate_outcome: Outcome::Deny,
            t22_transfer_hook: false,
            t22_transfer_hook_outcome: Outcome::Deny,
            t22_transfer_fee: false,
            t22_transfer_fee_outcome: Outcome::Deny,
            t22_default_frozen: false,
            t22_default_frozen_outcome: Outcome::Deny,
            has_unlisted_recipient: false,
            over_per_tx_cap: false,
            has_unlisted_mint: false,
            over_fee_cap: false,
            over_rent_cap: false,
            intent_missing: false,
            missing_intent_outcome: Outcome::Review,
            intent_no_transfers: false,
            intent_action_mismatch: false,
            intent_recipient_mismatch: false,
            intent_mint_mismatch: false,
            intent_amount_mismatch: false,
            intent_memo_mismatch: false,
            velocity_exceeded: false,
            simulation_missing: false,
        }
    }

    /// Does any rule refuse outright?
    fn any_deny(&self) -> bool {
        let outcome_denies = |flag: bool, outcome: Outcome| flag && outcome == Outcome::Deny;

        self.unsigned_violation
            || self.over_byte_limit
            // Invariants operator configuration cannot relax.
            || self.has_token_2022_instruction
            || self.has_inner_squads_instruction
            || self.has_plain_spl_transfer
            || self.has_other_spl_instruction
            || self.authority_change
            || self.has_unlisted_recipient
            || self.over_per_tx_cap
            || self.has_unlisted_mint
            || self.over_fee_cap
            || self.over_rent_cap
            // A durable nonce the operator allowlisted is still refused when
            // AdvanceNonceAccount is not instruction zero: the runtime would
            // reject it, and a half-honored durable transaction is never
            // emitted.
            || (self.durable_nonce_used
                && self.nonce_allowlisted
                && !self.nonce_is_first_instruction)
            // Configurable outcomes.
            || outcome_denies(self.has_unknown_program, self.unknown_program_outcome)
            || outcome_denies(self.has_unlisted_instruction, self.unknown_instruction_outcome)
            || outcome_denies(
                self.durable_nonce_used && !self.nonce_allowlisted,
                self.durable_nonce_outcome,
            )
            || outcome_denies(self.t22_permanent_delegate, self.t22_permanent_delegate_outcome)
            || outcome_denies(self.t22_transfer_hook, self.t22_transfer_hook_outcome)
            || outcome_denies(self.t22_transfer_fee, self.t22_transfer_fee_outcome)
            || outcome_denies(self.t22_default_frozen, self.t22_default_frozen_outcome)
            || outcome_denies(self.intent_missing, self.missing_intent_outcome)
            // Intent binding is never configurable: the bytes must be what the
            // caller declared.
            || (!self.intent_missing
                && (self.intent_no_transfers
                    || self.intent_action_mismatch
                    || self.intent_recipient_mismatch
                    || self.intent_mint_mismatch
                    || self.intent_amount_mismatch
                    || self.intent_memo_mismatch))
    }

    /// Is any evidence missing or untrustworthy?
    fn any_unknown(&self) -> bool {
        self.simulation_missing
    }

    /// Does anything need a human?
    fn any_review(&self) -> bool {
        let outcome_reviews = |flag: bool, outcome: Outcome| flag && outcome == Outcome::Review;

        self.velocity_exceeded
            || outcome_reviews(self.has_unknown_program, self.unknown_program_outcome)
            || outcome_reviews(self.has_unlisted_instruction, self.unknown_instruction_outcome)
            || outcome_reviews(
                self.durable_nonce_used && !self.nonce_allowlisted,
                self.durable_nonce_outcome,
            )
            || outcome_reviews(self.t22_permanent_delegate, self.t22_permanent_delegate_outcome)
            || outcome_reviews(self.t22_transfer_hook, self.t22_transfer_hook_outcome)
            || outcome_reviews(self.t22_transfer_fee, self.t22_transfer_fee_outcome)
            || outcome_reviews(self.t22_default_frozen, self.t22_default_frozen_outcome)
            || outcome_reviews(self.intent_missing, self.missing_intent_outcome)
    }

    /// The rule-combining algorithm, named rather than left implicit in the
    /// order of statements: **deny overrides**, then unknown, then review, and
    /// `ALLOW` only when nothing objected at all.
    ///
    /// The precedence is what makes the engine fail closed. `Unknown` sitting
    /// above `Review` is deliberate: evidence we could not obtain is a worse
    /// position than evidence that merely needs a human, and must not be
    /// downgraded into a queue an operator might wave through.
    pub fn verdict(&self) -> Verdict {
        if self.any_deny() {
            Verdict::Deny
        } else if self.any_unknown() {
            Verdict::Unknown
        } else if self.any_review() {
            Verdict::Review
        } else {
            Verdict::Allow
        }
    }
}

/// Answer every policy question about this transaction.
///
/// All of the collection walking, base58 parsing, and string comparison lives
/// here. Nothing here decides anything.
pub fn resolve(policy: &Policy, facts: &TxFacts) -> ResolvedFacts {
    let mut r = ResolvedFacts {
        unsigned_violation: policy.require_unsigned && facts.signed,
        over_byte_limit: facts.byte_len > policy.max_transaction_bytes,
        unknown_program_outcome: policy.unknown_program,
        unknown_instruction_outcome: policy.unknown_instruction,
        durable_nonce_used: facts.durable_nonce_used,
        nonce_is_first_instruction: facts.nonce_is_first_instruction,
        durable_nonce_outcome: policy.durable_nonce,
        authority_change: facts.authority_change,
        t22_permanent_delegate: facts.token2022.permanent_delegate,
        t22_permanent_delegate_outcome: policy.token_2022.permanent_delegate,
        t22_transfer_hook: facts.token2022.transfer_hook,
        t22_transfer_hook_outcome: policy.token_2022.transfer_hook,
        t22_transfer_fee: facts.token2022.transfer_fee,
        t22_transfer_fee_outcome: policy.token_2022.transfer_fee,
        t22_default_frozen: facts.token2022.default_frozen,
        t22_default_frozen_outcome: policy.token_2022.default_frozen,
        missing_intent_outcome: policy.missing_intent,
        simulation_missing: policy.simulation.required && !facts.simulation_ok,
        ..ResolvedFacts::clean()
    };

    r.nonce_allowlisted = facts
        .nonce_account
        .as_ref()
        .is_some_and(|account| policy.allowed_nonce_accounts.contains(account));

    // 3. Instructions.
    for ix in &facts.instructions {
        if ix.program == "token_2022" {
            r.has_token_2022_instruction = true;
            continue;
        }
        if ix.program == "squads" {
            r.has_inner_squads_instruction = true;
            continue;
        }
        if ix.program == "spl_token" {
            match ix.name.as_deref() {
                Some("transfer_checked") => {}
                Some("transfer") => r.has_plain_spl_transfer = true,
                _ => r.has_other_spl_instruction = true,
            }
            if ix.name.as_deref() != Some("transfer_checked") {
                continue;
            }
        }
        if ix.program.starts_with("unknown:") {
            r.has_unknown_program = true;
            continue;
        }
        match (policy.allowed_instructions.get(&ix.program), &ix.name) {
            (Some(names), Some(name)) if names.contains(name) => {}
            _ => r.has_unlisted_instruction = true,
        }
    }

    // 7. Transfers, then per-asset aggregates.
    let mut asset_totals: std::collections::BTreeMap<String, Option<u128>> =
        std::collections::BTreeMap::new();
    for tr in &facts.transfers {
        if !super::recipient_allowed(policy, tr) {
            r.has_unlisted_recipient = true;
        }
        let asset_key = tr.mint.clone().unwrap_or_else(|| "SOL".to_string());
        let total = asset_totals.entry(asset_key).or_insert(Some(0));
        *total = total.and_then(|current| current.checked_add(tr.amount_raw));
    }
    for (asset_key, total) in &asset_totals {
        match (policy.assets.get(asset_key), total) {
            (Some(asset), Some(total)) => match asset.max_raw() {
                Ok(max) if *total <= max => {}
                _ => r.over_per_tx_cap = true,
            },
            (Some(_), None) => r.over_per_tx_cap = true,
            (None, _) => r.has_unlisted_mint = true,
        }
    }

    // 8. Fee/rent.
    if let Some(fee) = &policy.fee {
        r.over_fee_cap = facts.priority_fee_lamports > fee.max_priority_fee_lamports
            || facts.estimated_fee_lamports > fee.max_transaction_fee_lamports;
        r.over_rent_cap = facts.account_creation_lamports > fee.max_account_creation_lamports;
    }

    // 9. Intent binding.
    match &facts.intent {
        None => r.intent_missing = true,
        Some(intent) => {
            let intent_mint = intent.mint.clone().unwrap_or_else(|| "SOL".to_string());
            let intent_amount = intent.amount_raw.parse::<u128>();
            r.intent_no_transfers = facts.transfers.is_empty();
            // A transfer with no mint must be declared a bare `transfer` with
            // no mint; one carrying a mint must be declared `spl_transfer`
            // with a mint. An empty transfer list matches nothing.
            let action_matches = !facts.transfers.is_empty()
                && facts
                    .transfers
                    .iter()
                    .all(|transfer| match transfer.mint.as_ref() {
                        None => intent.action == "transfer" && intent.mint.is_none(),
                        Some(_) => intent.action == "spl_transfer" && intent.mint.is_some(),
                    });
            r.intent_action_mismatch = !action_matches;
            for tr in &facts.transfers {
                let tr_mint = tr.mint.clone().unwrap_or_else(|| "SOL".to_string());
                if !super::recipient_matches_intent(&intent.recipient, tr) {
                    r.intent_recipient_mismatch = true;
                }
                if tr_mint != intent_mint {
                    r.intent_mint_mismatch = true;
                }
            }
            let total = facts
                .transfers
                .iter()
                .try_fold(0u128, |sum, tr| sum.checked_add(tr.amount_raw));
            r.intent_amount_mismatch = !matches!(
                (intent_amount, total),
                (Ok(expected), Some(actual)) if expected == actual
            );
            r.intent_memo_mismatch = !matches!(
                (&intent.memo, facts.memos.as_slice()),
                (None, []) | (Some(_), [_])
            ) || match (&intent.memo, facts.memos.as_slice()) {
                (Some(expected), [actual]) => expected != actual,
                _ => false,
            };
        }
    }

    // 10. Velocity.
    if let Some(velocity) = &policy.velocity {
        r.velocity_exceeded = velocity.allow_count_so_far >= velocity.max_allow_per_hour;
    }

    r
}

#[cfg(kani)]
mod proofs;
