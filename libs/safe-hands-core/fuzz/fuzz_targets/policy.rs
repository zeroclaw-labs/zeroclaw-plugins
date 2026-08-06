#![no_main]
//! Coverage-guided fuzzing of the authorization engine.
//!
//! This is the harness the stalled Kani proofs were reaching for, run by a
//! tool that terminates. Kani could not finish because CBMC has to model
//! `BTreeSet<String>` node internals symbolically (its own issue #1251);
//! libFuzzer never symbolically executes anything, so the collections that
//! blocked verification cost nothing here.
//!
//! It asserts the invariant that matters most, over inputs a person would not
//! think to write: **the engine never returns ALLOW for a recipient the
//! operator did not allowlist.** Everything else about the transaction is
//! fuzzer-controlled — amounts across the whole `u128` range, every risk flag,
//! the presence and content of the intent.
//!
//! Weaker than a proof, because it explores rather than exhausts. Stronger
//! than a test, because nobody chose the inputs.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use safe_hands_core::policy::{evaluate, Policy, TransferFact, TxFacts, Verdict};

const ALLOWED: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const ATTACKER: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Fuzzer-controlled facts. The recipient is a choice between the allowlisted
/// wallet and an attacker's, so the invariant stays meaningful rather than
/// degenerating into "random base58 is never allowlisted".
#[derive(Arbitrary, Debug)]
struct Input {
    to_attacker: bool,
    amount_raw: u128,
    signed: bool,
    durable_nonce_used: bool,
    nonce_is_first_instruction: bool,
    authority_change: bool,
    simulation_ok: bool,
    byte_len: u16,
    with_mint: bool,
    with_intent: bool,
    permanent_delegate: bool,
    transfer_hook: bool,
    transfer_fee: bool,
    default_frozen: bool,
}

fn policy() -> Policy {
    Policy::from_json(&format!(
        r#"{{"version":"1.0.0","default_action":"deny",
        "assets":{{"{USDC}":{{"decimals":6,"max_per_tx_raw":"25000000"}}}},
        "allowed_recipients":["{ALLOWED}"],
        "allowed_instructions":{{"spl_token":["transfer_checked"],
                                 "associated_token":["create_idempotent"],"memo":["memo"]}},
        "unknown_program":"deny","unknown_instruction":"deny",
        "missing_intent":"review","durable_nonce":"deny",
        "token_2022":{{"permanent_delegate":"deny","transfer_hook":"deny",
                       "transfer_fee":"deny","default_frozen":"deny"}},
        "simulation":{{"required":true,"max_slot_age":32}}}}"#
    ))
    .expect("fuzz policy parses")
}

fuzz_target!(|input: Input| {
    let recipient = if input.to_attacker { ATTACKER } else { ALLOWED };

    let mut facts = TxFacts {
        signed: input.signed,
        durable_nonce_used: input.durable_nonce_used,
        nonce_is_first_instruction: input.nonce_is_first_instruction,
        authority_change: input.authority_change,
        simulation_ok: input.simulation_ok,
        byte_len: input.byte_len as usize,
        transfers: vec![TransferFact {
            mint: input.with_mint.then(|| USDC.to_string()),
            amount_raw: input.amount_raw,
            recipient: recipient.to_string(),
        }],
        ..TxFacts::default()
    };
    facts.token2022.permanent_delegate = input.permanent_delegate;
    facts.token2022.transfer_hook = input.transfer_hook;
    facts.token2022.transfer_fee = input.transfer_fee;
    facts.token2022.default_frozen = input.default_frozen;

    if input.with_intent {
        facts.intent = Some(safe_hands_core::policy::Intent {
            action: if input.with_mint { "spl_transfer" } else { "transfer" }.to_string(),
            mint: input.with_mint.then(|| USDC.to_string()),
            amount_raw: input.amount_raw.to_string(),
            recipient: recipient.to_string(),
            memo: None,
        });
    }

    let report = evaluate(&policy(), &facts);

    if input.to_attacker {
        assert_ne!(
            report.verdict,
            Verdict::Allow,
            "ALLOW for an unlisted recipient — facts: {facts:?}, reasons: {:?}",
            report.reason_codes
        );
    }

    if report.verdict == Verdict::Allow {
        // Anything allowed must have cleared every hard invariant.
        assert!(!facts.signed, "ALLOW for an already-signed transaction");
        assert!(!facts.authority_change, "ALLOW for an authority change");
        assert!(
            input.amount_raw <= 25_000_000,
            "ALLOW above the per-transaction cap: {}",
            input.amount_raw
        );
        assert!(
            !(input.permanent_delegate
                || input.transfer_hook
                || input.transfer_fee
                || input.default_frozen),
            "ALLOW with a Token-2022 extension present"
        );
    }
});
