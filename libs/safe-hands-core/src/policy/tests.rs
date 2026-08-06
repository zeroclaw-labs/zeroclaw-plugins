//! Boundary matrix for the policy engine. Every rule, every edge, offline.

use super::*;
use proptest::prelude::*;

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
        memos: vec!["invoice-412".into()],
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
            memo: Some("invoice-412".into()),
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
fn safe_v01_hard_denies_token_2022_plain_classic_transfer_and_inner_squads() {
    let mut token_2022 = usdc_transfer(1_000, RECIP);
    token_2022.instructions[1] = IxFact {
        program: "token_2022".into(),
        name: Some("transfer_checked".into()),
    };
    let report = evaluate(&policy(), &token_2022);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|code| code == "SH-DENY-T22-060"));

    let mut plain = usdc_transfer(1_000, RECIP);
    plain.instructions[1].name = Some("transfer".into());
    let report = evaluate(&policy(), &plain);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|code| code == "SH-DENY-SPL-PLAIN-061"));

    let mut configured_to_allow_squads = policy();
    configured_to_allow_squads.allowed_instructions.insert(
        "squads".into(),
        std::iter::once("squads_ix".to_string()).collect(),
    );
    let mut nested_squads = usdc_transfer(1_000, RECIP);
    nested_squads.instructions.push(IxFact {
        program: "squads".into(),
        name: Some("squads_ix".into()),
    });
    let report = evaluate(&configured_to_allow_squads, &nested_squads);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|code| code == "SH-DENY-SQUADS-INNER-063"));
}

#[test]
fn intent_action_must_match_transfer_kind() {
    let mut spl_as_sol = usdc_transfer(1_000, RECIP);
    spl_as_sol.intent.as_mut().expect("intent").action = "transfer".into();
    let report = evaluate(&policy(), &spl_as_sol);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|code| code == "SH-INTENT-ACTION-034"));

    let mut sol = TxFacts {
        byte_len: 200,
        simulation_ok: true,
        instructions: vec![IxFact {
            program: "system".into(),
            name: Some("transfer".into()),
        }],
        transfers: vec![TransferFact {
            mint: None,
            amount_raw: 1,
            recipient: RECIP.into(),
        }],
        intent: Some(Intent {
            action: "spl_transfer".into(),
            mint: Some(USDC.into()),
            amount_raw: "1".into(),
            recipient: RECIP.into(),
            memo: None,
        }),
        ..Default::default()
    };
    assert_eq!(evaluate(&policy(), &sol).verdict, Verdict::Deny);
    sol.intent = Some(Intent {
        action: "transfer".into(),
        mint: None,
        amount_raw: "1".into(),
        recipient: RECIP.into(),
        memo: None,
    });
    assert_eq!(evaluate(&policy(), &sol).verdict, Verdict::Allow);
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
    assert!(r.reason_codes.iter().any(|c| c == "SH-DENY-SPL-IX-062"));
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

/// The nonce-account allowlist is what turns a durable transaction from
/// "refused" into "permitted". Without it, nothing changes — which is what
/// keeps every pre-existing policy behaving exactly as before.
fn policy_allowing_nonce(nonce: &str) -> Policy {
    let json = demo_policy_json().replace(
        r#""allowed_recipients""#,
        &format!(r#""allowed_nonce_accounts": ["{nonce}"], "allowed_recipients""#),
    );
    Policy::from_json(&json).expect("policy with a nonce allowlist parses")
}

#[test]
fn an_allowlisted_nonce_account_survives_the_approval_queue() {
    // This is the whole point: a human can take their time approving, because
    // the transaction's validity is pinned to the nonce, not a blockhash.
    let mut f = usdc_transfer(1_000, RECIP);
    f.durable_nonce_used = true;
    f.nonce_account = Some(OTHER.to_string());
    f.nonce_is_first_instruction = true;
    let r = evaluate(&policy_allowing_nonce(OTHER), &f);
    assert_eq!(r.verdict, Verdict::Allow, "codes: {:?}", r.reason_codes);
}

#[test]
fn a_nonce_account_the_operator_never_allowlisted_is_refused() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.durable_nonce_used = true;
    f.nonce_account = Some(RECIP.to_string()); // allowlisted as a recipient, not as a nonce
    f.nonce_is_first_instruction = true;
    let r = evaluate(&policy_allowing_nonce(OTHER), &f);
    assert_eq!(r.verdict, Verdict::Review);
    assert!(r
        .reason_codes
        .iter()
        .any(|c| c.starts_with("SH-REVIEW-NONCE")));
}

#[test]
fn an_unidentifiable_nonce_account_is_never_treated_as_permission() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.durable_nonce_used = true;
    f.nonce_account = None;
    f.nonce_is_first_instruction = true;
    let r = evaluate(&policy_allowing_nonce(OTHER), &f);
    assert_eq!(r.verdict, Verdict::Review);
}

#[test]
fn an_allowlisted_nonce_not_in_first_position_is_denied() {
    // The runtime requires AdvanceNonceAccount to be instruction 0. Emitting
    // one that is not first would produce a transaction that cannot land.
    let mut f = usdc_transfer(1_000, RECIP);
    f.durable_nonce_used = true;
    f.nonce_account = Some(OTHER.to_string());
    f.nonce_is_first_instruction = false;
    let r = evaluate(&policy_allowing_nonce(OTHER), &f);
    assert_eq!(r.verdict, Verdict::Deny);
    assert!(
        r.reason_codes.iter().any(|c| c == "SH-DENY-NONCE-011"),
        "codes: {:?}",
        r.reason_codes
    );
}

#[test]
fn a_policy_without_a_nonce_allowlist_behaves_exactly_as_before() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.durable_nonce_used = true;
    f.nonce_account = Some(OTHER.to_string());
    f.nonce_is_first_instruction = true;
    assert!(policy().allowed_nonce_accounts.is_empty());
    assert_eq!(evaluate(&policy(), &f).verdict, Verdict::Review);
}

// ── Mutants that survived `cargo mutants`, and the tests that kill them ─────
//
// Mutation testing injects a deliberate bug and reruns the suite. Four
// survived, meaning the suite could not tell the mutated engine from the real
// one. Both sites below are load-bearing, so both now have tests.

/// `cargo mutants` replaced `>` with `>=` and with `==` at the packet-size
/// check and nothing failed — the boundary was never pinned. 1232 bytes is
/// Solana's transaction MTU: exactly at the limit must pass, one over must
/// deny. An off-by-one here rejects legitimate maximum-size transactions.
#[test]
fn the_packet_size_limit_is_exact_at_the_boundary() {
    let policy = policy();
    let limit = policy.max_transaction_bytes;

    let mut at_limit = usdc_transfer(1_000, RECIP);
    at_limit.byte_len = limit;
    let report = evaluate(&policy, &at_limit);
    assert!(
        !report
            .reason_codes
            .iter()
            .any(|code| code.starts_with("SH-DENY-TOOBIG")),
        "a transaction of exactly {limit} bytes must not be refused for size: {:?}",
        report.reason_codes
    );

    let mut over_limit = usdc_transfer(1_000, RECIP);
    over_limit.byte_len = limit + 1;
    let report = evaluate(&policy, &over_limit);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "SH-DENY-TOOBIG-002"),
        "one byte over the limit must deny: {:?}",
        report.reason_codes
    );
}

/// `cargo mutants` made `Verdict::as_str` return `""` and `"xyzzy"` and the
/// suite passed. These strings are not cosmetic: `as_str` feeds the
/// `decision_id` hash that receipts commit to and that `--verify` re-derives,
/// and operators match on them. They are part of the wire contract.
#[test]
fn verdict_strings_are_part_of_the_wire_contract() {
    assert_eq!(Verdict::Allow.as_str(), "ALLOW");
    assert_eq!(Verdict::Review.as_str(), "REVIEW");
    assert_eq!(Verdict::Deny.as_str(), "DENY");
    assert_eq!(Verdict::Unknown.as_str(), "UNKNOWN");

    // All four must stay distinct, or two verdicts would hash alike.
    let all = [
        Verdict::Allow.as_str(),
        Verdict::Review.as_str(),
        Verdict::Deny.as_str(),
        Verdict::Unknown.as_str(),
    ];
    let unique: std::collections::BTreeSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len(), "verdict strings must be distinct");
    assert!(
        all.iter().all(|s| !s.is_empty()),
        "an empty verdict string would silently weaken every decision_id"
    );
}

/// `cargo mutants` replaced the instruction-allowlist membership check with
/// `true` and nothing failed: no test drove a *known* program carrying an
/// instruction the operator had not allowed. That is the entire
/// `unknown_instruction` rule, untested at the unit level.
#[test]
fn an_instruction_outside_the_allowlist_is_refused() {
    let mut facts = usdc_transfer(1_000, RECIP);
    facts.instructions.push(IxFact {
        program: "memo".to_string(),
        name: Some("set_authority_somehow".to_string()),
    });
    let report = evaluate(&policy(), &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "SH-DENY-IX-012"),
        "an unlisted instruction on a known program must deny: {:?}",
        report.reason_codes
    );
}

/// `cargo mutants` flipped `!=` to `==` on the classic-SPL guard and survived,
/// because under the demo policy `transfer_checked` is allowlisted either way.
/// It only matters for an operator who removes it: the real code falls through
/// to the allowlist and denies, the mutant skips the check and permits.
#[test]
fn removing_transfer_checked_from_the_allowlist_actually_denies_it() {
    let json = demo_policy_json().replace(
        r#""spl_token": ["transfer", "transfer_checked"]"#,
        r#""spl_token": []"#,
    );
    let restrictive = Policy::from_json(&json).expect("policy parses");

    let mut facts = usdc_transfer(1_000, RECIP);
    facts.instructions.push(IxFact {
        program: "spl_token".to_string(),
        name: Some("transfer_checked".to_string()),
    });
    let report = evaluate(&restrictive, &facts);
    assert_eq!(
        report.verdict,
        Verdict::Deny,
        "an operator who allowlists no SPL instruction must not get a transfer through: {:?}",
        report.reason_codes
    );
}

/// `cargo mutants` replaced the whole of `recipient_matches_intent` with
/// `true` and the suite passed: no unit test drove a transfer whose recipient
/// disagreed with the declared intent. The conformance arena covers it, but
/// mutation testing only reruns this crate's tests, and the gap was real here.
#[test]
fn a_transfer_to_someone_other_than_the_declared_recipient_denies() {
    let mut facts = usdc_transfer(1_000, RECIP);
    facts.transfers[0].recipient = OTHER.to_string();
    let report = evaluate(&policy(), &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code.starts_with("SH-INTENT-RECIPIENT")),
        "the bytes must be what the intent declared: {:?}",
        report.reason_codes
    );
}

/// The other half of that function: an intent naming a *wallet* is satisfied
/// by a transfer to that wallet's ATA for the mint. `cargo mutants` flipped
/// the ATA comparison and survived, so nothing pinned this behaviour.
#[test]
fn an_intent_naming_a_wallet_is_satisfied_by_its_ata() {
    let ata = crate::crypto::ata_address_str(RECIP, crate::crypto::TOKEN_PROGRAM, USDC)
        .expect("ATA derives");
    let mut facts = usdc_transfer(1_000, RECIP);
    facts.transfers[0].recipient = ata.clone();
    let report = evaluate(&policy(), &facts);
    assert_eq!(
        report.verdict,
        Verdict::Allow,
        "paying the ATA of the intended wallet is the same payment: {:?}",
        report.reason_codes
    );
    assert_ne!(
        ata, RECIP,
        "the ATA must differ from the wallet, or this proves nothing"
    );
}

/// `cargo mutants` flipped `&&` to `||` in the action/mint consistency check.
/// A transfer carrying a mint must be declared `spl_transfer` *with* a mint —
/// claiming a bare SOL `transfer` over an SPL transfer must not pass.
#[test]
fn the_declared_action_must_match_whether_a_mint_is_present() {
    let mut facts = usdc_transfer(1_000, RECIP);
    if let Some(intent) = facts.intent.as_mut() {
        intent.action = "transfer".to_string();
        intent.mint = None;
    }
    let report = evaluate(&policy(), &facts);
    assert_ne!(
        report.verdict,
        Verdict::Allow,
        "an SPL transfer declared as a bare SOL transfer must not be allowed: {:?}",
        report.reason_codes
    );
}

/// `cargo mutants` mutated the emptiness guard in `policy_from_config` three
/// ways and none failed. This is the fail-closed path every plugin depends on:
/// with no usable policy in host config, nothing may be authorized.
#[test]
fn a_missing_or_blank_policy_fails_closed() {
    use std::collections::HashMap;

    let mut config: HashMap<String, String> = HashMap::new();
    assert!(
        policy_from_config(&config).is_err(),
        "no policy_json at all must fail closed"
    );

    for blank in ["", "   ", "\n\t "] {
        config.insert("policy_json".to_string(), blank.to_string());
        assert!(
            policy_from_config(&config).is_err(),
            "a blank policy_json ({blank:?}) must fail closed, not parse as permissive"
        );
    }

    config.insert("policy_json".to_string(), demo_policy_json());
    assert!(
        policy_from_config(&config).is_ok(),
        "a real policy must still load"
    );
}

/// The bare-SOL arm of the same consistency check. A transfer with no mint
/// must be declared `transfer` *and* carry no mint in the intent; an intent
/// naming a mint over a SOL transfer is a mismatch. `cargo mutants` flipped
/// this `&&` to `||` and the SPL-side test above could not see it.
#[test]
fn a_sol_transfer_declared_with_a_mint_is_a_mismatch() {
    let mut facts = usdc_transfer(1_000, RECIP);
    facts.transfers[0].mint = None; // bare SOL on the wire...
    if let Some(intent) = facts.intent.as_mut() {
        intent.action = "transfer".to_string();
        intent.mint = Some(USDC.to_string()); // ...but the intent claims a mint
    }
    let report = evaluate(&policy(), &facts);
    assert_ne!(
        report.verdict,
        Verdict::Allow,
        "a SOL transfer whose intent names a mint must not be allowed: {:?}",
        report.reason_codes
    );
}

// ── The provable model must never disagree with production ─────────────────
//
// `resolved::verdict()` is a heap-free restatement of the same rules that a
// model checker can exhaust. It is only worth anything if it says the same
// thing as the engine operators actually run. These assert that, over the
// fixtures and over generated inputs.

/// Every hand-written scenario in this file, re-checked through the model.
#[test]
fn the_model_agrees_with_the_engine_on_every_shaped_case() {
    let policy = policy();
    let attacker = usdc_transfer(1_000, OTHER);
    let over_cap = usdc_transfer(999_000_000, RECIP);
    let mut signed = usdc_transfer(1_000, RECIP);
    signed.signed = true;
    let mut no_intent = usdc_transfer(1_000, RECIP);
    no_intent.intent = None;
    let mut nonce = usdc_transfer(1_000, RECIP);
    nonce.durable_nonce_used = true;
    nonce.nonce_account = Some(OTHER.to_string());
    let mut hooked = usdc_transfer(1_000, RECIP);
    hooked.token2022.transfer_hook = true;
    let mut unsimulated = usdc_transfer(1_000, RECIP);
    unsimulated.simulation_ok = false;
    let mut authority = usdc_transfer(1_000, RECIP);
    authority.authority_change = true;

    let cases = [
        ("clean", usdc_transfer(1_000, RECIP)),
        ("unlisted recipient", attacker),
        ("over cap", over_cap),
        ("signed", signed),
        ("no intent", no_intent),
        ("unlisted nonce", nonce),
        ("transfer hook", hooked),
        ("no simulation", unsimulated),
        ("authority change", authority),
    ];

    for (name, facts) in cases {
        let engine = evaluate(&policy, &facts).verdict;
        let model = resolved::resolve(&policy, &facts).verdict();
        assert_eq!(
            engine, model,
            "{name}: engine said {engine:?} but the model said {model:?}"
        );
    }
}

/// Property-test budget.
///
/// CI runs a gate, not a campaign: 512 cases keeps `just test` fast enough to
/// run on every change. A longer soak is a different job, and hard-coding the
/// count made it impossible to ask for one. `SH_PROPTEST_CASES=200000 cargo
/// test` runs the same properties for as long as you are willing to wait.
fn proptest_cases() -> u32 {
    std::env::var("SH_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// The same agreement, over inputs nobody chose.
    ///
    /// If this ever fails, the model has drifted from the engine and any proof
    /// against the model is worthless — which is exactly the failure mode a
    /// separate model invites, and exactly why it is checked continuously.
    #[test]
    fn the_model_agrees_with_the_engine_on_generated_facts(
        amount in 0u128..60_000_000,
        to_attacker in any::<bool>(),
        signed in any::<bool>(),
        authority_change in any::<bool>(),
        simulation_ok in any::<bool>(),
        durable_nonce_used in any::<bool>(),
        nonce_first in any::<bool>(),
        nonce_allowlisted in any::<bool>(),
        hook in any::<bool>(),
        fee in any::<bool>(),
        frozen in any::<bool>(),
        delegate in any::<bool>(),
        drop_intent in any::<bool>(),
        byte_len in 0usize..2000,
        // The effect layer, generated alongside everything else so the model
        // and the engine are compared over it too. A model that agreed only on
        // the paths it was written for would prove nothing about the rest.
        effects_known in any::<bool>(),
        effect_out in 0u128..60_000_000,
        effect_guarded in any::<bool>(),
        effect_asset_listed in any::<bool>(),
        effect_intent in any::<bool>(),
    ) {
        let recipient = if to_attacker { OTHER } else { RECIP };
        let mut facts = usdc_transfer(amount, recipient);
        facts.signed = signed;
        facts.authority_change = authority_change;
        facts.simulation_ok = simulation_ok;
        facts.durable_nonce_used = durable_nonce_used;
        facts.nonce_is_first_instruction = nonce_first;
        facts.nonce_account = Some(if nonce_allowlisted { OTHER } else { USDC }.to_string());
        facts.token2022.transfer_hook = hook;
        facts.token2022.transfer_fee = fee;
        facts.token2022.default_frozen = frozen;
        facts.token2022.permanent_delegate = delegate;
        facts.byte_len = byte_len;
        if drop_intent {
            facts.intent = None;
        }

        let unlisted = "So11111111111111111111111111111111111111112";
        if effects_known {
            facts.effects = Some(vec![crate::effects::Movement {
                owner: if effect_guarded { VAULT } else { OTHER }.into(),
                asset: if effect_asset_listed { USDC } else { unlisted }.into(),
                out_raw: effect_out,
                in_raw: 0,
            }]);
        }
        if effect_intent {
            facts.intent = Some(Intent {
                action: "effect".into(),
                mint: Some(if effect_asset_listed { USDC } else { unlisted }.into()),
                amount_raw: effect_out.to_string(),
                recipient: String::new(),
                memo: None,
            });
        }
        let subject = effects_policy(true);

        let engine = evaluate(&subject, &facts).verdict;
        let model = resolved::resolve(&subject, &facts).verdict();
        prop_assert_eq!(
            engine, model,
            "engine and model disagree on {:?}", facts
        );
    }
}

#[test]
fn authority_change_denies() {
    let mut f = usdc_transfer(1_000, RECIP);
    f.authority_change = true;
    let r = evaluate(&policy(), &f);
    assert_eq!(r.verdict, Verdict::Deny);
}

#[test]
fn token2022_instruction_denial_dominates_extension_policy() {
    let p = policy();
    let mut facts = usdc_transfer(1_000, RECIP);
    facts.instructions[1].program = "token_2022".into();
    facts.token2022.transfer_hook = true;
    let report = evaluate(&p, &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|code| code == "SH-DENY-T22-060"));
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
        memo: Some("invoice-412".into()),
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
fn configured_fee_policy_is_explicitly_unsupported_in_v01() {
    let with_fee = demo_policy_json().replace(
        "\"simulation\": {\"required\": true, \"max_slot_age\": 32}",
        "\"fee\": {\"max_priority_fee_lamports\": 1, \"max_transaction_fee_lamports\": 2, \"max_account_creation_lamports\": 3}, \"simulation\": {\"required\": true, \"max_slot_age\": 32}",
    );
    let error = Policy::from_json(&with_fee).expect_err("v0.1 fee config must fail closed");
    assert!(error.contains("unsupported in safe v0.1"), "{error}");
}

#[test]
fn memo_intent_requires_exact_value_and_cardinality() {
    let p = policy();
    let exact = usdc_transfer(1_000, RECIP);
    assert_eq!(evaluate(&p, &exact).verdict, Verdict::Allow);

    let mut absent_intent = exact.clone();
    absent_intent.intent.as_mut().unwrap().memo = None;
    let report = evaluate(&p, &absent_intent);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|code| code == "SH-INTENT-MEMO-035"));

    let mut wrong = exact.clone();
    wrong.intent.as_mut().unwrap().memo = Some("other".into());
    assert_eq!(evaluate(&p, &wrong).verdict, Verdict::Deny);

    let mut duplicate = exact;
    duplicate.memos.push("invoice-412".into());
    assert_eq!(evaluate(&p, &duplicate).verdict, Verdict::Deny);
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

#[test]
fn same_recipient_transfers_are_aggregated_for_cap_and_intent() {
    let mut facts = usdc_transfer(25_000_000, RECIP);
    facts.transfers.push(TransferFact {
        mint: Some(USDC.into()),
        amount_raw: 25_000_000,
        recipient: RECIP.into(),
    });

    let report = evaluate(&policy(), &facts);

    assert_eq!(report.verdict, Verdict::Deny);
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "SH-DENY-CAP-001"),
        "aggregate spend must exceed the per-transaction cap: {:?}",
        report.reason_codes
    );
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "SH-INTENT-AMOUNT-033"),
        "aggregate spend must exactly match declared intent: {:?}",
        report.reason_codes
    );
}

// --- Property-based security invariants -------------------------------------
// These assert the engine's guarantees hold across *ranges* of inputs, not just
// hand-picked cases: no combination of amounts, splits, or flags can coax an
// ALLOW out of a policy-violating transaction. This is the machine-checked
// backbone of the deny-by-default, fail-closed claim.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases()))]

    /// A single transfer at or under the per-tx cap, to the allowed recipient,
    /// with a matching intent and passing simulation, is always ALLOW.
    #[test]
    fn under_cap_matching_intent_allows(amount in 1u128..=25_000_000u128) {
        let r = evaluate(&policy(), &usdc_transfer(amount, RECIP));
        prop_assert_eq!(r.verdict, Verdict::Allow);
    }

    /// Split-transfer bypass is impossible: however a spend is fragmented across
    /// 1..8 transfers to the allowed recipient, if the aggregate exceeds the
    /// per-tx cap the verdict is never ALLOW — and the cap code is always cited.
    #[test]
    fn split_aggregate_over_cap_never_allows(
        amounts in prop::collection::vec(1u128..=25_000_000u128, 1..8)
    ) {
        // Construct the over-cap aggregate rather than rejecting draws that
        // miss it. `prop_assume!(sum > cap)` discards every single-transfer
        // draw and most small ones, so proptest hit its global reject budget
        // and aborted the moment this ran at more than a few hundred cases —
        // which meant this property, the backbone of the split-bypass claim,
        // could never be soaked. Topping the draw up keeps every transfer at
        // or under the per-tx cap, so the aggregate rule is still the only one
        // that can fire.
        let mut amounts = amounts;
        let drawn: u128 = amounts.iter().sum();
        if drawn <= 25_000_000u128 {
            amounts.push(25_000_000u128 - drawn + 1);
        }
        let sum: u128 = amounts.iter().sum();
        prop_assert!(sum > 25_000_000u128);
        let mut f = usdc_transfer(amounts[0], RECIP);
        f.transfers = amounts
            .iter()
            .map(|a| TransferFact {
                mint: Some(USDC.into()),
                amount_raw: *a,
                recipient: RECIP.into(),
            })
            .collect();
        // Declare the true aggregate so the intent check passes and CAP is the
        // sole reason the transaction cannot be ALLOW.
        f.intent = Some(Intent {
            action: "spl_transfer".into(),
            mint: Some(USDC.into()),
            amount_raw: sum.to_string(),
            recipient: RECIP.into(),
            memo: Some("invoice-412".into()),
        });
        let r = evaluate(&policy(), &f);
        prop_assert_ne!(r.verdict, Verdict::Allow);
        prop_assert!(r.reason_codes.iter().any(|c| c == "SH-DENY-CAP-001"));
    }

    /// A recipient outside the allowlist can never be ALLOW, at any amount.
    #[test]
    fn disallowed_recipient_never_allows(amount in 1u128..=25_000_000u128) {
        let r = evaluate(&policy(), &usdc_transfer(amount, OTHER));
        prop_assert_ne!(r.verdict, Verdict::Allow);
    }

    /// An authority change dominates every other signal: always DENY, whatever
    /// the amount, signed flag, nonce flag, or simulation state.
    #[test]
    fn authority_change_always_denies(
        amount in 0u128..50_000_000u128,
        signed in any::<bool>(),
        nonce in any::<bool>(),
        sim_ok in any::<bool>(),
    ) {
        let mut f = usdc_transfer(amount, RECIP);
        f.authority_change = true;
        f.signed = signed;
        f.durable_nonce_used = nonce;
        f.simulation_ok = sim_ok;
        prop_assert_eq!(evaluate(&policy(), &f).verdict, Verdict::Deny);
    }

    /// A signed (non-zeroed) payload can never be ALLOW under the unsigned
    /// invariant, regardless of amount.
    #[test]
    fn signed_input_never_allows(amount in 1u128..=25_000_000u128) {
        let mut f = usdc_transfer(amount, RECIP);
        f.signed = true;
        prop_assert_ne!(evaluate(&policy(), &f).verdict, Verdict::Allow);
    }

    /// The engine is a pure function: identical inputs yield an identical
    /// verdict and identical reason codes on every call (receipt determinism).
    #[test]
    fn evaluation_is_deterministic(
        amount in 0u128..60_000_000u128,
        signed in any::<bool>(),
        nonce in any::<bool>(),
    ) {
        let mut f = usdc_transfer(amount, RECIP);
        f.signed = signed;
        f.durable_nonce_used = nonce;
        let p = policy();
        let a = evaluate(&p, &f);
        let b = evaluate(&p, &f);
        prop_assert_eq!(a.verdict, b.verdict);
        prop_assert_eq!(a.reason_codes, b.reason_codes);
    }
}

// ── effects: authorization by what a transaction costs ──────────────────────
//
// The rules above reason about instructions the decoder recognizes. These
// reason about balances, which exist for every program — including the ones
// nobody has written yet, and the ones that move value through CPI where the
// instruction bytes show nothing at all.

const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const VAULT: &str = "D4dzFuEyWKyV7zTMCq9TqdMMGfJHTQAAhx7f3wkHdeJ2";

/// A policy that admits one unfamiliar program under explicit spending bounds.
fn effects_policy_json(admit: bool) -> String {
    let admitted = if admit {
        format!("\"admitted_programs\":[\"{JUPITER}\"],")
    } else {
        String::new()
    };
    let base = demo_policy_json();
    let effects = format!(
        "\"effects\":{{\"required\":true,\"guarded\":[\"{VAULT}\"],{admitted}\
         \"max_outflow_raw\":{{\"{USDC}\":\"25000000\",\"SOL\":\"10000000\"}}}},"
    );
    base.replacen('{', &format!("{{{effects}"), 1)
}

fn effects_policy(admit: bool) -> Policy {
    Policy::from_json(&effects_policy_json(admit)).expect("effects policy parses")
}

fn movement(owner: &str, asset: &str, out_raw: u128) -> crate::effects::Movement {
    crate::effects::Movement {
        owner: owner.into(),
        asset: asset.into(),
        out_raw,
        in_raw: 0,
    }
}

/// A call into a program the decoder cannot read, with an economic intent
/// rather than a transfer intent.
fn unknown_program_call(spend: u128) -> TxFacts {
    TxFacts {
        byte_len: 400,
        simulation_ok: true,
        instructions: vec![IxFact {
            program: format!("unknown:{JUPITER}"),
            name: None,
        }],
        effects: Some(vec![movement(VAULT, USDC, spend)]),
        intent: Some(Intent {
            action: "effect".into(),
            mint: Some(USDC.into()),
            amount_raw: spend.to_string(),
            recipient: String::new(),
            memo: None,
        }),
        ..TxFacts::default()
    }
}

/// The headline: a program the decoder has never seen, allowed because the
/// operator named it and the money it costs is inside the bound they wrote.
#[test]
fn an_admitted_program_within_its_bound_is_allowed() {
    let report = evaluate(&effects_policy(true), &unknown_program_call(20_000_000));
    assert_eq!(report.verdict, Verdict::Allow, "{:?}", report.reason_codes);
}

/// Admitting a program is not admitting an amount.
#[test]
fn an_admitted_program_over_its_bound_is_denied() {
    let report = evaluate(&effects_policy(true), &unknown_program_call(26_000_000));
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-DENY-EFFECT-070"));
}

/// Naming a program is half the permission; the other half is evidence.
///
/// With no evidence the admission does not apply, so the program falls back to
/// being simply unfamiliar — and this operator denies those. Two objections are
/// raised and the stricter wins, which is the whole point of deny-overrides.
#[test]
fn an_admitted_program_without_evidence_is_never_allowed() {
    let mut facts = unknown_program_call(1_000);
    facts.effects = None;
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Deny, "{:?}", report.reason_codes);
    assert!(
        report
            .reason_codes
            .iter()
            .any(|c| c == "SH-UNKNOWN-EFFECT-072"),
        "the missing evidence is still reported: {:?}",
        report.reason_codes
    );
    assert!(
        report
            .reason_codes
            .iter()
            .any(|c| c == "SH-DENY-PROGRAM-011"),
        "and the program is refused on its own terms: {:?}",
        report.reason_codes
    );
}

/// Effects do not admit programs the operator never named. Otherwise any
/// program that happened to stay under a cap would be permitted, which is a
/// blank cheque with a spending limit rather than an allowlist.
#[test]
fn effects_do_not_admit_a_program_the_operator_never_named() {
    let report = evaluate(&effects_policy(false), &unknown_program_call(1_000));
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-DENY-PROGRAM-011"));
}

/// An asset with no cap may not leave at all. Forgetting to list one must
/// refuse rather than permit — the difference between deny-by-default and
/// allow-by-omission.
#[test]
fn an_asset_with_no_cap_may_not_leave() {
    let mut facts = unknown_program_call(1_000);
    let unlisted = "So11111111111111111111111111111111111111112";
    facts.effects = Some(vec![movement(VAULT, unlisted, 1)]);
    facts.intent = Some(Intent {
        action: "effect".into(),
        mint: Some(unlisted.into()),
        amount_raw: "1".into(),
        recipient: String::new(),
        memo: None,
    });
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-DENY-EFFECT-071"));
}

/// Only the accounts the operator protects are bounded. A counterparty losing
/// value in a swap is the point of a swap.
#[test]
fn an_unguarded_owner_is_not_bounded() {
    let mut facts = unknown_program_call(1_000);
    facts.effects = Some(vec![movement(OTHER, USDC, u128::MAX)]);
    facts.intent = None;
    let mut policy = effects_policy(true);
    policy.missing_intent = Outcome::Review;
    let report = evaluate(&policy, &facts);
    assert_ne!(report.verdict, Verdict::Deny, "{:?}", report.reason_codes);
}

/// Receiving is never a violation. A swap that hands the vault more than it
/// gives up must not trip a spending bound.
#[test]
fn an_inflow_is_never_an_outflow() {
    let mut facts = unknown_program_call(1_000);
    facts.effects = Some(vec![
        movement(VAULT, USDC, 5_000_000),
        crate::effects::Movement {
            owner: VAULT.into(),
            asset: "So11111111111111111111111111111111111111112".into(),
            out_raw: 0,
            in_raw: u128::MAX,
        },
    ]);
    facts.intent = Some(Intent {
        action: "effect".into(),
        mint: Some(USDC.into()),
        amount_raw: "5000000".into(),
        recipient: String::new(),
        memo: None,
    });
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Allow, "{:?}", report.reason_codes);
}

// ── the effect intent ───────────────────────────────────────────────────────

/// The caller declares what the transaction should cost. Costing more than
/// that is a mismatch even when the policy cap would still permit it — the two
/// bounds are independent, and the tighter one wins.
#[test]
fn spending_more_than_declared_is_an_intent_mismatch() {
    let mut facts = unknown_program_call(20_000_000);
    facts.intent = Some(Intent {
        action: "effect".into(),
        mint: Some(USDC.into()),
        amount_raw: "1000000".into(),
        recipient: String::new(),
        memo: None,
    });
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-INTENT-EFFECT-AMOUNT-037"));
}

/// Spending less than declared is fine: the declaration is a ceiling, and a
/// swap that fills better than quoted must not be refused for it.
#[test]
fn spending_less_than_declared_is_allowed() {
    let mut facts = unknown_program_call(1_000_000);
    facts.intent = Some(Intent {
        action: "effect".into(),
        mint: Some(USDC.into()),
        amount_raw: "20000000".into(),
        recipient: String::new(),
        memo: None,
    });
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Allow, "{:?}", report.reason_codes);
}

/// Declaring one asset and moving another is the effect-layer version of
/// swapping the recipient — caught, but as a spend that never happened rather
/// than as a foreign asset, because the intent deliberately says nothing about
/// assets it did not name.
#[test]
fn moving_an_asset_the_caller_never_declared_is_a_mismatch() {
    let mut facts = unknown_program_call(1_000);
    facts.effects = Some(vec![movement(VAULT, "SOL", 1_000)]);
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-INTENT-EFFECT-AMOUNT-037"));
}

/// The fee is the reason the intent bounds only what it names.
///
/// Every transaction costs its payer lamports, so an effect intent that
/// objected to any unnamed asset would refuse every real transaction. The SOL
/// leg is bounded by the operator's own cap instead.
#[test]
fn the_unavoidable_fee_does_not_break_a_declared_spend() {
    let mut facts = unknown_program_call(20_000_000);
    facts.effects = Some(vec![
        movement(VAULT, USDC, 20_000_000),
        movement(VAULT, "SOL", 5_000),
    ]);
    assert_eq!(
        evaluate(&effects_policy(true), &facts).verdict,
        Verdict::Allow
    );

    // And the operator's SOL cap is what actually bounds it.
    facts.effects = Some(vec![
        movement(VAULT, USDC, 20_000_000),
        movement(VAULT, "SOL", 10_000_001),
    ]);
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-DENY-EFFECT-070"));
}

/// A declared spend that costs the guarded accounts nothing is not a match: it
/// means the transaction does something else, and the engine cannot say what.
#[test]
fn a_declared_spend_that_never_happens_is_a_mismatch() {
    let mut facts = unknown_program_call(1_000);
    facts.effects = Some(Vec::new());
    let report = evaluate(&effects_policy(true), &facts);
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-INTENT-EFFECT-AMOUNT-037"));
}

/// An effect intent with no effect evidence is missing evidence, not a
/// refusal — the same position as any other unavailable simulation.
///
/// Isolated with an operator who merely reviews unfamiliar programs, because
/// one who denies them would (correctly) drown the UNKNOWN in a DENY.
#[test]
fn an_effect_intent_without_evidence_is_unknown() {
    let mut policy = effects_policy(true);
    policy.unknown_program = Outcome::Review;
    let mut facts = unknown_program_call(1_000);
    facts.effects = None;
    let report = evaluate(&policy, &facts);
    assert_eq!(
        report.verdict,
        Verdict::Unknown,
        "{:?}",
        report.reason_codes
    );
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-UNKNOWN-EFFECT-072"));
}

// ── the layer stays inert unless asked for ─────────────────────────────────

/// Every policy written before this existed must behave exactly as it did.
#[test]
fn a_policy_without_an_effects_section_is_unaffected() {
    let plain = policy();
    assert!(plain.effects.is_none());
    let mut facts = usdc_transfer(1_000, RECIP);
    facts.effects = Some(vec![movement(VAULT, USDC, u128::MAX)]);
    assert_eq!(evaluate(&plain, &facts).verdict, Verdict::Allow);
}

/// A hard refusal cannot be talked out of by an effect that stayed in bounds.
/// Effects widen what unfamiliar programs may do; they never widen anything
/// else.
#[test]
fn effects_never_soften_a_hard_refusal() {
    let policy = effects_policy(true);
    for (name, mutate) in [
        (
            "authority change",
            Box::new(|f: &mut TxFacts| f.authority_change = true) as Box<dyn Fn(&mut TxFacts)>,
        ),
        ("signed input", Box::new(|f: &mut TxFacts| f.signed = true)),
        (
            "over byte limit",
            Box::new(|f: &mut TxFacts| f.byte_len = 100_000),
        ),
        (
            "token-2022 instruction",
            Box::new(|f: &mut TxFacts| {
                f.instructions.push(IxFact {
                    program: "token_2022".into(),
                    name: Some("transfer_checked".into()),
                })
            }),
        ),
    ] {
        let mut facts = unknown_program_call(1_000);
        mutate(&mut facts);
        assert_eq!(
            evaluate(&policy, &facts).verdict,
            Verdict::Deny,
            "effects softened: {name}"
        );
    }
}

// ── policy validation ───────────────────────────────────────────────────────

#[test]
fn an_effects_policy_that_protects_nobody_is_rejected() {
    let json = effects_policy_json(true).replace(&format!("[\"{VAULT}\"]"), "[]");
    let error = Policy::from_json(&json).expect_err("must be rejected");
    assert!(error.contains("guarded is empty"), "{error}");
}

#[test]
fn admitting_programs_without_enforcing_effects_is_rejected() {
    let json = effects_policy_json(true).replace("\"required\":true", "\"required\":false");
    let error = Policy::from_json(&json).expect_err("must be rejected");
    assert!(error.contains("admitted_programs"), "{error}");
}

#[test]
fn an_unreadable_cap_is_rejected_at_load_and_refuses_at_decision() {
    // Only the effects cap, not the asset cap that shares this number.
    let json = effects_policy_json(true).replace("\"25000000\",\"SOL\"", "\"twenty five\",\"SOL\"");
    let error = Policy::from_json(&json).expect_err("must be rejected");
    assert!(error.contains("not a raw integer"), "{error}");

    // And if one is ever constructed by hand anyway, it is a refusal rather
    // than an unbounded permission.
    let mut policy = effects_policy(true);
    policy
        .effects
        .as_mut()
        .expect("effects")
        .max_outflow_raw
        .insert(USDC.into(), "twenty five".into());
    let report = evaluate(&policy, &unknown_program_call(1));
    assert_eq!(report.verdict, Verdict::Deny);
    assert!(report
        .reason_codes
        .iter()
        .any(|c| c == "SH-DENY-EFFECT-071"));
}

/// **The canonical policy digest is pinned.**
///
/// `policy_sha256` is inside every `decision_id`, which is inside every receipt
/// and every link of the transparency log. If canonicalisation changes, every
/// decision ever recorded stops re-deriving at once — including the anchored
/// ones, which cannot be re-issued.
///
/// Adding the `effects` section broke exactly this, and it was found only
/// because the transparency-log tests replay a real receipt — a slow way to
/// learn it. This asserts it directly: an additive schema change an operator
/// did not opt into must be invisible to their digest.
#[test]
fn the_canonical_policy_digest_is_stable_across_additive_schema_changes() {
    let policy = policy();
    assert!(policy.effects.is_none());
    assert_eq!(
        policy.sha256(),
        "7b237b1f66e3e48ffdbe3ef8e5f4fc8add7d6edd13392258ee42f7411a0f6287",
        "canonicalisation changed — every receipt and every logged decision \
         computed against this policy has just become unverifiable"
    );

    // Opting in must change it, or the digest would not describe the policy.
    assert_ne!(effects_policy(true).sha256(), policy.sha256());
}
