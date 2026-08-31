//! Risk-scoring conformance: every flag, severity, band boundary and holder rule.
//!
//! The verdict an agent acts on is a deterministic function of chain state. These
//! tests pin each rule to the on-chain fact that must trigger it — so a refactor
//! can't silently downgrade a rug signal, and a "safe" verdict always means the
//! chain actually said safe.

use serde_json::{json, Value};
use solana_token_risk::risk::*;

const BURN: &str = "1nc1nerator11111111111111111111111111111111";

fn mint_resp(program: &str, mint_auth: Value, freeze_auth: Value, exts: Value) -> Value {
    json!({"result":{"value":{"data":{"parsed":{"info":{
        "decimals":6,"isInitialized":true,"supply":"1000000000000",
        "mintAuthority":mint_auth,"freezeAuthority":freeze_auth,"extensions":exts
    },"type":"mint"},"program":program},"owner":"x"}}})
}
fn clean() -> Value {
    mint_resp("spl-token", Value::Null, Value::Null, Value::Null)
}
fn facts(v: &Value) -> TokenFacts {
    parse_mint("Mint1", v).unwrap()
}
fn codes(r: &RiskReport) -> Vec<String> {
    r.flags.iter().map(|f| f.code.clone()).collect()
}
fn flag<'a>(r: &'a RiskReport, code: &str) -> &'a Flag {
    r.flags.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("missing flag {code}"))
}
fn ext(name: &str, state: Value) -> Value {
    json!([{ "extension": name, "state": state }])
}

// ── baseline ────────────────────────────────────────────────────────────────

#[test]
fn fully_renounced_spl_token_has_no_flags() {
    let r = assess(&facts(&clean()));
    assert!(r.flags.is_empty());
    assert_eq!(r.score, 0);
    assert_eq!(r.band, "MINIMAL");
}

#[test]
fn renounced_authorities_are_reported_as_reassuring_notes() {
    let r = assess(&facts(&clean()));
    assert!(r.notes.iter().any(|n| n.contains("Mint authority is renounced")));
    assert!(r.notes.iter().any(|n| n.contains("Freeze authority is renounced")));
}

#[test]
fn supply_and_decimals_are_parsed() {
    let f = facts(&clean());
    assert_eq!(f.decimals, 6);
    assert_eq!(f.raw_supply, 1_000_000_000_000u128);
    assert_eq!(f.ui_supply, 1_000_000.0);
}

// ── authorities ─────────────────────────────────────────────────────────────

#[test]
fn live_mint_authority_is_critical_and_names_the_holder() {
    let r = assess(&facts(&mint_resp("spl-token", json!("BossKey1"), Value::Null, Value::Null)));
    let f = flag(&r, "mint_authority_present");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.evidence.contains("BossKey1"));
    assert_eq!(r.band, "CRITICAL");
}

#[test]
fn live_freeze_authority_is_high_and_names_the_holder() {
    let r = assess(&facts(&mint_resp("spl-token", Value::Null, json!("Freezer1"), Value::Null)));
    let f = flag(&r, "freeze_authority_present");
    assert_eq!(f.severity, Severity::High);
    assert!(f.evidence.contains("Freezer1"));
    assert_eq!(r.band, "HIGH");
}

#[test]
fn both_authorities_live_stacks_the_score() {
    let r = assess(&facts(&mint_resp("spl-token", json!("A"), json!("B"), Value::Null)));
    assert_eq!(r.flags.len(), 2);
    assert_eq!(r.score, 60);
    assert_eq!(r.band, "CRITICAL");
}

#[test]
fn empty_string_authority_is_treated_as_renounced() {
    let r = assess(&facts(&mint_resp("spl-token", json!(""), Value::Null, Value::Null)));
    assert!(!codes(&r).contains(&"mint_authority_present".to_string()));
}

#[test]
fn uninitialized_mint_is_flagged() {
    let mut v = clean();
    v["result"]["value"]["data"]["parsed"]["info"]["isInitialized"] = json!(false);
    let r = assess(&facts(&v));
    let f = flag(&r, "mint_uninitialized");
    assert_eq!(f.severity, Severity::High);
}

// ── Token-2022 dangerous extensions ─────────────────────────────────────────

#[test]
fn transfer_hook_is_critical() {
    let v = mint_resp("spl-token-2022", Value::Null, Value::Null, ext("transferHook", json!({"programId":"p"})));
    let r = assess(&facts(&v));
    assert_eq!(flag(&r, "transfer_hook").severity, Severity::Critical);
    assert_eq!(r.band, "CRITICAL");
}

#[test]
fn permanent_delegate_is_critical() {
    let v = mint_resp("spl-token-2022", Value::Null, Value::Null, ext("permanentDelegate", json!({"delegate":"d"})));
    let r = assess(&facts(&v));
    assert_eq!(flag(&r, "permanent_delegate").severity, Severity::Critical);
}

#[test]
fn non_transferable_is_critical_and_scores_highest() {
    let v = mint_resp("spl-token-2022", Value::Null, Value::Null, ext("nonTransferable", Value::Null));
    let r = assess(&facts(&v));
    assert_eq!(flag(&r, "non_transferable").severity, Severity::Critical);
    assert_eq!(r.score, 45);
}

#[test]
fn default_account_state_frozen_is_flagged_high() {
    let v = mint_resp("spl-token-2022", Value::Null, Value::Null, ext("defaultAccountState", json!({"accountState":"frozen"})));
    let r = assess(&facts(&v));
    assert_eq!(flag(&r, "default_account_state_frozen").severity, Severity::High);
}

#[test]
fn default_account_state_initialized_is_not_flagged() {
    let v = mint_resp("spl-token-2022", Value::Null, Value::Null, ext("defaultAccountState", json!({"accountState":"initialized"})));
    let r = assess(&facts(&v));
    assert!(!codes(&r).contains(&"default_account_state_frozen".to_string()));
}

#[test]
fn mint_close_authority_is_medium() {
    let v = mint_resp("spl-token-2022", Value::Null, Value::Null, ext("mintCloseAuthority", json!({"closeAuthority":"c"})));
    let r = assess(&facts(&v));
    assert_eq!(flag(&r, "mint_close_authority").severity, Severity::Medium);
}

#[test]
fn dangerous_extensions_are_ignored_on_legacy_spl_token() {
    // The extension array only has meaning under Token-2022; a legacy mint that
    // somehow carries one must not be scored on it.
    let v = mint_resp("spl-token", Value::Null, Value::Null, ext("transferHook", json!({"programId":"p"})));
    let r = assess(&facts(&v));
    assert!(r.flags.is_empty());
}

#[test]
fn multiple_dangerous_extensions_stack_and_cap_at_100() {
    let exts = json!([
        {"extension":"transferHook","state":{"programId":"p"}},
        {"extension":"permanentDelegate","state":{"delegate":"d"}},
        {"extension":"nonTransferable","state":null}
    ]);
    let v = mint_resp("spl-token-2022", json!("A"), json!("B"), exts);
    let r = assess(&facts(&v));
    assert_eq!(r.score, 100, "score is capped");
    assert_eq!(r.band, "CRITICAL");
    assert!(r.flags.len() >= 5);
}

// ── transfer fee tiers ──────────────────────────────────────────────────────

fn fee(bps: u64, authority: Value) -> Value {
    mint_resp(
        "spl-token-2022",
        Value::Null,
        Value::Null,
        ext("transferFeeConfig", json!({
            "newerTransferFee": {"transferFeeBasisPoints": bps},
            "transferFeeConfigAuthority": authority
        })),
    )
}

#[test]
fn small_transfer_fee_is_low_severity() {
    let r = assess(&facts(&fee(50, Value::Null)));
    assert_eq!(flag(&r, "transfer_fee").severity, Severity::Low);
}

#[test]
fn medium_transfer_fee_is_medium_severity() {
    let r = assess(&facts(&fee(300, Value::Null)));
    assert_eq!(flag(&r, "transfer_fee").severity, Severity::Medium);
}

#[test]
fn large_transfer_fee_is_high_severity() {
    let r = assess(&facts(&fee(900, Value::Null)));
    assert_eq!(flag(&r, "transfer_fee").severity, Severity::High);
}

#[test]
fn transfer_fee_boundary_at_100_bps_stays_low() {
    assert_eq!(flag(&assess(&facts(&fee(100, Value::Null))), "transfer_fee").severity, Severity::Low);
    assert_eq!(flag(&assess(&facts(&fee(101, Value::Null))), "transfer_fee").severity, Severity::Medium);
}

#[test]
fn transfer_fee_boundary_at_500_bps_stays_medium() {
    assert_eq!(flag(&assess(&facts(&fee(500, Value::Null))), "transfer_fee").severity, Severity::Medium);
    assert_eq!(flag(&assess(&facts(&fee(501, Value::Null))), "transfer_fee").severity, Severity::High);
}

#[test]
fn a_live_fee_authority_adds_points_and_is_called_out() {
    let without = assess(&facts(&fee(300, Value::Null)));
    let with = assess(&facts(&fee(300, json!("FeeBoss"))));
    assert!(with.score > without.score, "a raisable fee is strictly worse");
    assert!(flag(&with, "transfer_fee").evidence.contains("can raise it"));
}

#[test]
fn transfer_fee_evidence_reports_the_basis_points() {
    let r = assess(&facts(&fee(275, Value::Null)));
    assert!(flag(&r, "transfer_fee").evidence.contains("275 bps"));
    assert!(flag(&r, "transfer_fee").title.contains("2.75%"));
}

#[test]
fn zero_transfer_fee_is_still_reported_but_lowest_tier() {
    let r = assess(&facts(&fee(0, Value::Null)));
    assert_eq!(flag(&r, "transfer_fee").severity, Severity::Low);
}

// ── banding ─────────────────────────────────────────────────────────────────

#[test]
fn a_single_critical_flag_forces_the_critical_band() {
    // Severity must not be averaged away by a low score.
    let v = mint_resp("spl-token-2022", Value::Null, Value::Null, ext("transferHook", json!({"programId":"p"})));
    let r = assess(&facts(&v));
    assert!(r.flags.iter().any(|f| f.severity == Severity::Critical));
    assert_eq!(r.band, "CRITICAL");
}

#[test]
fn a_lone_low_flag_yields_a_low_band() {
    let r = assess(&facts(&fee(10, Value::Null)));
    assert_eq!(r.band, "LOW");
}

#[test]
fn severity_ordering_is_total_and_ascending() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn severity_strings_are_stable_machine_readable_values() {
    assert_eq!(Severity::Info.as_str(), "info");
    assert_eq!(Severity::Low.as_str(), "low");
    assert_eq!(Severity::Medium.as_str(), "medium");
    assert_eq!(Severity::High.as_str(), "high");
    assert_eq!(Severity::Critical.as_str(), "critical");
}

#[test]
fn assessment_is_deterministic() {
    let f = facts(&mint_resp("spl-token", json!("A"), json!("B"), Value::Null));
    let a = assess(&f);
    let b = assess(&f);
    assert_eq!(a.score, b.score);
    assert_eq!(a.band, b.band);
    assert_eq!(codes(&a), codes(&b));
}

// ── holder concentration & owner classification ─────────────────────────────

fn with_holders(holders: Vec<Holder>) -> TokenFacts {
    let mut f = facts(&clean());
    f.holders_source_ok = true;
    f.top_holders = holders;
    f
}
fn holder(acct: &str, amt: f64, owner: Option<&str>, kind: OwnerKind) -> Holder {
    Holder { account: acct.into(), ui_amount: amt, owner: owner.map(|s| s.to_string()), kind }
}

#[test]
fn a_wallet_holding_most_of_supply_is_flagged() {
    // supply = 1,000,000 ui
    let f = with_holders(vec![holder("A", 700_000.0, Some("Whale"), OwnerKind::Wallet)]);
    let r = assess(&f);
    let c = flag(&r, "holder_concentration");
    assert_eq!(c.severity, Severity::Medium); // 70%
    assert!(c.evidence.contains("Whale"));
    assert!(c.title.contains("keypair wallet"));
}

#[test]
fn a_protocol_lp_vault_is_not_counted_as_a_whale() {
    let f = with_holders(vec![
        holder("Lp", 800_000.0, Some("LpVault"), OwnerKind::Protocol),
        holder("W", 50_000.0, Some("Small"), OwnerKind::Wallet),
    ]);
    let r = assess(&f);
    assert!(!codes(&r).contains(&"holder_concentration".to_string()));
    assert!(r.notes.iter().any(|n| n.contains("liquidity, not a wallet")));
}

#[test]
fn burned_supply_is_excluded_from_concentration() {
    let f = with_holders(vec![
        holder(BURN, 900_000.0, None, OwnerKind::Burn),
        holder("W", 50_000.0, Some("Small"), OwnerKind::Wallet),
    ]);
    let r = assess(&f);
    assert!(!codes(&r).contains(&"holder_concentration".to_string()));
}

#[test]
fn concentration_severity_scales_with_the_share() {
    let at = |pct: f64| {
        let f = with_holders(vec![holder("A", 10_000.0 * pct, Some("W"), OwnerKind::Wallet)]);
        assess(&f)
    };
    assert!(!codes(&at(20.0)).contains(&"holder_concentration".to_string()));
    assert_eq!(flag(&at(35.0), "holder_concentration").severity, Severity::Low);
    assert_eq!(flag(&at(60.0), "holder_concentration").severity, Severity::Medium);
    assert_eq!(flag(&at(95.0), "holder_concentration").severity, Severity::High);
}

#[test]
fn concentration_boundaries_are_inclusive_at_30_50_90() {
    let at = |pct: f64| {
        let f = with_holders(vec![holder("A", 10_000.0 * pct, Some("W"), OwnerKind::Wallet)]);
        assess(&f)
    };
    assert_eq!(flag(&at(30.0), "holder_concentration").severity, Severity::Low);
    assert_eq!(flag(&at(50.0), "holder_concentration").severity, Severity::Medium);
    assert_eq!(flag(&at(90.0), "holder_concentration").severity, Severity::High);
}

#[test]
fn an_unresolved_owner_is_treated_conservatively_as_a_possible_wallet() {
    let f = with_holders(vec![holder("A", 700_000.0, None, OwnerKind::Unknown)]);
    let r = assess(&f);
    let c = flag(&r, "holder_concentration");
    assert!(c.title.contains("owner unresolved"));
}

#[test]
fn top5_wallet_share_is_reported() {
    let f = with_holders(vec![
        holder("A", 300_000.0, Some("W1"), OwnerKind::Wallet),
        holder("B", 200_000.0, Some("W2"), OwnerKind::Wallet),
        holder("C", 100_000.0, Some("W3"), OwnerKind::Wallet),
    ]);
    let r = assess(&f);
    assert!(flag(&r, "holder_concentration").evidence.contains("top-5 wallets hold 60.0%"));
}

#[test]
fn missing_holder_data_is_explained_not_silently_dropped() {
    let r = assess(&facts(&clean()));
    assert!(r.notes.iter().any(|n| n.contains("getTokenLargestAccounts")));
}

#[test]
fn classify_owner_recognises_the_burn_address() {
    assert_eq!(classify_owner(BURN), OwnerKind::Burn);
}

#[test]
fn classify_owner_rejects_undecodable_input_without_panicking() {
    assert_eq!(classify_owner("not-a-key"), OwnerKind::Unknown);
    assert_eq!(classify_owner(""), OwnerKind::Unknown);
    assert_eq!(is_on_curve("!!!"), None);
}

#[test]
fn classify_owner_labels_a_decodable_key_as_wallet_or_protocol() {
    let k = classify_owner("So11111111111111111111111111111111111111112");
    assert!(k == OwnerKind::Wallet || k == OwnerKind::Protocol);
    assert!(is_on_curve("So11111111111111111111111111111111111111112").is_some());
}

#[test]
fn apply_largest_sorts_holders_descending_and_marks_burn() {
    let mut f = facts(&clean());
    let largest = json!({"result":{"value":[
        {"address":"small","uiAmount":10.0},
        {"address":BURN,"uiAmount":50.0},
        {"address":"big","uiAmount":900.0}
    ]}});
    apply_largest(&mut f, &largest);
    assert!(f.holders_source_ok);
    assert_eq!(f.top_holders[0].account, "big");
    assert_eq!(f.top_holders[1].ui_amount, 50.0);
    assert_eq!(f.top_holders[1].kind, OwnerKind::Burn);
}

#[test]
fn apply_largest_accepts_ui_amount_string_form() {
    let mut f = facts(&clean());
    let largest = json!({"result":{"value":[{"address":"a","uiAmountString":"12.5"}]}});
    apply_largest(&mut f, &largest);
    assert_eq!(f.top_holders[0].ui_amount, 12.5);
}

#[test]
fn apply_largest_tolerates_an_error_response() {
    let mut f = facts(&clean());
    apply_largest(&mut f, &json!({"error":{"code":429,"message":"rate limited"}}));
    assert!(!f.holders_source_ok, "a throttled RPC must not fake holder data");
}

#[test]
fn set_owner_attaches_and_reclassifies() {
    let mut f = with_holders(vec![holder("acct1", 1.0, None, OwnerKind::Unknown)]);
    f.set_owner("acct1", BURN);
    assert_eq!(f.top_holders[0].kind, OwnerKind::Burn);
    assert_eq!(f.top_holders[0].owner.as_deref(), Some(BURN));
}

// ── parse robustness ────────────────────────────────────────────────────────

#[test]
fn parse_rejects_a_missing_account() {
    assert!(parse_mint("x", &json!({"result":{"value":null}})).is_err());
}

#[test]
fn parse_rejects_a_non_mint_account() {
    let v = json!({"result":{"value":{"data":{"parsed":{"type":"account","info":{}},"program":"spl-token"}}}});
    let e = parse_mint("x", &v).unwrap_err();
    assert!(e.contains("not a token `mint`"));
}

#[test]
fn parse_rejects_non_json_parsed_encoding() {
    let v = json!({"result":{"value":{"data":["base64blob","base64"]}}});
    assert!(parse_mint("x", &v).is_err());
}

#[test]
fn parse_rejects_an_account_without_data() {
    assert!(parse_mint("x", &json!({"result":{"value":{"lamports":1}}})).is_err());
}

#[test]
fn parse_accepts_a_bare_result_without_the_rpc_envelope() {
    let inner = json!({"value":{"data":{"parsed":{"info":{
        "decimals":9,"isInitialized":true,"supply":"5","mintAuthority":null,"freezeAuthority":null
    },"type":"mint"},"program":"spl-token"}}});
    assert_eq!(parse_mint("x", &inner).unwrap().decimals, 9);
}

#[test]
fn parse_defaults_a_missing_supply_to_zero_without_panicking() {
    let mut v = clean();
    v["result"]["value"]["data"]["parsed"]["info"]["supply"] = Value::Null;
    let f = parse_mint("x", &v).unwrap();
    assert_eq!(f.raw_supply, 0);
    assert_eq!(f.ui_supply, 0.0);
}

#[test]
fn zero_supply_skips_concentration_without_dividing_by_zero() {
    let mut v = clean();
    v["result"]["value"]["data"]["parsed"]["info"]["supply"] = json!("0");
    let mut f = parse_mint("x", &v).unwrap();
    f.holders_source_ok = true;
    f.top_holders = vec![holder("A", 1.0, Some("W"), OwnerKind::Wallet)];
    let r = assess(&f);
    assert!(!codes(&r).contains(&"holder_concentration".to_string()));
}

#[test]
fn parse_reads_the_token_program_variant() {
    assert_eq!(facts(&clean()).program, "spl-token");
    let t22 = mint_resp("spl-token-2022", Value::Null, Value::Null, Value::Null);
    assert_eq!(facts(&t22).program, "spl-token-2022");
}

#[test]
fn parse_collects_every_declared_extension() {
    let exts = json!([
        {"extension":"transferHook","state":{"programId":"p"}},
        {"extension":"mintCloseAuthority","state":{"closeAuthority":"c"}}
    ]);
    let f = facts(&mint_resp("spl-token-2022", Value::Null, Value::Null, exts));
    assert_eq!(f.extensions.len(), 2);
}

#[test]
fn every_flag_carries_non_empty_evidence_and_a_title() {
    let exts = json!([
        {"extension":"transferHook","state":{"programId":"p"}},
        {"extension":"transferFeeConfig","state":{"newerTransferFee":{"transferFeeBasisPoints":700}}}
    ]);
    let v = mint_resp("spl-token-2022", json!("A"), json!("B"), exts);
    let r = assess(&facts(&v));
    assert!(!r.flags.is_empty());
    for f in &r.flags {
        assert!(!f.title.is_empty(), "{} has no title", f.code);
        assert!(!f.evidence.is_empty(), "{} has no evidence", f.code);
        assert!(f.points > 0, "{} scores nothing", f.code);
    }
}

#[test]
fn agent_verdict_maps_bands_to_red_amber_green() {
    use solana_token_risk::handler::agent_verdict;
    assert_eq!(agent_verdict("CRITICAL"), "RED");
    assert_eq!(agent_verdict("HIGH"), "RED");
    assert_eq!(agent_verdict("MEDIUM"), "AMBER");
    assert_eq!(agent_verdict("LOW"), "GREEN");
    assert_eq!(agent_verdict("MINIMAL"), "GREEN");
}
