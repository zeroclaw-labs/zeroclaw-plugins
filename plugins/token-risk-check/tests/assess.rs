//! Integration tests for the assessment core, exercised exactly as the wasm
//! `execute` entry point drives it: resolve the RPC URL, fetch through the
//! `MintFetcher` seam, parse into a `MintAccount`. The fetcher is mocked with
//! canned `getAccountInfo` JSON — these tests run on the host with a plain
//! `cargo test` and touch no network.

use std::collections::HashMap;

use serde_json::{json, Value};

use token_risk_check::assess::{
    build_account_info_request, classify, fetch_and_parse, resolve_rpc_url, AssessError,
    MintAccount, MintExtension, MintFetcher, DEFAULT_RPC_URL, SPL_TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID, VERDICT_AMBER, VERDICT_GREEN, VERDICT_RED,
};

/// Mock transport: returns one canned JSON-RPC response body.
struct CannedFetcher(Value);

impl MintFetcher for CannedFetcher {
    fn fetch(&self, _mint: &str) -> Result<Value, String> {
        Ok(self.0.clone())
    }
}

/// Mock transport: the HTTP call itself fails.
struct FailingFetcher;

impl MintFetcher for FailingFetcher {
    fn fetch(&self, _mint: &str) -> Result<Value, String> {
        Err("connection refused".to_string())
    }
}

fn rpc_ok(value: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 353_000_000}, "value": value}})
}

#[test]
fn parses_classic_spl_token_mint() {
    // USDC-shaped classic mint: live authorities, no extensions key at all.
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": SPL_TOKEN_PROGRAM_ID,
        "lamports": 388_127_620_723u64,
        "executable": false,
        "rentEpoch": 361u64,
        "data": {
            "program": "spl-token",
            "space": 82,
            "parsed": {
                "type": "mint",
                "info": {
                    "mintAuthority": "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9",
                    "freezeAuthority": "3sNBr7kMccME5D55xNgsmYpZnzPgP2g12CixAajXypn6",
                    "supply": "10007635362798840",
                    "decimals": 6,
                    "isInitialized": true
                }
            }
        }
    })));

    let acct = fetch_and_parse("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", &fetcher)
        .expect("classic mint must parse");
    assert_eq!(acct.owner_program, SPL_TOKEN_PROGRAM_ID);
    assert!(!acct.is_token_2022());
    assert_eq!(
        acct.mint_authority.as_deref(),
        Some("2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9")
    );
    assert_eq!(
        acct.freeze_authority.as_deref(),
        Some("3sNBr7kMccME5D55xNgsmYpZnzPgP2g12CixAajXypn6")
    );
    assert_eq!(acct.supply, "10007635362798840");
    assert_eq!(acct.decimals, 6);
    assert!(acct.is_initialized);
    assert!(acct.extensions.is_empty());
}

#[test]
fn null_authorities_parse_as_renounced() {
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": SPL_TOKEN_PROGRAM_ID,
        "data": {
            "program": "spl-token",
            "parsed": {
                "type": "mint",
                "info": {
                    "mintAuthority": null,
                    "freezeAuthority": null,
                    "supply": "999999999999",
                    "decimals": 9,
                    "isInitialized": true
                }
            }
        }
    })));

    let acct = fetch_and_parse("So11111111111111111111111111111111111111112", &fetcher).unwrap();
    assert_eq!(acct.mint_authority, None);
    assert_eq!(acct.freeze_authority, None);
}

#[test]
fn parses_token_2022_mint_with_extensions_faithfully() {
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": TOKEN_2022_PROGRAM_ID,
        "data": {
            "program": "spl-token-2022",
            "space": 469,
            "parsed": {
                "type": "mint",
                "info": {
                    "mintAuthority": "5vxoRv2P12q4K4cWPCJkvPjg6jYnuCYxjF3JJ111111x",
                    "freezeAuthority": null,
                    "supply": "1000000000000000",
                    "decimals": 9,
                    "isInitialized": true,
                    "extensions": [
                        {
                            "extension": "permanentDelegate",
                            "state": {"delegate": "5vxoRv2P12q4K4cWPCJkvPjg6jYnuCYxjF3JJ111111x"}
                        },
                        {
                            "extension": "transferHook",
                            "state": {
                                "authority": "5vxoRv2P12q4K4cWPCJkvPjg6jYnuCYxjF3JJ111111x",
                                "programId": "hook1111111111111111111111111111111111111111"
                            }
                        },
                        {
                            "extension": "defaultAccountState",
                            "state": {"accountState": "frozen"}
                        },
                        {
                            "extension": "transferFeeConfig",
                            "state": {
                                "newerTransferFee": {"epoch": 700, "maximumFee": 5000000u64, "transferFeeBasisPoints": 300},
                                "olderTransferFee": {"epoch": 690, "maximumFee": 5000000u64, "transferFeeBasisPoints": 300},
                                "transferFeeConfigAuthority": null,
                                "withdrawWithheldAuthority": null,
                                "withheldAmount": 0
                            }
                        },
                        {"extension": "nonTransferable"}
                    ]
                }
            }
        }
    })));

    let acct = fetch_and_parse("mintwithExtensions11111111111111111111111111", &fetcher)
        .expect("token-2022 mint must parse");
    assert_eq!(acct.owner_program, TOKEN_2022_PROGRAM_ID);
    assert!(acct.is_token_2022());
    assert_eq!(acct.freeze_authority, None);
    assert_eq!(acct.extensions.len(), 5);

    let types: Vec<&str> = acct
        .extensions
        .iter()
        .map(|e| e.extension_type.as_str())
        .collect();
    assert_eq!(
        types,
        vec![
            "permanentDelegate",
            "transferHook",
            "defaultAccountState",
            "transferFeeConfig",
            "nonTransferable"
        ]
    );

    // Raw state is preserved for the HALF 2 classifier.
    let delegate = &acct.extensions[0];
    assert_eq!(
        delegate.state.as_ref().unwrap()["delegate"],
        "5vxoRv2P12q4K4cWPCJkvPjg6jYnuCYxjF3JJ111111x"
    );
    let hook = &acct.extensions[1];
    assert_eq!(
        hook.state.as_ref().unwrap()["programId"],
        "hook1111111111111111111111111111111111111111"
    );
    let default_state = &acct.extensions[2];
    assert_eq!(default_state.state.as_ref().unwrap()["accountState"], "frozen");
    let fee = &acct.extensions[3];
    assert_eq!(
        fee.state.as_ref().unwrap()["newerTransferFee"]["transferFeeBasisPoints"],
        300
    );
    // Stateless extension keeps None, not a fabricated state.
    assert_eq!(acct.extensions[4].state, None);
}

#[test]
fn account_not_found_is_fail_closed() {
    // getAccountInfo on a non-existent account: result.value is null.
    let fetcher = CannedFetcher(rpc_ok(Value::Null));
    let err = fetch_and_parse("nonexistent1111111111111111111111111111111111", &fetcher)
        .expect_err("missing account must be an error, never a verdict");
    assert_eq!(err, AssessError::AccountNotFound);
    assert!(!err.to_string().contains("green"));
}

#[test]
fn transport_failure_is_fail_closed() {
    let err = fetch_and_parse("So11111111111111111111111111111111111111112", &FailingFetcher)
        .expect_err("transport failure must be an error");
    assert_eq!(err, AssessError::RpcFailure("connection refused".to_string()));
}

#[test]
fn json_rpc_error_response_is_fail_closed() {
    let fetcher = CannedFetcher(json!({
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32602, "message": "Invalid param: WrongSize"}
    }));
    let err = fetch_and_parse("tooShort", &fetcher).expect_err("rpc error must fail");
    assert!(matches!(err, AssessError::RpcFailure(m) if m.contains("-32602")));
}

#[test]
fn non_mint_account_is_fail_closed() {
    // A token *account* (holder wallet), not a mint — must be rejected.
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": SPL_TOKEN_PROGRAM_ID,
        "data": {
            "program": "spl-token",
            "parsed": {"type": "account", "info": {"mint": "x", "owner": "y"}}
        }
    })));
    let err = fetch_and_parse("someTokenAccount", &fetcher).expect_err("non-mint must fail");
    assert!(matches!(err, AssessError::UnexpectedResponse(m) if m.contains("not a mint")));
}

#[test]
fn unparsed_account_data_is_fail_closed() {
    // Base64 fallback (host RPC could not jsonParse the account).
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": "SomeUnknownProgram1111111111111111111111111",
        "data": ["AAAA", "base64"]
    })));
    let err = fetch_and_parse("weirdAccount", &fetcher).expect_err("raw data must fail");
    assert!(matches!(err, AssessError::UnexpectedResponse(_)));
}

#[test]
fn extension_entry_without_type_name_is_fail_closed() {
    // An unidentifiable extension is an error, not a silent skip — dropping
    // one could hide exactly the risk (e.g. permanentDelegate) we look for.
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": TOKEN_2022_PROGRAM_ID,
        "data": {
            "program": "spl-token-2022",
            "parsed": {
                "type": "mint",
                "info": {
                    "mintAuthority": null,
                    "freezeAuthority": null,
                    "supply": "1",
                    "decimals": 0,
                    "isInitialized": true,
                    "extensions": [{"state": {"delegate": "x"}}]
                }
            }
        }
    })));
    let err = fetch_and_parse("badExtensionMint", &fetcher).expect_err("must fail");
    assert!(matches!(err, AssessError::UnexpectedResponse(m) if m.contains("extension")));
}

#[test]
fn rpc_url_config_wins_over_default() {
    let mut section = HashMap::new();
    section.insert(
        "rpc_url".to_string(),
        "https://example-rpc.test/with-key".to_string(),
    );
    assert_eq!(resolve_rpc_url(&section), "https://example-rpc.test/with-key");
}

#[test]
fn rpc_url_falls_back_to_public_default() {
    assert_eq!(resolve_rpc_url(&HashMap::new()), DEFAULT_RPC_URL);
    let mut blank = HashMap::new();
    blank.insert("rpc_url".to_string(), "  ".to_string());
    assert_eq!(resolve_rpc_url(&blank), DEFAULT_RPC_URL);
}

#[test]
fn account_info_request_uses_json_parsed_encoding() {
    let req = build_account_info_request("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    assert_eq!(req["method"], "getAccountInfo");
    assert_eq!(req["params"][0], "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    assert_eq!(req["params"][1]["encoding"], "jsonParsed");
}

// ───────────────────────── HALF 2: classification ─────────────────────────

const MINT: &str = "MintUnderTest111111111111111111111111111111";

/// A fully clean classic SPL mint: both authorities renounced, no extensions.
fn clean_mint() -> MintAccount {
    MintAccount {
        owner_program: SPL_TOKEN_PROGRAM_ID.to_string(),
        mint_authority: None,
        freeze_authority: None,
        supply: "1000000000".to_string(),
        decimals: 9,
        is_initialized: true,
        extensions: Vec::new(),
    }
}

/// A clean Token-2022 mint with the given extensions.
fn t22_mint(extensions: Vec<MintExtension>) -> MintAccount {
    MintAccount {
        owner_program: TOKEN_2022_PROGRAM_ID.to_string(),
        extensions,
        ..clean_mint()
    }
}

fn ext(extension_type: &str, state: Option<Value>) -> MintExtension {
    MintExtension {
        extension_type: extension_type.to_string(),
        state,
    }
}

fn assert_checks_honest(result: &token_risk_check::assess::AssessmentResult) {
    assert_eq!(
        result.checks_performed,
        vec!["mint_authority", "freeze_authority", "token2022_extensions"]
    );
    assert_eq!(
        result.not_checked,
        vec!["holder_concentration", "lp_status", "metadata_mutability"]
    );
    assert_eq!(result.untrusted_metadata, None);
    assert_eq!(result.mint, MINT);
}

#[test]
fn active_mint_authority_is_red() {
    let mut acct = clean_mint();
    acct.mint_authority = Some("AuthPubkey11111111111111111111111111111111".to_string());
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert_eq!(r.reasons.len(), 1);
    assert!(r.reasons[0].contains("mint authority active"));
    assert!(r.reasons[0].contains("AuthPubkey11111111111111111111111111111111"));
    assert!(r.reasons[0].contains("inflated"));
    assert_checks_honest(&r);
}

#[test]
fn active_freeze_authority_is_red() {
    let mut acct = clean_mint();
    acct.freeze_authority = Some("FreezeKey111111111111111111111111111111111".to_string());
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert_eq!(r.reasons.len(), 1);
    assert!(r.reasons[0].contains("freeze authority active"));
    assert!(r.reasons[0].contains("frozen"));
}

#[test]
fn permanent_delegate_is_red() {
    let acct = t22_mint(vec![ext(
        "permanentDelegate",
        Some(json!({"delegate": "Del111"})),
    )]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert!(r.reasons[0].contains("permanentDelegate"));
    assert!(r.reasons[0].contains("any"));
}

#[test]
fn transfer_hook_is_red() {
    let acct = t22_mint(vec![ext(
        "transferHook",
        Some(json!({"programId": "Hook111"})),
    )]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert!(r.reasons[0].contains("transferHook"));
    assert!(r.reasons[0].contains("every transfer"));
}

#[test]
fn default_account_state_frozen_is_red() {
    let acct = t22_mint(vec![ext(
        "defaultAccountState",
        Some(json!({"accountState": "frozen"})),
    )]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert!(r.reasons[0].contains("defaultAccountState"));
    assert!(r.reasons[0].contains("frozen"));
}

#[test]
fn default_account_state_initialized_is_benign() {
    let acct = t22_mint(vec![ext(
        "defaultAccountState",
        Some(json!({"accountState": "initialized"})),
    )]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_GREEN);
    assert!(r.reasons.is_empty());
}

#[test]
fn unreadable_default_account_state_is_red_fail_closed() {
    // State missing entirely: we cannot prove accounts aren't born frozen.
    let acct = t22_mint(vec![ext("defaultAccountState", None)]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert!(r.reasons[0].contains("unreadable"));
}

#[test]
fn transfer_fee_only_is_amber_with_fee_in_reason() {
    let acct = t22_mint(vec![ext(
        "transferFeeConfig",
        Some(json!({
            "newerTransferFee": {"epoch": 700, "maximumFee": 5_000_000u64, "transferFeeBasisPoints": 300},
            "olderTransferFee": {"epoch": 690, "maximumFee": 5_000_000u64, "transferFeeBasisPoints": 250}
        })),
    )]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_AMBER);
    assert_eq!(r.reasons.len(), 1);
    assert!(r.reasons[0].contains("300 basis points"));
    assert!(r.reasons[0].contains("3.00%"));
    assert_checks_honest(&r);
}

#[test]
fn transfer_fee_with_unreadable_rate_is_still_amber() {
    let acct = t22_mint(vec![ext("transferFeeConfig", Some(json!({})))]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_AMBER);
    assert!(r.reasons[0].contains("could not be read"));
}

#[test]
fn non_transferable_only_is_amber() {
    let acct = t22_mint(vec![ext("nonTransferable", None)]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_AMBER);
    assert!(r.reasons[0].contains("nonTransferable"));
    assert!(r.reasons[0].contains("cannot be transferred"));
}

#[test]
fn unclassified_extension_is_amber_never_silently_passed() {
    let acct = t22_mint(vec![ext(
        "mintCloseAuthority",
        Some(json!({"closeAuthority": "X111"})),
    )]);
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_AMBER);
    assert!(r.reasons[0].contains("mintCloseAuthority"));
    assert!(r.reasons[0].contains("not risk-classified"));
}

#[test]
fn clean_classic_spl_mint_is_green() {
    let r = classify(MINT, &clean_mint());
    assert_eq!(r.verdict, VERDICT_GREEN);
    assert!(r.reasons.is_empty());
    assert_eq!(r.token_program, "spl-token");
    assert_checks_honest(&r);
}

#[test]
fn clean_token_2022_mint_is_green() {
    let r = classify(MINT, &t22_mint(Vec::new()));
    assert_eq!(r.verdict, VERDICT_GREEN);
    assert!(r.reasons.is_empty());
    assert_eq!(r.token_program, "token-2022");
    assert_checks_honest(&r);
}

#[test]
fn multiple_red_signals_list_all_reasons() {
    let mut acct = t22_mint(vec![ext(
        "permanentDelegate",
        Some(json!({"delegate": "Del111"})),
    )]);
    acct.mint_authority = Some("MintAuth1111111111111111111111111111111111".to_string());
    acct.freeze_authority = Some("FreezeAuth111111111111111111111111111111111".to_string());
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert_eq!(r.reasons.len(), 3, "all triggered signals must be listed");
    assert!(r.reasons.iter().any(|m| m.contains("mint authority")));
    assert!(r.reasons.iter().any(|m| m.contains("freeze authority")));
    assert!(r.reasons.iter().any(|m| m.contains("permanentDelegate")));
}

#[test]
fn red_beats_amber_and_both_reasons_are_listed() {
    let mut acct = t22_mint(vec![ext(
        "transferFeeConfig",
        Some(json!({"newerTransferFee": {"transferFeeBasisPoints": 100}})),
    )]);
    acct.freeze_authority = Some("FreezeAuth111111111111111111111111111111111".to_string());
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED, "red must take precedence over amber");
    assert_eq!(r.reasons.len(), 2);
    assert!(r.reasons[0].contains("freeze authority"), "red reasons come first");
    assert!(r.reasons[1].contains("basis points"));
}

#[test]
fn green_is_never_returned_when_any_signal_triggers() {
    let signal_cases: Vec<MintAccount> = vec![
        {
            let mut a = clean_mint();
            a.mint_authority = Some("A1".to_string());
            a
        },
        {
            let mut a = clean_mint();
            a.freeze_authority = Some("A2".to_string());
            a
        },
        t22_mint(vec![ext("permanentDelegate", None)]),
        t22_mint(vec![ext("transferHook", None)]),
        t22_mint(vec![ext("defaultAccountState", Some(json!({"accountState": "frozen"})))]),
        t22_mint(vec![ext("defaultAccountState", None)]),
        t22_mint(vec![ext("transferFeeConfig", None)]),
        t22_mint(vec![ext("nonTransferable", None)]),
        t22_mint(vec![ext("somethingNovel", None)]),
    ];
    for acct in signal_cases {
        let r = classify(MINT, &acct);
        assert_ne!(r.verdict, VERDICT_GREEN, "signal must never yield green: {:?}", r.reasons);
        assert!(!r.reasons.is_empty(), "non-green verdict must carry reasons");
    }
}

#[test]
fn unknown_owner_program_is_fail_closed_before_classification() {
    // HALF 1 hardening: a "mint" owned by an unknown program errors in parse,
    // so classify can never mislabel token_program (and never runs at all).
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": "FakeTokenProgram111111111111111111111111111",
        "data": {
            "program": "spl-token",
            "parsed": {
                "type": "mint",
                "info": {
                    "mintAuthority": null, "freezeAuthority": null,
                    "supply": "1", "decimals": 0, "isInitialized": true
                }
            }
        }
    })));
    let err = fetch_and_parse(MINT, &fetcher).expect_err("unknown owner must fail");
    assert!(matches!(err, AssessError::UnexpectedResponse(m) if m.contains("unknown token program")));
}

#[test]
fn end_to_end_fetch_then_classify_dangerous_token_2022_mint() {
    // The exact path execute takes: canned RPC json → parse → classify.
    let fetcher = CannedFetcher(rpc_ok(json!({
        "owner": TOKEN_2022_PROGRAM_ID,
        "data": {
            "program": "spl-token-2022",
            "parsed": {
                "type": "mint",
                "info": {
                    "mintAuthority": "Attacker11111111111111111111111111111111111",
                    "freezeAuthority": null,
                    "supply": "1000000000000000",
                    "decimals": 9,
                    "isInitialized": true,
                    "extensions": [
                        {"extension": "permanentDelegate", "state": {"delegate": "Attacker11111111111111111111111111111111111"}},
                        {"extension": "transferFeeConfig", "state": {"newerTransferFee": {"transferFeeBasisPoints": 500}}}
                    ]
                }
            }
        }
    })));
    let acct = fetch_and_parse(MINT, &fetcher).expect("must parse");
    let r = classify(MINT, &acct);
    assert_eq!(r.verdict, VERDICT_RED);
    assert_eq!(r.reasons.len(), 3); // mint authority + permanentDelegate + fee
    assert_eq!(r.token_program, "token-2022");
}

#[test]
fn assessment_result_serializes_to_the_documented_shape() {
    let json_out = serde_json::to_value(classify(MINT, &clean_mint())).unwrap();
    assert_eq!(
        json_out,
        json!({
            "verdict": "green",
            "reasons": [],
            "checks_performed": ["mint_authority", "freeze_authority", "token2022_extensions"],
            "not_checked": ["holder_concentration", "lp_status", "metadata_mutability"],
            "untrusted_metadata": null,
            "mint": MINT,
            "token_program": "spl-token"
        })
    );
}
