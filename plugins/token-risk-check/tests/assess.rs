//! Integration tests for the assessment core, exercised exactly as the wasm
//! `execute` entry point drives it: resolve the RPC URL, fetch through the
//! `MintFetcher` seam, parse into a `MintAccount`. The fetcher is mocked with
//! canned `getAccountInfo` JSON — these tests run on the host with a plain
//! `cargo test` and touch no network.

use std::collections::HashMap;

use serde_json::{json, Value};

use token_risk_check::assess::{
    build_account_info_request, fetch_and_parse, resolve_rpc_url, AssessError, MintFetcher,
    DEFAULT_RPC_URL, SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
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
