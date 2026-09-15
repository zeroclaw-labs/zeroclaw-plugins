//! JSON-RPC 2.0 request builders + response parsers for the Solana RPC methods
//! `solana-build-tx` needs.
//!
//! These are **pure functions** — no HTTP, no network. The wasm shim in
//! `lib.rs` wires them to `waki` HTTP; host tests call them directly against
//! canned JSON. This split keeps the parsing logic testable without a wasm
//! toolchain or live RPC.
//!
//! # Methods covered
//! - `getLatestBlockhash` → [`BlockhashInfo`]
//! - `simulateTransaction` (with `replaceRecentBlockhash=true`,
//!   `accounts.encoding=base64`) → [`SimulationReport`]
//! - `getTokenAccountsByOwner` → `Vec<TokenAccountInfo>` (for pre-build
//!   delegate check against `expected_delegates_allowlist`)

use crate::builder::{BlockhashInfo, SimulatedAccount, SimulationReport, TokenBalance};

/// One token account from `getTokenAccountsByOwner` (jsonParsed encoding).
/// Used for the pre-build delegate check.
#[derive(Debug, Clone)]
pub struct TokenAccountInfo {
    pub pubkey: String,
    /// Active delegate if any (base58), `None` if unset.
    pub delegate: Option<String>,
    pub close_authority: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
//  request builders
// ═══════════════════════════════════════════════════════════════════════════

/// JSON-RPC request body for `getLatestBlockhash`.
pub fn build_blockhash_request() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash"
    })
}

/// JSON-RPC request body for `simulateTransaction` with the config the
/// validation layers require: replace blockhash at sign-time, return base64
/// account data for Layer B state diff.
pub fn build_simulate_request(unsigned_tx_b64: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "simulateTransaction",
        "params": [
            unsigned_tx_b64,
            {
                "encoding": "base64",
                "replaceRecentBlockhash": true,
                "sigVerify": false,
                "config": {
                    "encoding": "base64",
                    "commitment": "confirmed",
                    "accounts": {
                        "encoding": "base64"
                    }
                }
            }
        ]
    })
}

/// JSON-RPC request body for `getTokenAccountsByOwner`.
pub fn build_token_accounts_request(pubkey: &str, program_id: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            pubkey,
            { "programId": program_id },
            { "encoding": "jsonParsed" }
        ]
    })
}

// ═══════════════════════════════════════════════════════════════════════════
//  response parsers
// ═══════════════════════════════════════════════════════════════════════════

/// Parse `getLatestBlockhash` response JSON → `BlockhashInfo`.
pub fn parse_blockhash_response(json: &serde_json::Value) -> Result<BlockhashInfo, String> {
    let value = json
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or("missing result.value")?;

    let blockhash = value
        .get("blockhash")
        .and_then(|b| b.as_str())
        .ok_or("missing blockhash")?
        .to_string();

    let last_valid_block_height = value
        .get("lastValidBlockHeight")
        .and_then(|h| h.as_u64())
        .unwrap_or(0);

    Ok(BlockhashInfo {
        blockhash,
        last_valid_block_height,
    })
}

/// Parse `simulateTransaction` response JSON → `SimulationReport`.
pub fn parse_simulation_response(json: &serde_json::Value) -> Result<SimulationReport, String> {
    let value = json
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or("missing result.value")?;

    // err can be null (success) or an object/string (failure).
    let err = if value.get("err").map(|e| e.is_null()).unwrap_or(true) {
        None
    } else {
        Some(value.get("err").map(|e| e.to_string()).unwrap_or_default())
    };

    let pre = parse_token_balances(value.get("preTokenBalances"));
    let post = parse_token_balances(value.get("postTokenBalances"));
    let accounts = parse_sim_accounts(value.get("accounts"));
    let units_consumed = value
        .get("unitsConsumed")
        .and_then(|u| u.as_u64())
        .unwrap_or(0);
    let logs = value
        .get("logs")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(SimulationReport {
        err,
        pre_token_balances: pre,
        post_token_balances: post,
        accounts,
        units_consumed,
        logs,
    })
}

/// Parse `getTokenAccountsByOwner` response JSON → `Vec<TokenAccountInfo>`.
pub fn parse_token_accounts_response(
    json: &serde_json::Value,
) -> Result<Vec<TokenAccountInfo>, String> {
    let value = json
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_array())
        .ok_or("missing result.value array")?;

    let mut accounts = Vec::new();
    for entry in value {
        let pubkey = entry
            .get("pubkey")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();

        let info = entry
            .get("account")
            .and_then(|a| a.get("data"))
            .and_then(|d| d.get("parsed"))
            .and_then(|p| p.get("info"));

        let delegate = info
            .and_then(|i| i.get("delegate"))
            .and_then(|d| d.as_str())
            .map(String::from);

        let close_authority = info
            .and_then(|i| i.get("closeAuthority"))
            .and_then(|c| c.as_str())
            .map(String::from);

        accounts.push(TokenAccountInfo {
            pubkey,
            delegate,
            close_authority,
        });
    }
    Ok(accounts)
}

// ─── internal parsers ──────────────────────────────────────────────────────

fn parse_token_balances(json: Option<&serde_json::Value>) -> Vec<TokenBalance> {
    let arr = match json.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .filter_map(|tb| {
            Some(TokenBalance {
                account_index: tb.get("accountIndex").and_then(|i| i.as_u64())? as u32,
                mint: tb.get("mint")?.as_str()?.to_string(),
                owner: tb.get("owner")?.as_str()?.to_string(),
                program_id: tb
                    .get("programId")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                amount: tb
                    .get("uiTokenAmount")
                    .and_then(|a| a.get("amount"))
                    .and_then(|a| a.as_str())
                    .unwrap_or("0")
                    .to_string(),
            })
        })
        .collect()
}

fn parse_sim_accounts(json: Option<&serde_json::Value>) -> Vec<SimulatedAccount> {
    let arr = match json.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .filter_map(|a| {
            Some(SimulatedAccount {
                pubkey: a.get("pubkey")?.as_str()?.to_string(),
                owner: a
                    .get("owner")
                    .and_then(|o| o.as_str())
                    .unwrap_or("")
                    .to_string(),
                lamports: a.get("lamports").and_then(|l| l.as_u64()).unwrap_or(0),
                data_base64: a
                    .get("data")
                    .and_then(|d| {
                        if d.is_array() {
                            // [encoding, data] tuple format
                            d.as_array()
                                .and_then(|arr| arr.get(1).and_then(|v| v.as_str()))
                        } else {
                            d.as_str()
                        }
                    })
                    .map(String::from),
                writable: a.get("writable").and_then(|w| w.as_bool()).unwrap_or(false),
                executable: a
                    .get("executable")
                    .and_then(|e| e.as_bool())
                    .unwrap_or(false),
                rent_epoch: a.get("rentEpoch").and_then(|r| r.as_u64()).unwrap_or(0),
            })
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
//  self-check
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockhash_request_shape() {
        let req = build_blockhash_request();
        assert_eq!(req["method"], "getLatestBlockhash");
        assert_eq!(req["jsonrpc"], "2.0");
    }

    #[test]
    fn simulate_request_has_replace_blockhash() {
        let req = build_simulate_request("dGVzdA==");
        assert_eq!(req["method"], "simulateTransaction");
        // replaceRecentBlockhash must be true for sign-time freshness.
        let config = &req["params"][1];
        assert_eq!(config["replaceRecentBlockhash"], true);
    }

    #[test]
    fn token_accounts_request_includes_program_id_filter() {
        let req = build_token_accounts_request("MyPubkey", "Tokenkeg...");
        assert_eq!(req["method"], "getTokenAccountsByOwner");
        assert_eq!(req["params"][0], "MyPubkey");
        assert_eq!(req["params"][1]["programId"], "Tokenkeg...");
    }

    #[test]
    fn parse_blockhash_extracts_fields() {
        let json = serde_json::json!({
            "result": {
                "value": {
                    "blockhash": "TestBlockhashXXXX",
                    "lastValidBlockHeight": 200_000
                }
            }
        });
        let bh = parse_blockhash_response(&json).unwrap();
        assert_eq!(bh.blockhash, "TestBlockhashXXXX");
        assert_eq!(bh.last_valid_block_height, 200_000);
    }

    #[test]
    fn parse_simulation_success() {
        let json = serde_json::json!({
            "result": {
                "value": {
                    "err": null,
                    "unitsConsumed": 5000,
                    "preTokenBalances": [],
                    "postTokenBalances": [],
                    "accounts": [],
                    "logs": ["Program log: ok"]
                }
            }
        });
        let report = parse_simulation_response(&json).unwrap();
        assert!(report.err.is_none());
        assert_eq!(report.units_consumed, 5000);
        assert_eq!(report.logs.len(), 1);
    }

    #[test]
    fn parse_simulation_error() {
        let json = serde_json::json!({
            "result": {
                "value": {
                    "err": { "InstructionError": [0, "InsufficientFunds"] },
                    "unitsConsumed": 200
                }
            }
        });
        let report = parse_simulation_response(&json).unwrap();
        assert!(report.err.is_some());
        assert!(report.err.unwrap().contains("InsufficientFunds"));
    }

    #[test]
    fn parse_token_balances_extracts_amounts() {
        let json = serde_json::json!({
            "result": {
                "value": {
                    "err": null,
                    "preTokenBalances": [{
                        "accountIndex": 0,
                        "mint": "EPjFWcc5...",
                        "owner": "9WZDXwBb...",
                        "programId": "TokenkegQ...",
                        "uiTokenAmount": { "amount": "100000000" }
                    }],
                    "postTokenBalances": [{
                        "accountIndex": 0,
                        "mint": "EPjFWcc5...",
                        "owner": "9WZDXwBb...",
                        "programId": "TokenkegQ...",
                        "uiTokenAmount": { "amount": "95000000" }
                    }],
                    "accounts": [],
                    "unitsConsumed": 0
                }
            }
        });
        let report = parse_simulation_response(&json).unwrap();
        assert_eq!(report.pre_token_balances.len(), 1);
        assert_eq!(report.pre_token_balances[0].amount, "100000000");
        assert_eq!(report.post_token_balances[0].amount, "95000000");
    }

    #[test]
    fn parse_sim_accounts_with_base64_data() {
        let json = serde_json::json!({
            "result": {
                "value": {
                    "err": null,
                    "accounts": [{
                        "pubkey": "SrcATA",
                        "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                        "lamports": 1000000,
                        "data": ["base64", "AAAAAAAA"],
                        "writable": true,
                        "executable": false,
                        "rentEpoch": 0
                    }],
                    "unitsConsumed": 0
                }
            }
        });
        let report = parse_simulation_response(&json).unwrap();
        assert_eq!(report.accounts.len(), 1);
        assert_eq!(report.accounts[0].pubkey, "SrcATA");
        assert!(report.accounts[0].writable);
        assert_eq!(report.accounts[0].data_base64.as_deref(), Some("AAAAAAAA"));
    }

    #[test]
    fn parse_token_accounts_extracts_delegate() {
        let json = serde_json::json!({
            "result": {
                "value": [
                    {
                        "pubkey": "Acct1",
                        "account": {
                            "data": {
                                "parsed": {
                                    "info": {
                                        "delegate": "DelegateAddr",
                                        "closeAuthority": null
                                    }
                                }
                            }
                        }
                    },
                    {
                        "pubkey": "Acct2",
                        "account": {
                            "data": {
                                "parsed": {
                                    "info": {
                                        "delegate": null,
                                        "closeAuthority": "CloseAuth"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        });
        let accounts = parse_token_accounts_response(&json).unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].delegate.as_deref(), Some("DelegateAddr"));
        assert!(accounts[0].close_authority.is_none());
        assert!(accounts[1].delegate.is_none());
        assert_eq!(accounts[1].close_authority.as_deref(), Some("CloseAuth"));
    }

    #[test]
    fn parse_blockhash_missing_result_rejects() {
        let json = serde_json::json!({ "error": "oops" });
        assert!(parse_blockhash_response(&json).is_err());
    }
}
