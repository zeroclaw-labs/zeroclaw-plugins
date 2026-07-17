//! Solana token safety scanner — pure Rust core (no wasm dependency).
#![allow(dead_code)] // some functions only used in wasm component via cfg
//!
//! Checks a Solana SPL token for common safety signals:
//! - Mint authority (renounced = safe)
//! - Freeze authority (renounced = safe)
//! - Holder concentration (top 10 holders)
//! - Token supply and decimals
//!
//! All RPC calls are abstracted through an `HttpClient` trait so the same
//! logic compiles and is testable on the host without wasm.

use serde::{Deserialize, Serialize};

/// Result returned to the agent.
#[derive(Debug, Serialize)]
pub struct TokenSafetyReport {
    pub mint: String,
    pub decimals: u8,
    pub supply: String,
    pub mint_authority: Option<String>,
    pub mint_authority_renounced: bool,
    pub freeze_authority: Option<String>,
    pub freeze_authority_renounced: bool,
    pub top_holder_concentration_pct: Option<f64>,
    pub top_holders: Vec<HolderInfo>,
    pub safety_score: u8, // 0-100
    pub warnings: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HolderInfo {
    pub address: String,
    pub amount: String,
    pub pct: f64,
}

/// Trait for HTTP POST (abstracts over real HTTP client or test mock).
pub trait HttpClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

/// Check a token's safety by querying the Solana RPC.
pub fn check_token_safety(
    client: &dyn HttpClient,
    rpc_url: &str,
    mint: &str,
) -> Result<TokenSafetyReport, String> {
    // 1. getAccountInfo for the mint
    let mint_info = get_mint_info(client, rpc_url, mint)?;

    // 2. getTokenLargestAccounts for holder concentration (relative to total supply)
    let largest = get_largest_accounts(client, rpc_url, mint, &mint_info.supply)?;

    // 3. Build report
    let top_pct: f64 = largest.iter().take(10).map(|h| h.pct).sum();
    let mut warnings = Vec::new();
    let mut score: u8 = 100;

    if !mint_info.mint_authority_renounced {
        warnings.push("⚠️ Mint authority is NOT renounced — new tokens can be minted.".into());
        score = score.saturating_sub(30);
    }
    if !mint_info.freeze_authority_renounced {
        warnings.push("⚠️ Freeze authority is NOT renounced — tokens can be frozen.".into());
        score = score.saturating_sub(20);
    }
    if top_pct > 80.0 {
        warnings.push(format!(
            "🔴 Top holders control {:.1}% of supply — highly concentrated.",
            top_pct
        ));
        score = score.saturating_sub(40);
    } else if top_pct > 50.0 {
        warnings.push(format!(
            "🟡 Top holders control {:.1}% of supply — moderately concentrated.",
            top_pct
        ));
        score = score.saturating_sub(20);
    } else if top_pct > 30.0 {
        warnings.push(format!(
            "🟢 Top holders control {:.1}% of supply — somewhat distributed.",
            top_pct
        ));
        score = score.saturating_sub(5);
    }

    if warnings.is_empty() {
        warnings.push("✅ No safety concerns detected.".into());
    }

    let summary = if score >= 80 {
        format!("✅ SAFE (score {score}/100): Mint authority renounced, supply distributed.")
    } else if score >= 50 {
        format!("🟡 CAUTION (score {score}/100): Some risk factors present.")
    } else {
        format!("🔴 RISKY (score {score}/100): Multiple safety concerns.")
    };

    Ok(TokenSafetyReport {
        mint: mint.to_string(),
        decimals: mint_info.decimals,
        supply: mint_info.supply,
        mint_authority: mint_info.mint_authority,
        mint_authority_renounced: mint_info.mint_authority_renounced,
        freeze_authority: mint_info.freeze_authority,
        freeze_authority_renounced: mint_info.freeze_authority_renounced,
        top_holder_concentration_pct: Some(top_pct),
        top_holders: largest,
        safety_score: score,
        warnings,
        summary,
    })
}

struct MintInfo {
    decimals: u8,
    supply: String,
    mint_authority: Option<String>,
    mint_authority_renounced: bool,
    freeze_authority: Option<String>,
    freeze_authority_renounced: bool,
}

fn get_mint_info(
    client: &dyn HttpClient,
    rpc_url: &str,
    mint: &str,
) -> Result<MintInfo, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            mint,
            {"encoding": "jsonParsed"}
        ]
    })
    .to_string();

    let resp = client.post_json(rpc_url, &body)?;
    let v: serde_json::Value =
        serde_json::from_str(&resp).map_err(|e| format!("RPC parse error: {e}"))?;

    let data = &v["result"]["value"]["data"]["parsed"]["info"];
    let supply = data["supply"]
        .as_str()
        .unwrap_or("0")
        .to_string();
    let decimals = data["decimals"].as_u64().unwrap_or(0) as u8;
    let ma = data["mintAuthority"].as_str().map(|s| s.to_string());
    let fa = data["freezeAuthority"].as_str().map(|s| s.to_string());
    let ma_renounced = ma.is_none();
    let fa_renounced = fa.is_none();

    Ok(MintInfo {
        decimals,
        supply,
        mint_authority: ma,
        mint_authority_renounced: ma_renounced,
        freeze_authority: fa,
        freeze_authority_renounced: fa_renounced,
    })
}

fn get_largest_accounts(
    client: &dyn HttpClient,
    rpc_url: &str,
    mint: &str,
    total_supply: &str,
) -> Result<Vec<HolderInfo>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenLargestAccounts",
        "params": [mint]
    })
    .to_string();

    let resp = client.post_json(rpc_url, &body)?;
    let v: serde_json::Value =
        serde_json::from_str(&resp).map_err(|e| format!("RPC parse error: {e}"))?;

    let accounts = v["result"]["value"].as_array().ok_or("No largest accounts data")?;

    // Use total supply from mint info for percentages
    let total: f64 = total_supply
        .parse()
        .unwrap_or(1.0);

    let holders: Vec<HolderInfo> = accounts
        .iter()
        .take(10)
        .map(|a| {
            let amount = a["amount"].as_str().unwrap_or("0").to_string();
            let amt: f64 = amount.parse().unwrap_or(0.0);
            let pct = if total > 0.0 { (amt / total) * 100.0 } else { 0.0 };
            HolderInfo {
                address: a["address"].as_str().unwrap_or("").to_string(),
                amount,
                pct,
            }
        })
        .collect();

    Ok(holders)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct MockClient {
        responses: RefCell<VecDeque<String>>,
    }

    impl MockClient {
        fn new(responses: Vec<String>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl HttpClient for MockClient {
        fn post_json(&self, _url: &str, _body: &str) -> Result<String, String> {
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "no mock response".into())
        }
    }

    #[test]
    fn test_safe_token() {
        let mint_info = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "value": {
                    "data": {
                        "parsed": {
                            "info": {
                                "decimals": 6,
                                "supply": "1000000000000",
                                "mintAuthority": null,
                                "freezeAuthority": null
                            }
                        }
                    }
                }
            }
        })
        .to_string();

        let largest = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "value": [
                    {"address": "raymium", "amount": "50000000000"},
                    {"address": "orca", "amount": "50000000000"},
                    {"address": "meteora", "amount": "50000000000"},
                    {"address": "saber", "amount": "20000000000"},
                    {"address": "mercurial", "amount": "20000000000"}
                ]
            }
        })
        .to_string();

        let client = MockClient::new(vec![mint_info, largest]);
        let report = check_token_safety(&client, "http://localhost", "TokenMint")
            .expect("should succeed");

        assert_eq!(report.safety_score, 100);
        assert!(report.mint_authority_renounced);
        assert!(report.freeze_authority_renounced);
    }

    #[test]
    fn test_risky_token() {
        let mint_info = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "value": {
                    "data": {
                        "parsed": {
                            "info": {
                                "decimals": 6,
                                "supply": "1000000000000",
                                "mintAuthority": "SOME_AUTHORITY",
                                "freezeAuthority": "FREEZE_AUTH"
                            }
                        }
                    }
                }
            }
        })
        .to_string();

        let largest = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "value": [
                    {"address": "A1", "amount": "900000000000"},
                    {"address": "A2", "amount": "50000000000"},
                    {"address": "A3", "amount": "30000000000"}
                ]
            }
        })
        .to_string();

        let client = MockClient::new(vec![mint_info, largest]);
        let report = check_token_safety(&client, "http://localhost", "ScamCoin")
            .expect("should succeed");

        assert!(report.safety_score < 50);
        assert!(!report.mint_authority_renounced);
        assert!(!report.freeze_authority_renounced);
    }
}
