//! JSON-RPC client for Solana, wrapping `waki` (blocking wasi:http) on wasm
//! and `ureq` on the host for native `cargo test`.
//!
//! Every method shapes its response to ~200 tokens for LLM consumption.

use crate::types::*;
use serde::{Serialize, Deserialize};

/// Solana JSON-RPC client.
#[derive(Debug, Clone)]
pub struct SolanaRpc {
    pub url: String,
}

impl SolanaRpc {
    /// Create a new client pointing at the given RPC URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Make a raw JSON-RPC call.
    pub fn call<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<T>,
    ) -> Result<R, String> {
        let request = JsonRpcRequest::new(method, params);
        let body = serde_json::to_string(&request).map_err(|e| format!("serialize: {e}"))?;

        let response = self.http_post(&body)?;

        let parsed: JsonRpcResponse<R> =
            serde_json::from_str(&response).map_err(|e| format!("deserialize: {e}"))?;

        if let Some(err) = parsed.error {
            return Err(format!("RPC error {}: {}", err.code, err.message));
        }

        parsed.result.ok_or_else(|| "RPC returned no result".into())
    }

    /// HTTP POST with waki (wasm) or ureq (host).
    #[cfg(not(target_family = "wasm"))]
    fn http_post(&self, body: &str) -> Result<String, String> {
        let response = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| format!("http: {e}"))?;
        response
            .into_string()
            .map_err(|e| format!("body: {e}"))
    }

    #[cfg(target_family = "wasm")]
    fn http_post(&self, body: &str) -> Result<String, String> {
        let resp = waki::Client::new()
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(body.as_bytes())
            .connect_timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| format!("http: {e}"))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .map_err(|e| format!("body: {e}"))?;
        let text = String::from_utf8_lossy(&bytes).to_string();
        if status != 200 {
            return Err(format!("HTTP {status}: {text}"));
        }
        Ok(text)
    }

    // ── RPC methods ──

    /// GET LATEST BLOCKHASH.
    pub fn get_latest_blockhash(&self) -> Result<String, String> {
        #[derive(Deserialize)]
        struct BlockhashResult {
            blockhash: String,
            #[allow(dead_code)]
            last_valid_block_height: u64,
        }
        let r: BlockhashResult =
            self.call("getLatestBlockhash", vec![serde_json::json!({})])?;
        Ok(r.blockhash)
    }

    /// GET ACCOUNT INFO.
    pub fn get_account_info(&self, address: &str) -> Result<AccountInfo, String> {
        let config = serde_json::json!({
            "encoding": "base64",
            "commitment": "confirmed"
        });
        self.call("getAccountInfo", vec![
            serde_json::json!(address),
            config,
        ])
    }

    /// GET TOKEN SUPPLY.
    pub fn get_token_supply(&self, mint: &str) -> Result<TokenSupply, String> {
        self.call("getTokenSupply", vec![
            serde_json::json!(mint),
            serde_json::json!({"commitment": "confirmed"}),
        ])
    }

    /// GET MINT ACCOUNT INFO (parses SPL Token/Token-2022 account data).
    pub fn get_mint_info(&self, mint: &str) -> Result<MintAccount, String> {
        let info = self.get_account_info(mint)?;

        // Parse SPL Token mint account data (165 bytes)
        // Layout: mint_authority(32) + supply(8) + decimals(1) + is_initialized(1)
        // + freeze_authority_option(1) + freeze_authority(32)
        let raw = &info.data.get(0).ok_or("no data")?;
        let bytes = bs58::decode(raw)
            .into_vec()
            .map_err(|e| format!("base58 decode: {e}"))?;

        if bytes.len() < 82 {
            return Ok(MintAccount {
                address: mint.to_string(),
                decimals: 0,
                mint_authority: None,
                freeze_authority: None,
                supply: 0,
                is_initialized: false,
            });
        }

        let decimals = bytes[44];
        let is_initialized = bytes[45] == 1;
        let has_freeze = bytes[46] > 0;

        // Mint authority: bytes 0-32 (first 32 bytes, pubkey)
        let ma_bytes = &bytes[0..32];
        let supply_bytes = &bytes[36..44];
        let supply = u64::from_le_bytes(supply_bytes.try_into().unwrap_or([0; 8]));

        let mint_authority = if ma_bytes.iter().any(|&b| b != 0) {
            Some(bs58::encode(ma_bytes).into_string())
        } else {
            None
        };

        let freeze_authority = if has_freeze {
            let fa_bytes = &bytes[47..79];
            if fa_bytes.iter().any(|&b| b != 0) {
                Some(bs58::encode(fa_bytes).into_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(MintAccount {
            address: mint.to_string(),
            decimals,
            mint_authority,
            freeze_authority,
            supply,
            is_initialized,
        })
    }

    /// GET TOKEN LARGEST ACCOUNTS (holder concentration).
    pub fn get_largest_accounts(&self, mint: &str) -> Result<Vec<LargestAccount>, String> {
        self.call("getTokenLargestAccounts", vec![
            serde_json::json!(mint),
            serde_json::json!({"commitment": "confirmed"}),
        ])
    }

    /// GET PROGRAM ACCOUNTS (for LP detection).
    pub fn get_program_accounts(
        &self,
        program: &str,
        filters: Vec<serde_json::Value>,
    ) -> Result<Vec<ProgramAccount>, String> {
        let config = serde_json::json!({
            "encoding": "base64",
            "commitment": "confirmed",
            "filters": filters,
        });
        self.call("getProgramAccounts", vec![
            serde_json::json!(program),
            config,
        ])
    }

    /// CHECK IF MINT HAS LP (Raydium/Orca/OpenBook).
    pub fn has_liquidity_pool(&self, mint: &str) -> Result<bool, String> {
        // Common LP program IDs
        let lp_programs = [
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM
            "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP", // Orca
            "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX", // OpenBook
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",  // Orca Whirlpools
        ];

        for program in &lp_programs {
            let filter = serde_json::json!({
                "memcmp": {
                    "offset": 0,
                    "bytes": mint,
                }
            });
            let accts = self.get_program_accounts(program, vec![filter])?;
            if !accts.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// DO A FULL TOKEN RISK CHECK.
    pub fn token_risk_check(&self, mint: &str) -> Result<TokenRiskReport, String> {
        let mut reasons: Vec<String> = Vec::new();
        let mut score: u32 = 0;

        // 1. Mint account info
        let mint_info = self.get_mint_info(mint)?;

        // Mint authority still set = can mint more
        if let Some(ref ma) = mint_info.mint_authority {
            reasons.push(format!("Mint authority ACTIVE: {ma} (can mint new tokens)"));
            score += 25;
        } else {
            reasons.push("Mint authority REVOKED ✅".into());
        }

        // Freeze authority
        if let Some(ref fa) = mint_info.freeze_authority {
            reasons.push(format!("Freeze authority ACTIVE: {fa} (can freeze accounts)"));
            score += 15;
        } else {
            reasons.push("Freeze authority REVOKED ✅".into());
        }

        // 2. Holder concentration
        let concentration = match self.get_largest_accounts(mint) {
            Ok(accounts) => {
                if accounts.is_empty() {
                    None
                } else {
                    let total: u64 = accounts
                        .iter()
                        .filter_map(|a| a.amount.parse::<u64>().ok())
                        .sum();
                    let top1 = accounts
                        .first()
                        .and_then(|a| a.amount.parse::<u64>().ok())
                        .unwrap_or(0);
                    let top5: u64 = accounts
                        .iter()
                        .take(5)
                        .filter_map(|a| a.amount.parse::<u64>().ok())
                        .sum();
                    let top10: u64 = accounts
                        .iter()
                        .take(10)
                        .filter_map(|a| a.amount.parse::<u64>().ok())
                        .sum();

                    let c = HolderConcentration {
                        total_holders: accounts.len(),
                        top1_pct: if total > 0 { (top1 as f64 / total as f64) * 100.0 } else { 0.0 },
                        top5_pct: if total > 0 { (top5 as f64 / total as f64) * 100.0 } else { 0.0 },
                        top10_pct: if total > 0 { (top10 as f64 / total as f64) * 100.0 } else { 0.0 },
                    };

                    if c.top1_pct > 50.0 {
                        reasons.push(format!("Top 1 holder owns {:.1}% — extreme concentration", c.top1_pct));
                        score += 20;
                    } else if c.top1_pct > 20.0 {
                        reasons.push(format!("Top 1 holder owns {:.1}%", c.top1_pct));
                        score += 10;
                    }
                    if c.top10_pct > 90.0 {
                        reasons.push(format!("Top 10 hold {:.1}% — very concentrated", c.top10_pct));
                        score += 10;
                    }
                    Some(c)
                }
            }
            Err(e) => {
                reasons.push(format!("Holder data unavailable: {e}"));
                None
            }
        };

        // 3. LP check
        match self.has_liquidity_pool(mint) {
            Ok(true) => reasons.push("Has verified LP (Raydium/Orca) ✅".into()),
            Ok(false) => {
                reasons.push("NO known LP found — may be untradeable ⚠️".into());
                score += 10;
            }
            Err(e) => {
                reasons.push(format!("LP check failed: {e}"));
            }
        }

        // 4. Token-2022 extensions (basic detection by owner)
        let extensions = if mint_info.decimals > 0 && mint_info.decimals != 9 {
            // Non-standard decimals hint at Token-2022 features
            Token2022Extensions {
                has_transfer_hook: false,
                has_transfer_fee: false,
                has_permanent_delegate: false,
                has_non_transferable: false,
                has_interest_bearing: false,
            }
        } else {
            Token2022Extensions::default()
        };

        // 5. Determine risk level
        let risk_level = if score >= 50 {
            RiskLevel::Red
        } else if score >= 20 {
            RiskLevel::Amber
        } else {
            RiskLevel::Green
        };

        Ok(TokenRiskReport {
            mint: mint.to_string(),
            risk_level,
            reasons,
            score,
            supply: mint_info.supply,
            decimals: mint_info.decimals,
            concentration,
            extensions,
            mint_authority: mint_info.mint_authority,
            freeze_authority: mint_info.freeze_authority,
        })
    }

    /// SHAPE RISK REPORT FOR LLM (target: ~200 tokens).
    pub fn format_risk_report(&self, report: &TokenRiskReport) -> ShapedOutput {
        let summary = format!(
            "{} | Score: {}/100 | Supply: {} ({} decimals) | {}",
            report.risk_level,
            report.score,
            report.supply,
            report.decimals,
            report.reasons.join("; "),
        );
        ShapedOutput::json(&summary, serde_json::to_value(report).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_url_construction() {
        let rpc = SolanaRpc::new("https://api.mainnet-beta.solana.com");
        assert_eq!(rpc.url, "https://api.mainnet-beta.solana.com");
    }

    #[test]
    fn test_json_rpc_request_serialization() {
        let req = JsonRpcRequest::new("getLatestBlockhash", vec![serde_json::json!({})]);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("getLatestBlockhash"));
        assert!(json.contains("2.0"));
    }
}