//! Pure Jupiter swap core. No wit-bindgen or wasm dependency so it compiles
//! and tests on the host with `cargo test`.
//!
//! Handles:
//! 1. Price lookup via Jupiter price API
//! 2. Swap quote via Jupiter quote API
//! 3. Output shaping — compact LLM-friendly text, never raw 40KB JSON

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Config ────────────────────────────────────────────────────────────

/// Plugin config resolved from the host's jailed config section.
#[derive(Debug, Clone)]
pub struct SwapConfig {
    /// Jupiter price API base URL.
    pub price_api: String,
    /// Jupiter quote API base URL.
    pub quote_api: String,
    /// OutLayer API base URL.
    pub outlayer_api: String,
    /// OutLayer API key (read from config, never hardcoded).
    pub outlayer_api_key: String,
    /// Max slippage in basis points (e.g. 50 = 0.5%).
    pub max_slippage_bps: u32,
    /// Comma-separated allowed mint addresses (empty = allow all).
    pub allowed_mints: Vec<String>,
    /// Daily spend cap in USD (0 = no cap).
    pub daily_spend_cap_usd: f64,
}

impl SwapConfig {
    /// Build from the flat `string -> string` section the host injects.
    /// Missing keys fall back to safe defaults.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let price_api = section
            .get("price_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://price.jup.ag/v6".to_string());
        let quote_api = section
            .get("quote_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://quote-api.jup.ag/v6".to_string());
        let outlayer_api = section
            .get("outlayer_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://api.outlayer.fastnear.com".to_string());
        let outlayer_api_key = section
            .get("outlayer_api_key")
            .cloned()
            .unwrap_or_default();
        let max_slippage_bps = section
            .get("max_slippage_bps")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let allowed_mints = section
            .get("allowed_mints")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        let daily_spend_cap_usd = section
            .get("daily_spend_cap_usd")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500.0);
        Self {
            price_api,
            quote_api,
            outlayer_api,
            outlayer_api_key,
            max_slippage_bps,
            allowed_mints,
            daily_spend_cap_usd,
        }
    }
}

// ── API types ─────────────────────────────────────────────────────────

/// JSON-RPC request body.
#[derive(Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'static str,
    pub params: serde_json::Value,
}

/// JSON-RPC response body (we only need result/error).
#[derive(Deserialize)]
pub struct JsonRpcResponse {
    pub result: Option<serde_json::Value>,
    pub error: Option<RpcError>,
}

#[derive(Deserialize)]
pub struct RpcError {
    pub message: String,
}

// ── Request builders ──────────────────────────────────────────────────

/// Build Jupiter price lookup URL.
/// GET {price_api}/price?ids={mints}
pub fn build_price_url(cfg: &SwapConfig, mints: &[&str]) -> String {
    let ids = mints.join(",");
    format!("{}/price?ids={}", cfg.price_api, ids)
}

/// Build Jupiter quote URL.
/// GET {quote_api}/quote?inputMint=..&outputMint=..&amount=..&slippageBps=..
pub fn build_quote_url(
    cfg: &SwapConfig,
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: u32,
) -> String {
    let slippage = slippage_bps.min(cfg.max_slippage_bps);
    format!(
        "{}/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}&onlyDirectRoutes=true&asLegacyTransaction=false",
        cfg.quote_api, input_mint, output_mint, amount, slippage
    )
}

/// Build OutLayer address derivation URL.
/// GET {outlayer_api}/wallet/v1/address?chain=solana
pub fn build_outlayer_address_url(cfg: &SwapConfig) -> String {
    format!("{}/wallet/v1/address?chain=solana", cfg.outlayer_api)
}

/// Build OutLayer balance URL.
/// GET {outlayer_api}/wallet/v1/balance?chain=solana&token={mint}
pub fn build_outlayer_balance_url(cfg: &SwapConfig, mint: &str) -> String {
    format!(
        "{}/wallet/v1/balance?chain=solana&token={}",
        cfg.outlayer_api, mint
    )
}

/// Build OutLayer transfer request body for swap submission.
/// POST {outlayer_api}/wallet/v1/transfer
pub fn build_outlayer_transfer_body(
    chain: &str,
    token: &str,
    to: &str,
    amount: &str,
    tx_data: &str,
) -> serde_json::Value {
    serde_json::json!({
        "chain": chain,
        "token": token,
        "to": to,
        "amount": amount,
        "tx_data": tx_data,
    })
}

// ── Output shaping ────────────────────────────────────────────────────

/// Shape a Jupiter price response into a compact string for the LLM.
/// Target: ~200 tokens, not 40KB of raw JSON.
pub fn shape_price_response(raw: &serde_json::Value) -> String {
    let prices = raw.as_object().and_then(|o| o.get("data")).and_then(|d| d.as_object());
    if let Some(prices) = prices {
        let mut lines = Vec::new();
        for (mint, info) in prices {
            let price = info.get("price").and_then(|v| v.as_str()).unwrap_or("N/A");
            let symbol = mint_short(mint);
            lines.push(format!("{}: ${}", symbol, price));
        }
        lines.join(", ")
    } else {
        "No prices found.".to_string()
    }
}

/// Shape a Jupiter quote response into a compact string for the LLM.
pub fn shape_quote_response(raw: &serde_json::Value) -> String {
    let in_amount = raw
        .get("inAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let out_amount = raw
        .get("outAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let price_impact_pct = raw
        .get("priceImpactPct")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let slippage_bps = raw
        .get("slippageBps")
        .and_then(|v| v.as_number())
        .and_then(|n| n.as_u64())
        .unwrap_or(0);

    // Route info — which DEXes
    let route_plan = raw.get("routePlan").and_then(|v| v.as_array());
    let dexes = match route_plan {
        Some(steps) => {
            let names: Vec<String> = steps
                .iter()
                .filter_map(|step| {
                    step.get("swapInfo")
                        .and_then(|si| si.get("label"))
                        .and_then(|l| l.as_str())
                        .map(|s| s.to_string())
                })
                .collect();
            if names.is_empty() {
                "unknown".to_string()
            } else {
                names.join(" → ")
            }
        }
        None => "direct".to_string(),
    };

    let pi: f64 = price_impact_pct.parse().unwrap_or(0.0);
    let pi_display = (pi * 100.0).abs();
    let slippage_display = slippage_bps as f64 / 100.0;

    format!(
        "Quote: {} in → {} out. Route: {}. Slippage: {:.2}%. Price impact: {:.3}%.",
        in_amount, out_amount, dexes, slippage_display, pi_display
    )
}

/// Extract the base64 swap transaction from a Jupiter swap response.
pub fn extract_swap_transaction(swap_response: &serde_json::Value) -> Result<String, String> {
    swap_response
        .get("swapTransaction")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No swapTransaction in response".to_string())
}

// ── Mint allowlist enforcement ───────────────────────────────────────

/// Check if a mint is in the allowlist. Empty allowlist = allow all.
pub fn is_mint_allowed(cfg: &SwapConfig, mint: &str) -> bool {
    cfg.allowed_mints.is_empty() || cfg.allowed_mints.iter().any(|m| *m == mint.to_lowercase())
}

/// Reject if either mint is not in the allowlist. Returns an error message.
pub fn enforce_mint_allowlist(
    cfg: &SwapConfig,
    input_mint: &str,
    output_mint: &str,
) -> Result<(), String> {
    if !is_mint_allowed(cfg, input_mint) {
        return Err(format!(
            "Input mint {} not in allowlist. Transaction rejected.",
            mint_short(input_mint)
        ));
    }
    if !is_mint_allowed(cfg, output_mint) {
        return Err(format!(
            "Output mint {} not in allowlist. Transaction rejected.",
            mint_short(output_mint)
        ));
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Shorten a mint address for display: "So11111111111111111111111111111111" → "So111…1111"
pub fn mint_short(mint: &str) -> &str {
    if mint.len() > 12 {
        &mint[..8]
    } else {
        mint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_config() -> SwapConfig {
        SwapConfig::from_section(&HashMap::new())
    }

    fn config_with(pairs: &[(&str, &str)]) -> SwapConfig {
        let section: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        SwapConfig::from_section(&section)
    }

    #[test]
    fn empty_config_has_safe_defaults() {
        let cfg = empty_config();
        assert_eq!(cfg.price_api, "https://price.jup.ag/v6");
        assert_eq!(cfg.quote_api, "https://quote-api.jup.ag/v6");
        assert_eq!(cfg.outlayer_api, "https://api.outlayer.fastnear.com");
        assert!(cfg.outlayer_api_key.is_empty());
        assert_eq!(cfg.max_slippage_bps, 50);
        assert!(cfg.allowed_mints.is_empty());
        assert_eq!(cfg.daily_spend_cap_usd, 500.0);
    }

    #[test]
    fn config_overrides_from_section() {
        let cfg = config_with(&[
            ("max_slippage_bps", "100"),
            ("daily_spend_cap_usd", "1000"),
            ("allowed_mints", "So11111111111111111111111111111111,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        ]);
        assert_eq!(cfg.max_slippage_bps, 100);
        assert_eq!(cfg.daily_spend_cap_usd, 1000.0);
        assert_eq!(cfg.allowed_mints.len(), 2);
    }

    #[test]
    fn empty_allowlist_allows_everything() {
        let cfg = empty_config();
        assert!(is_mint_allowed(&cfg, "any_random_mint_address"));
    }

    #[test]
    fn non_empty_allowlist_blocks_unlisted_mints() {
        let cfg = config_with(&[("allowed_mints", "So11111111111111111111111111111111")]);
        assert!(is_mint_allowed(&cfg, "So11111111111111111111111111111111"));
        assert!(!is_mint_allowed(&cfg, "random_bad_mint"));
    }

    #[test]
    fn enforce_allowlist_passes_for_allowed() {
        let sol = "So11111111111111111111111111111111";
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let cfg = config_with(&[("allowed_mints", "So11111111111111111111111111111111,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")]);
        assert!(enforce_mint_allowlist(&cfg, sol, usdc).is_ok());
    }

    #[test]
    fn enforce_allowlist_blocks_bad_mint() {
        let sol = "So11111111111111111111111111111111";
        let bad = "9xyzFAKEtokenMintAddress";
        let cfg = config_with(&[("allowed_mints", "So11111111111111111111111111111111")]);
        let result = enforce_mint_allowlist(&cfg, sol, bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowlist"));
    }

    #[test]
    fn build_price_url_formats_correctly() {
        let cfg = empty_config();
        let url = build_price_url(&cfg, &["So11111111111111111111111111111111", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"]);
        assert!(url.contains("price?ids="));
        assert!(url.contains("So1111"));
        assert!(url.contains("EPjFWdd"));
    }

    #[test]
    fn build_quote_url_clamps_slippage() {
        let cfg = config_with(&[("max_slippage_bps", "50")]);
        let url = build_quote_url(&cfg, "So1111", "EPjFWd", 1000000, 500);
        // slippage should be clamped to 50 (max from config), not 500
        assert!(url.contains("slippageBps=50"));
        assert!(url.contains("amount=1000000"));
    }

    #[test]
    fn build_quote_url_allows_under_cap() {
        let cfg = config_with(&[("max_slippage_bps", "300")]);
        let url = build_quote_url(&cfg, "So1111", "EPjFWd", 1000000, 100);
        assert!(url.contains("slippageBps=100"));
    }

    #[test]
    fn shape_price_response_compact() {
        let raw = serde_json::json!({
            "data": {
                "So11111111111111111111111111111111": {
                    "id": "So11111111111111111111111111111111",
                    "price": "143.27"
                },
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {
                    "id": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "price": "0.9998"
                }
            }
        });
        let out = shape_price_response(&raw);
        assert!(out.contains("$143.27"));
        assert!(out.contains("$0.9998"));
        // Should be compact
        assert!(out.len() < 200);
    }

    #[test]
    fn shape_quote_response_compact() {
        let raw = serde_json::json!({
            "inAmount": "1000000",
            "outAmount": "142857000",
            "priceImpactPct": "-0.00123",
            "slippageBps": 50,
            "routePlan": [
                { "swapInfo": { "label": "Raydium" } },
                { "swapInfo": { "label": "Orca" } }
            ]
        });
        let out = shape_quote_response(&raw);
        assert!(out.contains("1000000"));
        assert!(out.contains("142857000"));
        assert!(out.contains("Raydium"));
        assert!(out.contains("Orca"));
        assert!(out.contains("0.50%"));
        assert!(out.len() < 300);
    }

    #[test]
    fn extract_swap_transaction_from_response() {
        let raw = serde_json::json!({
            "swapTransaction": "base64encodedtxdata=="
        });
        assert_eq!(
            extract_swap_transaction(&raw).unwrap(),
            "base64encodedtxdata=="
        );
    }

    #[test]
    fn extract_swap_transaction_missing_errors() {
        let raw = serde_json::json!({ "other": "data" });
        assert!(extract_swap_transaction(&raw).is_err());
    }

    #[test]
    fn outlayer_urls_format_correctly() {
        let cfg = empty_config();
        let addr = build_outlayer_address_url(&cfg);
        assert!(addr.contains("/wallet/v1/address"));
        assert!(addr.contains("chain=solana"));

        let bal = build_outlayer_balance_url(&cfg, "So1111");
        assert!(bal.contains("token=So1111"));
    }

    #[test]
    fn outlayer_transfer_body_structure() {
        let body = build_outlayer_transfer_body("solana", "SOL", "dest_addr", "1000000", "tx_base64==");
        assert_eq!(body["chain"], "solana");
        assert_eq!(body["token"], "SOL");
        assert_eq!(body["tx_data"], "tx_base64==");
    }
}
