//! Pure Jupiter swap core. No wit-bindgen or wasm dependency so it compiles
//! and tests on the host with `cargo test`.
//!
//! Jupiter Swap API V2: https://api.jup.ag/swap/v2
//!   - GET /order → quote + assembled transaction (meta-aggregator)
//!   - POST /execute → managed landing (sign + submit)
//!
//! Jupiter Price API V3: https://api.jup.ag/price/v3
//!   - GET ?ids={mints} → USD prices + 24h change
//!
//! Keyless access: 0.5 RPS without API key. Production: x-api-key header.

use std::collections::HashMap;

// ── Well-known mints ──────────────────────────────────────────────────

pub const SOL_MINT: &str = "So11111111111111111111111111111111111111112"; // 43 chars: wrapped SOL
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

// ── Config ────────────────────────────────────────────────────────────

/// Plugin config resolved from the host's jailed config section.
#[derive(Debug, Clone)]
pub struct SwapConfig {
    /// Jupiter API base URL (Swap API V2).
    pub swap_api: String,
    /// Jupiter Price API V3 URL.
    pub price_api: String,
    /// Optional Jupiter API key for higher rate limits.
    pub jupiter_api_key: String,
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
        let swap_api = section
            .get("swap_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://api.jup.ag/swap/v2".to_string());
        let price_api = section
            .get("price_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://api.jup.ag/price/v3".to_string());
        let jupiter_api_key = section
            .get("jupiter_api_key")
            .cloned()
            .unwrap_or_default();
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
            swap_api,
            price_api,
            jupiter_api_key,
            outlayer_api,
            outlayer_api_key,
            max_slippage_bps,
            allowed_mints,
            daily_spend_cap_usd,
        }
    }

    /// Whether we have a Jupiter API key (higher rate limits).
    pub fn has_jupiter_key(&self) -> bool {
        !self.jupiter_api_key.is_empty()
    }
}

// ── Request builders ──────────────────────────────────────────────────

/// Build Jupiter Price API V3 URL.
/// GET {price_api}?ids={mints}
pub fn build_price_url(cfg: &SwapConfig, mints: &[&str]) -> String {
    let ids = mints.join(",");
    format!("{}?ids={}", cfg.price_api, ids)
}

/// Build Jupiter Swap API V2 order URL (meta-aggregator).
/// GET {swap_api}/order?inputMint=..&outputMint=..&amount=..&slippageBps=..
pub fn build_order_url(
    cfg: &SwapConfig,
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: u32,
    taker: &str,
) -> String {
    let slippage = slippage_bps.min(cfg.max_slippage_bps);
    let mut url = format!(
        "{}/order?inputMint={}&outputMint={}&amount={}&slippageBps={}",
        cfg.swap_api, input_mint, output_mint, amount, slippage
    );
    if !taker.is_empty() {
        url.push_str(&format!("&taker={taker}"));
    }
    url
}

/// Build Jupiter Swap API V2 execute request body.
/// POST {swap_api}/execute
pub fn build_execute_body(
    signed_transaction: &str,
    request_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "signedTransaction": signed_transaction,
        "requestId": request_id,
    })
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

/// Build OutLayer Solana sign-transaction request body.
/// POST {outlayer_api}/wallet/v1/solana/sign-transaction
///
/// OutLayer signs the tx message (base64) with its TEE-held ed25519 key.
/// Returns a base58 signature. Caller assembles + broadcasts.
pub fn build_outlayer_solana_sign_body(unsigned_tx_base64: &str) -> serde_json::Value {
    serde_json::json!({
        "chain": "solana",
        "unsigned_tx": unsigned_tx_base64
    })
}

/// Shape an OutLayer Solana sign response into a compact string.
/// Response: { signature: base58, chain: "solana", wallet_id: uuid }
pub fn shape_outlayer_sign_response(raw: &serde_json::Value) -> String {
    let signature = raw
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let wallet_id = raw
        .get("wallet_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    format!("Signed by OutLayer ({}). Sig: {}", wallet_id, signature)
}

// ── Output shaping ────────────────────────────────────────────────────

/// Shape a Jupiter Price API V3 response into a compact string for the LLM.
/// V3 format: { "mint": { "usdPrice": f64, "priceChange24h": f64, ... } }
/// Target: ~200 tokens.
pub fn shape_price_response(raw: &serde_json::Value) -> String {
    let prices = raw.as_object().filter(|m| !m.is_empty());
    if let Some(prices) = prices {
        let mut lines = Vec::new();
        for (mint, info) in prices {
            let usd_price = info.get("usdPrice").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let change_24h = info
                .get("priceChange24h")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let sign = if change_24h >= 0.0 { "+" } else { "" };
            let symbol = mint_short(mint);
            lines.push(format!(
                "{}: ${:.2} (24h: {}{:.2}%)",
                symbol, usd_price, sign, change_24h
            ));
        }
        lines.join(", ")
    } else {
        "No prices found.".to_string()
    }
}

/// Shape a Jupiter Swap API V2 order response into a compact string for the LLM.
/// V2 /order format: { requestId, outAmount, router, mode, feeBps, ... }
pub fn shape_order_response(raw: &serde_json::Value) -> String {
    let out_amount = raw
        .get("outAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let router = raw
        .get("router")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let fee_bps = raw
        .get("feeBps")
        .and_then(|v| v.as_number())
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let has_tx = raw
        .get("transaction")
        .and_then(|v| v.as_str())
        .map_or(false, |s| !s.is_empty() && s != "null");

    let fee_display = fee_bps as f64 / 100.0;
    let tx_status = if has_tx { "ready to sign" } else { "quote-only" };

    format!(
        "Order: {} out. Router: {}. Fee: {:.2} bps ({}). {}.",
        out_amount, router, fee_display, tx_status, tx_status
    )
}

/// Shape a Jupiter execute response into a compact string.
/// V2 /execute format: { status, signature, totalInputAmount, totalOutputAmount, ... }
pub fn shape_execute_response(raw: &serde_json::Value) -> String {
    let status = raw
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let signature = raw
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let total_in = raw
        .get("totalInputAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let total_out = raw
        .get("totalOutputAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("?");

    match status {
        "Success" => format!(
            "Swap executed. In: {} Out: {}. Tx: {}",
            total_in, total_out, signature
        ),
        _ => format!(
            "Swap {}: in {} out {}. Tx: {}",
            status.to_lowercase(),
            total_in,
            total_out,
            signature
        ),
    }
}

/// Extract the base64 transaction from a Jupiter /order response.
pub fn extract_order_transaction(order_response: &serde_json::Value) -> Result<String, String> {
    order_response
        .get("transaction")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "null")
        .map(|s| s.to_string())
        .ok_or_else(|| {
            let code = order_response
                .get("errorCode")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let msg = order_response
                .get("errorMessage")
                .and_then(|v| v.as_str())
                .unwrap_or("No transaction in response");
            format!("Order error ({}): {}", code, msg)
        })
}

/// Extract the request ID from a Jupiter /order response.
pub fn extract_request_id(order_response: &serde_json::Value) -> Result<String, String> {
    order_response
        .get("requestId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No requestId in order response".to_string())
}

// ── Mint allowlist enforcement ───────────────────────────────────────

/// Check if a mint is in the allowlist. Empty allowlist = allow all.
pub fn is_mint_allowed(cfg: &SwapConfig, mint: &str) -> bool {
    cfg.allowed_mints.is_empty()
        || cfg
            .allowed_mints
            .iter()
            .any(|m| *m == mint.to_lowercase())
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

/// Shorten a mint address for display: "So11111111111111111111111111111111111111112" → "So1111..."
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
        let section: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        SwapConfig::from_section(&section)
    }

    #[test]
    fn empty_config_has_safe_defaults() {
        let cfg = empty_config();
        assert_eq!(cfg.swap_api, "https://api.jup.ag/swap/v2");
        assert_eq!(cfg.price_api, "https://api.jup.ag/price/v3");
        assert_eq!(cfg.outlayer_api, "https://api.outlayer.fastnear.com");
        assert!(cfg.jupiter_api_key.is_empty());
        assert!(!cfg.has_jupiter_key());
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
            (
                "allowed_mints",
                "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            ),
            ("jupiter_api_key", "test_key"),
        ]);
        assert_eq!(cfg.max_slippage_bps, 100);
        assert_eq!(cfg.daily_spend_cap_usd, 1000.0);
        assert_eq!(cfg.allowed_mints.len(), 2);
        assert!(cfg.has_jupiter_key());
    }

    #[test]
    fn empty_allowlist_allows_everything() {
        let cfg = empty_config();
        assert!(is_mint_allowed(&cfg, "any_random_mint_address"));
    }

    #[test]
    fn non_empty_allowlist_blocks_unlisted_mints() {
        let cfg = config_with(&[("allowed_mints", SOL_MINT)]);
        assert!(is_mint_allowed(&cfg, SOL_MINT));
        assert!(!is_mint_allowed(&cfg, "random_bad_mint"));
    }

    #[test]
    fn enforce_allowlist_passes_for_allowed() {
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let cfg = config_with(&[(
            "allowed_mints",
            "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        )]);
        assert!(enforce_mint_allowlist(&cfg, SOL_MINT, usdc).is_ok());
    }

    #[test]
    fn enforce_allowlist_blocks_bad_mint() {
        let bad = "9xyzFAKEtokenMintAddress";
        let cfg = config_with(&[("allowed_mints", SOL_MINT)]);
        let result = enforce_mint_allowlist(&cfg, SOL_MINT, bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowlist"));
    }

    // ── Price V3 ──

    #[test]
    fn build_price_url_uses_v3() {
        let cfg = empty_config();
        let url = build_price_url(&cfg, &[SOL_MINT, USDC_MINT]);
        assert!(url.contains("price/v3"));
        assert!(url.contains("ids="));
        assert!(url.contains("So1111"));
        assert!(url.contains("EPjFWdd"));
    }

    #[test]
    fn shape_price_v3_response_compact() {
        let raw = serde_json::json!({
            "So11111111111111111111111111111111111111112": {
                "usdPrice": 143.27,
                "decimals": 9,
                "priceChange24h": 1.29
            },
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {
                "usdPrice": 0.9998,
                "decimals": 6,
                "priceChange24h": -0.15
            }
        });
        let out = shape_price_response(&raw);
        assert!(out.contains("$143.27"));
        assert!(out.contains("+1.29%"));
        assert!(out.contains("$1.00"));
        assert!(out.contains("-0.15%"));
        assert!(out.len() < 300);
    }

    #[test]
    fn shape_price_v3_empty_returns_message() {
        let raw = serde_json::json!({});
        let out = shape_price_response(&raw);
        assert_eq!(out, "No prices found.");
    }

    // ── Swap V2 /order ──

    #[test]
    fn build_order_url_uses_v2() {
        let cfg = empty_config();
        let url = build_order_url(&cfg, SOL_MINT, USDC_MINT, 100000000, 50, "");
        assert!(url.contains("swap/v2/order"));
        assert!(url.contains("inputMint=So1111"));
        assert!(url.contains("outputMint=EPjFWdd"));
        assert!(url.contains("amount=100000000"));
        assert!(url.contains("slippageBps=50"));
    }

    #[test]
    fn build_order_url_includes_taker() {
        let cfg = empty_config();
        let url = build_order_url(&cfg, SOL_MINT, USDC_MINT, 100000000, 50, "my_wallet_addr");
        assert!(url.contains("taker=my_wallet_addr"));
    }

    #[test]
    fn build_order_url_clamps_slippage() {
        let cfg = config_with(&[("max_slippage_bps", "50")]);
        let url = build_order_url(&cfg, SOL_MINT, USDC_MINT, 1000000, 500, "");
        assert!(url.contains("slippageBps=50"));
    }

    #[test]
    fn shape_order_response_compact() {
        let raw = serde_json::json!({
            "requestId": "req_abc123",
            "outAmount": "14285714300",
            "router": "jupiterz",
            "mode": "ultra",
            "feeBps": 30,
            "feeMint": "So11111111111111111111111111111111111111112",
            "transaction": "base64txdata"
        });
        let out = shape_order_response(&raw);
        assert!(out.contains("14285714300"));
        assert!(out.contains("jupiterz"));
        assert!(out.contains("0.30"));
        assert!(out.contains("ready to sign"));
        assert!(out.len() < 300);
    }

    #[test]
    fn shape_order_response_quote_only() {
        let raw = serde_json::json!({
            "requestId": "req_xyz",
            "outAmount": "50000",
            "router": "metis",
            "mode": "manual",
            "feeBps": 0,
            "transaction": ""
        });
        let out = shape_order_response(&raw);
        assert!(out.contains("quote-only"));
        assert!(out.contains("metis"));
    }

    #[test]
    fn extract_order_transaction_success() {
        let raw = serde_json::json!({
            "transaction": "aGVsbG8gd29ybGQ=",
            "requestId": "req_1"
        });
        assert_eq!(extract_order_transaction(&raw).unwrap(), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn extract_order_transaction_null_fails() {
        let raw = serde_json::json!({
            "transaction": null,
            "requestId": "req_2"
        });
        assert!(extract_order_transaction(&raw).is_err());
    }

    #[test]
    fn extract_order_transaction_error_message() {
        let raw = serde_json::json!({
            "transaction": "",
            "errorCode": 42,
            "errorMessage": "Insufficient liquidity"
        });
        let err = extract_order_transaction(&raw).unwrap_err();
        assert!(err.contains("42"));
        assert!(err.contains("Insufficient liquidity"));
    }

    #[test]
    fn extract_request_id_success() {
        let raw = serde_json::json!({ "requestId": "req_abc" });
        assert_eq!(extract_request_id(&raw).unwrap(), "req_abc");
    }

    #[test]
    fn extract_request_id_missing_fails() {
        let raw = serde_json::json!({ "noId": "here" });
        assert!(extract_request_id(&raw).is_err());
    }

    // ── Swap V2 /execute ──

    #[test]
    fn build_execute_body_structure() {
        let body = build_execute_body("signed_tx_base64", "req_123");
        assert_eq!(body["signedTransaction"], "signed_tx_base64");
        assert_eq!(body["requestId"], "req_123");
    }

    #[test]
    fn shape_execute_response_success() {
        let raw = serde_json::json!({
            "status": "Success",
            "signature": "5Kt8...abc",
            "totalInputAmount": "100000000",
            "totalOutputAmount": "14285714300"
        });
        let out = shape_execute_response(&raw);
        assert!(out.contains("Swap executed"));
        assert!(out.contains("100000000"));
        assert!(out.contains("14285714300"));
        assert!(out.contains("5Kt8"));
        assert!(out.len() < 300);
    }

    #[test]
    fn shape_execute_response_failed() {
        let raw = serde_json::json!({
            "status": "Failed",
            "signature": "",
            "error": "Slippage exceeded"
        });
        let out = shape_execute_response(&raw);
        assert!(out.contains("failed"));
    }

    // ── OutLayer ──

    #[test]
    fn outlayer_address_url_has_solana_chain() {
        let cfg = empty_config();
        let url = build_outlayer_address_url(&cfg);
        assert!(url.contains("/wallet/v1/address"));
        assert!(url.contains("chain=solana"));
    }

    #[test]
    fn outlayer_balance_url_includes_token() {
        let cfg = empty_config();
        let url = build_outlayer_balance_url(&cfg, USDC_MINT);
        assert!(url.contains("EPjFWdd"));
        assert!(url.contains("chain=solana"));
    }

    #[test]
    fn outlayer_solana_sign_body_serializes() {
        let body = build_outlayer_solana_sign_body("dGVzdA==");
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(serialized.contains("\"chain\":\"solana\""));
        assert!(serialized.contains("\"unsigned_tx\":\"dGVzdA==\""));
        assert!(serialized.len() < 200);
    }

    #[test]
    fn outlayer_sign_response_shaping() {
        let raw = serde_json::json!({
            "signature": "5Kt8abc123sig",
            "chain": "solana",
            "wallet_id": "450290fb-a7ae-4744-8251-61e29ba12e15"
        });
        let out = shape_outlayer_sign_response(&raw);
        assert!(out.contains("450290fb"));
        assert!(out.contains("5Kt8abc123sig"));
    }

    // ── Helpers ──

    #[test]
    fn mint_short_truncates_long_addresses() {
        assert_eq!(mint_short(USDC_MINT), "EPjFWdd5");
    }

    #[test]
    fn mint_short_preserves_short_addresses() {
        assert_eq!(mint_short("short"), "short");
    }

    #[test]
    fn well_known_mints_are_correct() {
        assert!(SOL_MINT.starts_with("So1111"));
        assert!(USDC_MINT.starts_with("EPjFWdd"));
        // Standard wrapped SOL mint (43 chars)
        assert_eq!(SOL_MINT.len(), 43);
        // Standard USDC mint (44 chars)
        assert_eq!(USDC_MINT.len(), 44);
    }
}
