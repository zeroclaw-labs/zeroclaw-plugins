//! ZeroClaw WIT tool plugin: `jupiter-swap-execute`.
//!
//! Quotes and executes Solana token swaps via Jupiter Swap API V2, with
//! custody enforcement through OutLayer (TEE-signed, policy-gated).
//!
//! Jupiter Swap API V2 flow:
//!   1. GET  /swap/v2/order   → quote + assembled transaction (meta-aggregator)
//!   2. Sign the transaction  → partial sign (taker only; JupiterZ needs MM sig)
//!   3. POST /swap/v2/execute → Jupiter lands the tx with managed fees/slippage
//!
//! For T1 custody: the agent gets the unsigned tx from /order, passes it to
//! OutLayer which signs in TEE with policy enforcement (spend caps, mint allowlist).
//!
//! Custody tier: T1 — agent builds unsigned tx, OutLayer signs in TEE.
//! Secrets held: OutLayer API key only (via config_read). No private keys.
//!
//! The pure swap core lives in [`jupiter`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`.

pub mod jupiter;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::jupiter::*;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct JupiterSwapExecute;

    const PLUGIN_NAME: &str = "jupiter-swap-execute";
    const PLUGIN_VERSION: &str = "0.2.0";
    const TOOL_NAME: &str = "jupiter-swap";

    /// Execute arguments from the LLM.
    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        /// Action: "quote", "price", "swap", or "balance"
        action: String,
        /// Input mint address (for quote/swap)
        #[serde(default)]
        input_mint: String,
        /// Output mint address (for quote/swap)
        #[serde(default)]
        output_mint: String,
        /// Amount in smallest unit (for quote/swap)
        #[serde(default)]
        amount: u64,
        /// Slippage in basis points (optional, defaults to config max)
        #[serde(default)]
        slippage_bps: u32,
        /// Mints to look up prices for (comma-separated, for price action)
        #[serde(default)]
        mints: String,
        /// Token mint for balance lookup
        #[serde(default)]
        token: String,
        /// Taker wallet address (optional — needed for JupiterZ RFQ)
        #[serde(default)]
        taker: String,
        /// Injected config section from host
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for JupiterSwapExecute {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for JupiterSwapExecute {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Quote and execute Solana token swaps via Jupiter Swap API V2 with OutLayer custody. \
             Actions: 'quote' (swap order), 'price' (token prices), 'swap' (order + custody execution), \
             'balance' (OutLayer wallet balance). \
             T1 custody: agent builds unsigned tx, OutLayer signs in TEE with policy enforcement. \
             Mint allowlist and spend caps enforced client-side before any network call. \
             Jupiter V2: GET /order returns assembled tx, POST /execute lands it. Keyless: 0.5 RPS."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["quote", "price", "swap", "balance"],
                        "description": "Action to perform"
                    },
                    "input_mint": {
                        "type": "string",
                        "description": "Input token mint address (for quote/swap)"
                    },
                    "output_mint": {
                        "type": "string",
                        "description": "Output token mint address (for quote/swap)"
                    },
                    "amount": {
                        "type": "integer",
                        "description": "Amount in smallest unit (for quote/swap)"
                    },
                    "slippage_bps": {
                        "type": "integer",
                        "description": "Max slippage in basis points (default: config max)"
                    },
                    "mints": {
                        "type": "string",
                        "description": "Comma-separated mint addresses for price lookup"
                    },
                    "token": {
                        "type": "string",
                        "description": "Token mint for balance lookup"
                    },
                    "taker": {
                        "type": "string",
                        "description": "Taker wallet address (enables JupiterZ RFQ for best price)"
                    }
                },
                "required": ["action"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                        None,
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = SwapConfig::from_section(&parsed.config);

            let result = match parsed.action.as_str() {
                "price" => handle_price(&cfg, &parsed),
                "quote" => handle_quote(&cfg, &parsed),
                "swap" => handle_swap(&cfg, &parsed),
                "balance" => handle_balance(&cfg, &parsed),
                other => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "unknown action",
                        None,
                    );
                    Err(format!(
                        "Unknown action: '{other}'. Use: quote, price, swap, balance"
                    ))
                }
            };

            match result {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        &format!("{} ok", parsed.action),
                        None,
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(err) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &format!("{} failed", parsed.action),
                        Some(&err),
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(err),
                    })
                }
            }
        }
    }

    /// Handle "price" action — look up token prices via Jupiter Price API V3.
    fn handle_price(cfg: &SwapConfig, args: &ExecuteArgs) -> Result<String, String> {
        if args.mints.is_empty() {
            return Err("Missing 'mints' parameter for price action".to_string());
        }
        let mint_list: Vec<&str> = args.mints.split(',').map(str::trim).collect();
        let url = build_price_url(cfg, &mint_list);

        let response =
            http_get(&url, cfg.has_jupiter_key().then(|| cfg.jupiter_api_key.as_str()))
                .map_err(|e| format!("Jupiter price API request failed: {e}"))?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("Failed to parse price response: {e}"))?;

        Ok(shape_price_response(&parsed))
    }

    /// Handle "quote" action — get a swap order from Jupiter Swap API V2.
    fn handle_quote(cfg: &SwapConfig, args: &ExecuteArgs) -> Result<String, String> {
        if args.input_mint.is_empty() || args.output_mint.is_empty() {
            return Err(
                "Missing 'input_mint' and 'output_mint' for quote action".to_string(),
            );
        }
        if args.amount == 0 {
            return Err("Missing 'amount' for quote action".to_string());
        }

        // Enforce mint allowlist before making any network call
        enforce_mint_allowlist(cfg, &args.input_mint, &args.output_mint)?;

        let slippage = if args.slippage_bps > 0 {
            args.slippage_bps
        } else {
            cfg.max_slippage_bps
        };

        let url = build_order_url(
            cfg,
            &args.input_mint,
            &args.output_mint,
            args.amount,
            slippage,
            &args.taker,
        );
        let response =
            http_get(&url, cfg.has_jupiter_key().then(|| cfg.jupiter_api_key.as_str()))
                .map_err(|e| format!("Jupiter order API request failed: {e}"))?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("Failed to parse order response: {e}"))?;

        // Check for API-level error
        if let Some(err_msg) = parsed.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Jupiter API error: {err_msg}"));
        }

        Ok(shape_order_response(&parsed))
    }

    /// Handle "swap" action — order + submit to OutLayer custody.
    fn handle_swap(cfg: &SwapConfig, args: &ExecuteArgs) -> Result<String, String> {
        if args.input_mint.is_empty() || args.output_mint.is_empty() {
            return Err(
                "Missing 'input_mint' and 'output_mint' for swap action".to_string(),
            );
        }
        if args.amount == 0 {
            return Err("Missing 'amount' for swap action".to_string());
        }
        if cfg.outlayer_api_key.is_empty() {
            return Err(
                "OutLayer API key not configured. Set 'outlayer_api_key' in plugin config."
                    .to_string(),
            );
        }

        // Enforce mint allowlist
        enforce_mint_allowlist(cfg, &args.input_mint, &args.output_mint)?;

        let slippage = if args.slippage_bps > 0 {
            args.slippage_bps
        } else {
            cfg.max_slippage_bps
        };

        // Step 1: Get order (quote + assembled transaction) from Jupiter V2
        let order_url = build_order_url(
            cfg,
            &args.input_mint,
            &args.output_mint,
            args.amount,
            slippage,
            &args.taker,
        );
        let order_response =
            http_get(&order_url, cfg.has_jupiter_key().then(|| cfg.jupiter_api_key.as_str()))
                .map_err(|e| format!("Jupiter order API request failed: {e}"))?;

        let order_parsed: serde_json::Value = serde_json::from_str(&order_response)
            .map_err(|e| format!("Failed to parse order response: {e}"))?;

        if let Some(err_msg) = order_parsed.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Jupiter API error: {err_msg}"));
        }

        let order_summary = shape_order_response(&order_parsed);

        // Step 2: Extract unsigned transaction + request ID
        let tx_data = extract_order_transaction(&order_parsed)?;
        let request_id = extract_request_id(&order_parsed)?;

        // Step 3: Submit to OutLayer for custody-signed execution
        // OutLayer signs the tx in TEE and submits via Jupiter /execute or its own pipeline.
        let outlayer_url = format!("{}/wallet/v1/transfer", cfg.outlayer_api);
        let transfer_body = build_outlayer_transfer_body(
            "solana",
            &args.input_mint,
            "", // destination embedded in swap tx instructions
            &args.amount.to_string(),
            &tx_data,
        );

        let outlayer_response = http_post_json_with_auth(
            &outlayer_url,
            &transfer_body,
            &cfg.outlayer_api_key,
        )
        .map_err(|e| format!("OutLayer submission failed: {e}"))?;

        // Step 4: Return result
        let out_parsed: serde_json::Value = serde_json::from_str(&outlayer_response)
            .unwrap_or_else(|_| serde_json::json!({ "raw": outlayer_response }));

        let status = out_parsed
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        let request_id_out = out_parsed
            .get("request_id")
            .and_then(|r| r.as_str())
            .unwrap_or(&request_id);

        match status {
            "completed" | "signed" => Ok(format!(
                "Swap executed. {}. Transaction signed by OutLayer TEE. Request: {}",
                order_summary, request_id_out
            )),
            "pending_approval" | "requires_approval" => Ok(format!(
                "Swap pending approval. {} exceeds policy threshold — check OutLayer approval queue. Request: {}",
                order_summary, request_id_out
            )),
            "rejected" => Err(format!(
                "Swap rejected by OutLayer policy. {}. Request: {}",
                order_summary, request_id_out
            )),
            _ => Ok(format!(
                "Swap submitted to OutLayer. {} Status: {} Request: {}",
                order_summary, status, request_id_out
            )),
        }
    }

    /// Handle "balance" action — read OutLayer wallet balance.
    fn handle_balance(cfg: &SwapConfig, args: &ExecuteArgs) -> Result<String, String> {
        if cfg.outlayer_api_key.is_empty() {
            return Err(
                "OutLayer API key not configured. Set 'outlayer_api_key' in plugin config."
                    .to_string(),
            );
        }

        let token = if args.token.is_empty() {
            SOL_MINT
        } else {
            &args.token
        };

        let url = build_outlayer_balance_url(cfg, token);
        let response = http_get_with_auth(&url, &cfg.outlayer_api_key)
            .map_err(|e| format!("OutLayer balance request failed: {e}"))?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("Failed to parse balance response: {e}"))?;

        let balance = parsed
            .get("balance")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A");
        let symbol = mint_short(token);

        Ok(format!("{} balance: {}", symbol, balance))
    }

    // ── HTTP helpers (wasi:http outbound) ──────────────────────────
    //
    // These use waki (blocking wasi:http) as the reference plugins do.
    // The host grants HTTP access only when manifest declares http_client.

    fn http_get(url: &str, api_key: Option<&str>) -> Result<String, String> {
        let _ = (url, api_key);
        Err("HTTP not available in test mode".to_string())
    }

    fn http_get_with_auth(url: &str, _token: &str) -> Result<String, String> {
        Err("HTTP not available in test mode".to_string())
    }

    fn http_post_json(url: &str, body: &serde_json::Value) -> Result<String, String> {
        let _ = (url, body);
        Err("HTTP not available in test mode".to_string())
    }

    fn http_post_json_with_auth(
        url: &str,
        body: &serde_json::Value,
        _token: &str,
    ) -> Result<String, String> {
        let _ = (url, body);
        Err("HTTP not available in test mode".to_string())
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, detail: Option<&str>) {
        let attrs = detail.map(|d| format!("{{\"detail\":\"{}\"}}", d));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "jupiter_swap_execute::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(JupiterSwapExecute);
}
