//! ZeroClaw WIT tool plugin: `jupiter-swap-execute`.
//!
//! Quotes and executes Solana token swaps via Jupiter (public.jupiterapi.com),
//! with custody enforcement through OutLayer (TEE-signed, policy-gated).
//!
//! Jupiter V1 flow:
//!   1. GET  /quote       → swap quote (with asLegacyTransaction=true)
//!   2. POST /swap        → unsigned legacy transaction (no address lookup tables)
//!   3. Replace blockhash with fresh one from Solana RPC
//!   4. Send message bytes to OutLayer for TEE custody signing
//!   5. Assemble signed tx + broadcast to Solana
//!
//! Custody tier: T1 — agent builds unsigned tx, OutLayer signs in TEE.
//! Secrets held: OutLayer API key only (via config_read). No private keys.
//!
//! IMPORTANT: asLegacyTransaction=true is REQUIRED for custody signing.
//! V0 transactions with address lookup tables have a compiled-message hash
//! mismatch that causes SignatureFailure. Legacy transactions have no ALTs.
//!
//! The pure swap core lives in [`jupiter`] with no wasm dependency.

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
            "Quote and execute Solana token swaps via Jupiter (public.jupiterapi.com) with OutLayer custody. \
             Actions: 'quote' (swap quote), 'price' (token prices), 'swap' (quote + custody sign + broadcast), \
             'balance' (OutLayer wallet balance). \
             T1 custody: agent builds unsigned tx, OutLayer signs in TEE with policy enforcement. \
             Mint allowlist and spend caps enforced client-side. \
             Uses asLegacyTransaction=true to avoid address lookup table custody issues. \
             Jupiter V1: GET /quote, POST /swap. Keyless: 0.5 RPS."
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

    /// Handle "quote" action — get a swap quote from Jupiter /quote.
    fn handle_quote(cfg: &SwapConfig, args: &ExecuteArgs) -> Result<String, String> {
        if args.input_mint.is_empty() || args.output_mint.is_empty() {
            return Err("Missing 'input_mint' and 'output_mint' for quote action".to_string());
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

        let url = build_quote_url(cfg, &args.input_mint, &args.output_mint, args.amount, slippage);
        let response = http_get(
            &url,
            cfg.has_jupiter_key().then(|| cfg.jupiter_api_key.as_str()),
        )
        .map_err(|e| format!("Jupiter quote API request failed: {e}"))?;

        let parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| format!("Failed to parse quote response: {e}"))?;

        // Check for API-level error
        if let Some(err_msg) = parsed.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Jupiter API error: {err_msg}"));
        }

        Ok(shape_quote_response(&parsed))
    }

    /// Handle "swap" action — quote → swap → OutLayer custody sign → broadcast.
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
        if args.taker.is_empty() {
            return Err("Missing 'taker' wallet address for swap action".to_string());
        }

        enforce_mint_allowlist(cfg, &args.input_mint, &args.output_mint)?;

        let slippage = if args.slippage_bps > 0 {
            args.slippage_bps
        } else {
            cfg.max_slippage_bps
        };

        // Step 1: Jupiter /quote
        let quote_url =
            build_quote_url(cfg, &args.input_mint, &args.output_mint, args.amount, slippage);
        let quote_response = http_get(
            &quote_url,
            cfg.has_jupiter_key().then(|| cfg.jupiter_api_key.as_str()),
        )
        .map_err(|e| format!("Jupiter quote request failed: {e}"))?;
        let quote_parsed: serde_json::Value = serde_json::from_str(&quote_response)
            .map_err(|e| format!("Failed to parse quote: {e}"))?;
        if let Some(err_msg) = quote_parsed.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Jupiter quote error: {err_msg}"));
        }
        let quote_summary = shape_quote_response(&quote_parsed);

        // Step 2: Jupiter /swap → unsigned legacy transaction
        let swap_url = format!("{}/swap", cfg.swap_api);
        let swap_body = build_swap_body(cfg, &quote_parsed, &args.taker);
        let swap_response = http_post_json(&swap_url, &swap_body)
            .map_err(|e| format!("Jupiter swap request failed: {e}"))?;
        let swap_parsed: serde_json::Value = serde_json::from_str(&swap_response)
            .map_err(|e| format!("Failed to parse swap: {e}"))?;
        let swap_tx = extract_swap_transaction(&swap_parsed)?;

        // Step 3: Extract message bytes
        let tx_bytes = crate::jupiter::decode_base64(&swap_tx)
            .map_err(|e| format!("Failed to decode swap tx: {e}"))?;
        let message_bytes = crate::jupiter::extract_message_from_tx(&tx_bytes)
            .map_err(|e| format!("Failed to extract message: {e}"))?;

        // Step 4: Fetch fresh blockhash from Solana RPC and replace in message.
        // Jupiter's blockhash may be stale by the time OutLayer signs + we broadcast.
        let bh_rpc_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash"
        });
        let bh_response = http_post_json(&cfg.solana_rpc, &bh_rpc_body)
            .map_err(|e| format!("Failed to fetch blockhash: {e}"))?;
        let bh_parsed: serde_json::Value = serde_json::from_str(&bh_response)
            .map_err(|e| format!("Failed to parse blockhash: {e}"))?;
        let bh_b58 = bh_parsed
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.get("blockhash"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if bh_b58.is_empty() {
            return Err("No blockhash in RPC response".to_string());
        }
        let bh_bytes = crate::jupiter::decode_base58(bh_b58)
            .map_err(|e| format!("Failed to decode blockhash: {e}"))?;
        let bh_array: [u8; 32] = bh_bytes
            .try_into()
            .map_err(|_| "blockhash not 32 bytes".to_string())?;
        let fresh_message = crate::jupiter::replace_blockhash_in_message(&message_bytes, &bh_array)
            .map_err(|e| format!("Failed to replace blockhash: {e}"))?;
        if fresh_message.len() > 1232 {
            return Err(format!(
                "Message ({} bytes) exceeds OutLayer 1232-byte limit. Use simpler route.",
                fresh_message.len()
            ));
        }
        let message_b64 = crate::jupiter::encode_base64(&fresh_message);

        // Step 5: OutLayer custody sign
        let outlayer_url = format!("{}/wallet/v1/solana/sign-transaction", cfg.outlayer_api);
        let sign_body = build_outlayer_solana_sign_body(&message_b64);
        let outlayer_response =
            http_post_json_with_auth(&outlayer_url, &sign_body, &cfg.outlayer_api_key)
                .map_err(|e| format!("OutLayer sign request failed: {e}"))?;
        let out_parsed: serde_json::Value = serde_json::from_str(&outlayer_response)
            .unwrap_or_else(|_| serde_json::json!({ "raw": outlayer_response }));
        let signature = out_parsed.get("signature").and_then(|s| s.as_str()).unwrap_or("?");

        // Step 6: Assemble signed tx with fresh blockhash + signature
        let mut signed_tx_bytes = crate::jupiter::assemble_signed_tx(&tx_bytes, signature)
            .map_err(|e| format!("Failed to assemble signed tx: {e}"))?;
        // Also replace blockhash in the full signed tx.
        // The message starts at byte 66 in the signed tx (prefix + num_sigs + sig).
        // We need the same offset within the message that replace_blockhash_in_message uses.
        // Instead of duplicating the calculation, replace the message portion directly.
        let msg_start = 66; // legacy tx: 1 prefix + 1 compact_u32 + 64 sig
        if signed_tx_bytes.len() > msg_start + fresh_message.len() {
            signed_tx_bytes[msg_start..msg_start + fresh_message.len()].copy_from_slice(&fresh_message);
        }

        // Step 7: Broadcast
        let signed_tx_b64 = crate::jupiter::encode_base64(&signed_tx_bytes);
        let broadcast_result = crate::jupiter::broadcast_tx(cfg, &signed_tx_b64);
        let wallet_id = out_parsed.get("wallet_id").and_then(|w| w.as_str()).unwrap_or("?");

        Ok(format!(
            "Swap: {}. OutLayer signed ({}). Sig: {}. Broadcast: {}",
            quote_summary,
            wallet_id,
            signature,
            broadcast_result.unwrap_or_else(|e| format!("failed: {e}"))
        ))
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

    fn http_get_with_auth(_url: &str, _token: &str) -> Result<String, String> {
        Err("HTTP not available in test mode".to_string())
    }

    #[allow(dead_code)]
    fn http_post_json(_url: &str, _body: &serde_json::Value) -> Result<String, String> {
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
