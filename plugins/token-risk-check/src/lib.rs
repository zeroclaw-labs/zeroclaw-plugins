//! A ZeroClaw WIT tool plugin: `check_token_risk`.
//!
//! Fetches an SPL Token mint account plus its largest holders, then returns
//! a compact red/amber/green verdict: is the freeze authority still active,
//! is the mint authority still active, how concentrated is supply among the
//! top holders. T0 custody tier -- read-only, no keys, no signing, no
//! outbound funds.
//!
//! The pure risk-assessment core lives in `core` with no wasm dependency,
//! so it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through a thin shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::core::{
        assess_risk, compute_concentration, decode_mint_account, format_summary,
        validate_mint_address, Config, HolderBalance,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "check_token_risk";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check a Solana SPL token mint for red-flag risk conditions: active freeze \
             authority, active mint authority, and holder concentration. Returns a \
             red/amber/green verdict with reasons. Read-only: this tool never holds \
             keys, never signs, and never moves funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The base58 SPL token mint address to check."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            if let Err(e) = validate_mint_address(&parsed.mint) {
                emit(PluginAction::Fail, PluginOutcome::Failure, "invalid mint address", None);
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("invalid mint address: {e}")),
                });
            }

            let cfg = Config::from_section(&parsed.config);

            let account_data = match fetch_mint_account(&cfg.rpc_url, &parsed.mint) {
                Ok(data) => data,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "rpc fetch failed", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            let mint_info = match decode_mint_account(&account_data) {
                Ok(info) => info,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "decode failed", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            let holders = fetch_largest_holders(&cfg.rpc_url, &parsed.mint).unwrap_or_default();
            let concentration = compute_concentration(&holders, mint_info.supply);
            let verdict = assess_risk(&mint_info, &concentration);
            let summary = format_summary(&parsed.mint, &mint_info, &verdict);

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "risk check complete",
                Some(verdict.level.as_str()),
            );

            Ok(ToolResult { success: true, output: summary, error: None })
        }
    }

    fn fetch_mint_account(rpc_url: &str, mint: &str) -> Result<Vec<u8>, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [mint, {"encoding": "base64"}]
        });

        let resp = waki::Client::new()
            .post(rpc_url)
            .json(&body)
            .connect_timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| format!("rpc request failed: {e}"))?;

        let text = resp.body().map_err(|e| format!("reading rpc response failed: {e}"))?;
        let text = String::from_utf8(text).map_err(|e| format!("rpc response not utf8: {e}"))?;
        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("rpc response not json: {e}"))?;

        let data_b64 = json
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.get("data"))
            .and_then(|d| d.get(0))
            .and_then(|d| d.as_str())
            .ok_or_else(|| "mint account not found or malformed response".to_string())?;

        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| format!("account data not valid base64: {e}"))
    }

    fn fetch_largest_holders(rpc_url: &str, mint: &str) -> Result<Vec<HolderBalance>, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenLargestAccounts",
            "params": [mint]
        });

        let resp = waki::Client::new()
            .post(rpc_url)
            .json(&body)
            .connect_timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| format!("rpc request failed: {e}"))?;

        let text = resp.body().map_err(|e| format!("reading rpc response failed: {e}"))?;
        let text = String::from_utf8(text).map_err(|e| format!("rpc response not utf8: {e}"))?;
        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("rpc response not json: {e}"))?;

        let values = json
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| "no holder data in response".to_string())?;

        let holders = values
            .iter()
            .filter_map(|v| v.get("amount").and_then(|a| a.as_str()))
            .filter_map(|s| s.parse::<u64>().ok())
            .map(|amount| HolderBalance { amount })
            .collect();

        Ok(holders)
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, verdict: Option<&str>) {
        let attrs = verdict.map(|v| format!("{{\"verdict\":\"{v}\"}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
