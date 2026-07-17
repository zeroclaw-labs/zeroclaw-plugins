//! ZeroClaw `token-risk-check` tool plugin.
//!
//! The component performs read-only Solana RPC and public DEX lookups. It never
//! accepts a transaction, secret key, or signing instruction. Risk scoring is
//! implemented in the host-testable [`risk`] module; this file is only the WIT
//! and HTTP shim.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde::Deserialize;
    use serde_json::{json, Value};

    use crate::risk::{analyze_responses, rpc_request, validate_mint};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = "0.1.0";
    const TOOL_NAME: &str = "token-risk-check";
    const DEFAULT_DEX_URL: &str = "https://api.dexscreener.com/latest/dex/tokens";

    struct TokenRiskCheck;

    #[derive(Deserialize)]
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
            "Read-only Solana token risk screening. Checks mint/freeze authority, holder-account concentration, DEX liquidity, and Token-2022 extensions. Never signs or submits transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 Solana token mint address"
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(err) => return Ok(failure(format!("invalid arguments: {err}"))),
            };
            if let Err(err) = validate_mint(&parsed.mint) {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "invalid mint",
                    None,
                );
                return Ok(failure(err));
            }

            let Some(rpc_url) = parsed
                .config
                .get("rpc_url")
                .filter(|v| !v.trim().is_empty())
            else {
                return Ok(failure(
                    "missing plugin config: rpc_url must be an HTTPS Solana RPC endpoint"
                        .to_string(),
                ));
            };
            if !is_https_endpoint(rpc_url) {
                return Ok(failure("rpc_url must use HTTPS".to_string()));
            }
            let dex_url = parsed
                .config
                .get("dex_url")
                .map(String::as_str)
                .unwrap_or(DEFAULT_DEX_URL);
            if !is_https_endpoint(dex_url) {
                return Ok(failure("dex_url must use HTTPS".to_string()));
            }

            let mint_account = match post_rpc(
                rpc_url,
                &rpc_request(
                    "getAccountInfo",
                    json!([parsed.mint, {"encoding": "jsonParsed"}]),
                    1,
                ),
            ) {
                Ok(value) => value,
                Err(err) => return Ok(failure(err)),
            };
            let supply = match post_rpc(
                rpc_url,
                &rpc_request(
                    "getTokenSupply",
                    json!([parsed.mint, {"commitment": "confirmed"}]),
                    2,
                ),
            ) {
                Ok(value) => value,
                Err(err) => return Ok(failure(err)),
            };
            let largest = match post_rpc(
                rpc_url,
                &rpc_request(
                    "getTokenLargestAccounts",
                    json!([parsed.mint, {"commitment": "confirmed"}]),
                    3,
                ),
            ) {
                Ok(value) => value,
                Err(err) => return Ok(failure(err)),
            };

            // DEX data is advisory. A provider outage is represented as missing
            // liquidity and increases uncertainty rather than aborting the RPC checks.
            let dex = get_json(&format!(
                "{}/{}",
                dex_url.trim_end_matches('/'),
                parsed.mint
            ))
            .ok();

            match analyze_responses(&parsed.mint, &mint_account, &supply, &largest, dex.as_ref()) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "token risk check complete",
                        Some(report.score),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report.compact_json(),
                        error: None,
                    })
                }
                Err(err) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "risk analysis failed",
                        None,
                    );
                    Ok(failure(err))
                }
            }
        }
    }

    fn post_rpc(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|err| format!("Solana RPC request failed: {err}"))?
            .json::<Value>()
            .map_err(|err| format!("Solana RPC returned invalid JSON: {err}"))
    }

    fn get_json(url: &str) -> Result<Value, String> {
        waki::Client::new()
            .get(url)
            .send()
            .map_err(|err| format!("DEX request failed: {err}"))?
            .json::<Value>()
            .map_err(|err| format!("DEX provider returned invalid JSON: {err}"))
    }

    fn is_https_endpoint(value: &str) -> bool {
        value.starts_with("https://") && !value.chars().any(char::is_whitespace)
    }

    fn failure(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, score: Option<u16>) {
        let attrs = score.map(|value| format!(r#"{{"score":{value}}}"#));
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
