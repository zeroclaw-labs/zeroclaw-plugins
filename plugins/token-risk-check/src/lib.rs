//! ZeroClaw `token-risk-check` tool plugin.
//!
//! The core parser and risk policy live in [`risk`] and have no WASM or HTTP
//! dependency. This file is only the thin `wasm32-wasip2` shim: validate the
//! request, make read-only HTTP calls, and return a compact report.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    use std::collections::HashMap;
    use std::time::Duration;

    use serde::Deserialize;
    use serde_json::{json, Value};

    use crate::risk::{analyze, validate_mint, RiskConfig};

    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
    const DEFAULT_DEX_TEMPLATE: &str = "https://api.dexscreener.com/latest/dex/tokens/{mint}";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        mint: String,
        #[serde(default = "default_true")]
        include_liquidity: bool,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_true() -> bool {
        true
    }

    struct TokenRiskCheck;

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
            "Read-only Solana token safety preflight. Checks mint/freeze authority, \
             largest-account concentration, Token-2022 extensions (including transfer \
             hooks, fees, and permanent delegate), and optional indexed liquidity. \
             Returns a compact heuristic report, never signs or builds transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 Solana mint address to inspect."
                    },
                    "include_liquidity": {
                        "type": "boolean",
                        "default": true,
                        "description": "Query the configured read-only liquidity index."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return Ok(failure(format!("invalid arguments: {error}"))),
            };

            if let Err(error) = validate_mint(&parsed.mint) {
                return Ok(failure(error));
            }

            let cfg = RiskConfig::from_section(&parsed.config);
            let rpc_url = parsed
                .config
                .get("rpc_url")
                .map(String::as_str)
                .unwrap_or(DEFAULT_RPC_URL);
            if let Err(error) = validate_endpoint(rpc_url, "rpc_url") {
                return Ok(failure(error));
            }

            emit(PluginAction::Query, None, "starting token risk check", None);

            let account = match rpc(
                rpc_url,
                "getAccountInfo",
                json!([parsed.mint, {"encoding": "jsonParsed", "commitment": "confirmed"}]),
            ) {
                Ok(value) => value,
                Err(error) => return Ok(logged_failure(error)),
            };
            let largest = match rpc(
                rpc_url,
                "getTokenLargestAccounts",
                json!([parsed.mint, {"commitment": "confirmed"}]),
            ) {
                Ok(value) => value,
                Err(error) => return Ok(logged_failure(error)),
            };

            // Liquidity is deliberately best-effort. An index outage must be
            // reported as unknown, not misclassified as zero liquidity.
            let market = if parsed.include_liquidity {
                let template = parsed
                    .config
                    .get("dex_url_template")
                    .map(String::as_str)
                    .unwrap_or(DEFAULT_DEX_TEMPLATE);
                let url = template.replace("{mint}", &parsed.mint);
                match validate_endpoint(&url, "dex_url_template") {
                    Ok(()) => get_json(&url).ok(),
                    Err(_) => None,
                }
            } else {
                Some(json!({"_tokenRiskCheckSkipped": true}))
            };

            match analyze(&parsed.mint, &account, &largest, market.as_ref(), &cfg) {
                Ok(report) => {
                    let output = report.render_compact();
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "completed token risk check",
                        Some(json!({"rating": report.rating.as_str()}).to_string()),
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(error) => Ok(logged_failure(error)),
            }
        }
    }

    fn rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        post_json(url, &body).and_then(|value| {
            if let Some(error) = value.get("error") {
                Err(format!("Solana RPC {method} failed: {error}"))
            } else {
                Ok(value)
            }
        })
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .connect_timeout(CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|error| format!("HTTP request failed: {error}"))?
            .json::<Value>()
            .map_err(|error| format!("invalid HTTP JSON response: {error}"))
    }

    fn get_json(url: &str) -> Result<Value, String> {
        waki::Client::new()
            .get(url)
            .connect_timeout(CONNECT_TIMEOUT)
            .send()
            .map_err(|error| format!("liquidity request failed: {error}"))?
            .json::<Value>()
            .map_err(|error| format!("invalid liquidity JSON response: {error}"))
    }

    fn validate_endpoint(url: &str, field: &str) -> Result<(), String> {
        let local_http = url.starts_with("http://127.0.0.1:")
            || url.starts_with("http://localhost:")
            || url == "http://localhost"
            || url == "http://127.0.0.1";
        if url.starts_with("https://") || local_http {
            Ok(())
        } else {
            Err(format!(
                "{field} must use HTTPS (plain HTTP is allowed only for localhost)"
            ))
        }
    }

    fn failure(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn logged_failure(error: String) -> ToolResult {
        emit(
            PluginAction::Fail,
            Some(PluginOutcome::Failure),
            "token risk check failed closed",
            None,
        );
        failure(error)
    }

    fn emit(
        action: PluginAction,
        outcome: Option<PluginOutcome>,
        message: &str,
        attrs: Option<String>,
    ) {
        log_record(
            if matches!(outcome, Some(PluginOutcome::Failure)) {
                LogLevel::Warn
            } else {
                LogLevel::Info
            },
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
