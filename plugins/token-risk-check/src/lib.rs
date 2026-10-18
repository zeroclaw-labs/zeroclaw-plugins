//! A ZeroClaw WIT tool plugin: `token-risk-check`.
//!
//! Given a Solana mint address, returns a compact red/amber/green risk report
//! covering mint/freeze authorities, Token-2022 extensions, supply, top-holder
//! concentration, and LP liquidity/lock status. This is T0/read-only: it never
//! signs, builds, or submits transactions.
//!
//! The pure risk-analysis core lives in [`risk`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! only adapts WIT + wasi:http to that core.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::{json, Value};

    use crate::risk::{check_token_risk, LiquidityClient, RiskConfig, RpcClient};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token-risk-check";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
    const DEFAULT_RUGCHECK_URL: &str = "https://api.rugcheck.xyz";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct HttpRpc {
        url: String,
    }

    struct HttpLiquidity {
        base_url: String,
    }

    impl RpcClient for HttpRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, String> {
            let body = json!({
                "jsonrpc": "2.0",
                "id": "token-risk-check",
                "method": method,
                "params": params
            });
            let response = waki::Client::new()
                .post(&self.url)
                .json(&body)
                .send()
                .map_err(|e| format!("rpc transport error: {e}"))?
                .json::<Value>()
                .map_err(|e| format!("rpc json error: {e}"))?;
            if let Some(err) = response.get("error") {
                return Err(format!("rpc {method} failed: {err}"));
            }
            response
                .get("result")
                .cloned()
                .ok_or_else(|| format!("rpc {method} response missing result"))
        }
    }

    impl LiquidityClient for HttpLiquidity {
        fn token_report(&self, mint: &str) -> Result<Value, String> {
            let url = format!(
                "{}/v1/tokens/{mint}/report",
                self.base_url.trim_end_matches('/')
            );
            waki::Client::new()
                .get(&url)
                .send()
                .map_err(|e| format!("liquidity transport error: {e}"))?
                .json::<Value>()
                .map_err(|e| format!("liquidity json error: {e}"))
        }
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
            "Inspect a Solana token mint and return a compact red/amber/green risk report. \
             Read-only T0: checks authorities, holder concentration, LP liquidity/locks, \
             Token-2022 extensions, and supply without custody or transaction capability."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 Solana token mint address to inspect."
                    }
                },
                "required": ["mint"],
                "additionalProperties": false
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

            let cfg = RiskConfig::from_section(&parsed.config);
            let rpc_url = parsed
                .config
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
            let rpc = HttpRpc { url: rpc_url };
            let liquidity = HttpLiquidity {
                base_url: parsed
                    .config
                    .get("rugcheck_url")
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_RUGCHECK_URL.to_string()),
            };

            match check_token_risk(&rpc, &liquidity, &parsed.mint, &cfg) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "checked token risk",
                        Some(report.score),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report.to_compact_text(),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "risk check failed",
                        None,
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, score: Option<u8>) {
        let attrs = score.map(|n| format!("{{\"risk_score\":{n}}}"));
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
