//! Read-only Solana token risk checks for ZeroClaw.
//!
//! The pure assessment core lives in [`risk`]. The wasm component is a thin
//! `wasi:http` shim: it fetches public RPC/liquidity data, passes those replies
//! to the core, and returns a compact report. It never accepts or reads a key,
//! builds a transaction, or moves funds.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::risk::{assess_token, RiskConfig, RiskDataSource};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::{json, Value};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    struct TokenRiskCheck;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct HttpSource<'a> {
        config: &'a RiskConfig,
    }

    impl RiskDataSource for HttpSource<'_> {
        fn mint_account(&self, mint: &str) -> Result<Value, String> {
            post_rpc(
                &self.config.rpc_url,
                "getAccountInfo",
                json!([mint, {"encoding": "jsonParsed", "commitment": "confirmed"}]),
            )
        }

        fn largest_accounts(&self, mint: &str) -> Result<Value, String> {
            post_rpc(
                &self.config.rpc_url,
                "getTokenLargestAccounts",
                json!([mint, {"commitment": "confirmed"}]),
            )
        }

        fn liquidity(&self, mint: &str) -> Result<Value, String> {
            let url = format!(
                "{}/{}",
                self.config.dex_api_base.trim_end_matches('/'),
                mint
            );
            waki::Client::new()
                .get(&url)
                .send()
                .map_err(|e| format!("liquidity request failed: {e}"))?
                .json::<Value>()
                .map_err(|e| format!("invalid liquidity response: {e}"))
        }
    }

    fn post_rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let value = waki::Client::new()
            .post(url)
            .json(&body)
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?
            .json::<Value>()
            .map_err(|e| format!("invalid RPC response: {e}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("RPC rejected {method}: {error}"));
        }
        Ok(value)
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
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Check a Solana token mint without custody or signing. Reports mint/freeze authority, Token-2022 extensions, top-holder concentration, and the deepest observed Solana liquidity pool as a compact red/amber/green assessment. This is a screening signal, not a guarantee or financial advice."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 Solana token mint address."
                    }
                },
                "required": ["mint"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return failure(format!("invalid arguments: {error}")),
            };
            let config = match RiskConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return failure(error),
            };
            let source = HttpSource { config: &config };
            match assess_token(&source, &parsed.mint, &config) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "completed read-only token risk check",
                        Some(json!({"verdict": report.verdict})),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&report)
                            .map_err(|e| format!("could not encode report: {e}"))?,
                        error: None,
                    })
                }
                Err(error) => failure(error),
            }
        }
    }

    fn failure(error: String) -> Result<ToolResult, String> {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "token risk check failed closed",
            None,
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<Value>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: attrs.map(|value| value.to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
