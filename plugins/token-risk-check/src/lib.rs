//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Red/amber/green risk report for any Solana mint — custody tier T0: pure
//! reads, no keys, no state. Checks mint/freeze authorities, Token-2022
//! extensions (permanent delegates, transfer hooks, fees, default-frozen
//! state), and holder concentration, and shapes the answer to a few hundred
//! characters so it can run before every other Solana action without taxing
//! the agent's context window.
//!
//! The pure core lives in [`risk`] with no wasm dependency and is host-tested
//! against a mock RPC with plain `cargo test`; this file is the thin
//! component shim wiring it to the `tool-plugin` WIT world with the blocking
//! `waki` client (TLS is performed host-side).
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

    use crate::risk::{assess_mint, RiskConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    use zeroclaw_solana_core::rpc::HttpTransport;

    struct WakiTransport;

    impl HttpTransport for WakiTransport {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let response = waki::Client::new()
                .post(url)
                .header("content-type", "application/json")
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?;
            let bytes = response
                .body()
                .map_err(|e| format!("rpc response read failed: {e}"))?;
            String::from_utf8(bytes).map_err(|_| "rpc response is not UTF-8".to_string())
        }
    }

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";

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
            "Check a Solana token mint for safety red flags BEFORE holding, sending, or \
             quoting it: mint/freeze authorities, Token-2022 extensions (permanent \
             delegate, transfer hooks, transfer fees, default-frozen accounts), and \
             holder concentration. Returns RED/AMBER/GREEN with one-line reasons. \
             Read-only; touches no funds and no keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The token mint address to assess (base58)."
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
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };
            let cfg = RiskConfig::from_section(&parsed.config);

            match assess_mint(&WakiTransport, &parsed.mint, &cfg) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "mint assessed",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report.text,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "assessment failed",
                    );
                    Ok(fail(e))
                }
            }
        }
    }

    fn fail(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
