//! ZeroClaw WIT tool plugin: `token-risk-check`.
//!
//! Assesses Token-2022 risk profile for any SPL mint address.
//! T0 (read-only) — RPC reads only, no signing, no secrets held.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod token_risk_check;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::token_risk_check::{assess_risk, RiskAssessment};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token-risk-check";

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
            "Assess the risk profile of any SPL token mint address on Solana. \
             Checks mint/freeze authority, permanent delegate, transfer hooks, transfer fees, \
             holder concentration, and supply. Returns green/amber/red with a detailed breakdown. \
             T0: read-only RPC queries only."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The SPL mint address to assess (base58).",
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]{32,44}$"
                    }
                },
                "required": ["mint"]
            }).to_string()
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

            // Validate mint address format
            if parsed.mint.len() < 32 || parsed.mint.len() > 44 {
                emit(PluginAction::Fail, PluginOutcome::Failure, "invalid mint address", None);
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("mint address must be 32-44 base58 characters".to_string()),
                });
            }

            // Get RPC URL from config or use public endpoint
            let rpc_url = parsed.config
                .get("rpc_url")
                .cloned()
                .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());

            emit(PluginAction::Start, PluginOutcome::Attempting, "fetching mint info", None);

            let assessment: RiskAssessment = assess_risk(&parsed.mint, &rpc_url);

            let output = serde_json::to_string(&assessment)
                .map_err(|e| format!("JSON serialization failed: {e}"))?;

            emit(
                PluginAction::Complete,
                if assessment.tier == "green" { PluginOutcome::Success }
                else if assessment.tier == "amber" { PluginOutcome::Warning }
                else { PluginOutcome::Failure },
                "assessment complete",
                None,
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, _count: Option<usize>) {
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

#[cfg(not(target_family = "wasm"))]
pub use token_risk_check::*;
