//! ZeroClaw WIT tool plugin: `portfolio-brief`.
//!
//! Shapes a wallet's token portfolio into ~200 tokens for LLM daily briefing.
//! T0 (read-only) — RPC reads + price API.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod portfolio_brief;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::portfolio_brief::brief;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct PortfolioBriefPlugin;

    const PLUGIN_NAME: &str = "portfolio-brief";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "portfolio-brief";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        wallet: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for PortfolioBriefPlugin {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    impl Tool for PortfolioBriefPlugin {
        fn name() -> String { TOOL_NAME.to_string() }

        fn description() -> String {
            "Get a wallet's full token portfolio — balances, approximate USD values, and a \
             human-readable summary shaped to ~200 tokens for a daily briefing. \
             T0: read-only RPC + public price API.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "wallet": {
                        "type": "string",
                        "description": "Solana wallet address (base58).",
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]{32,44}$"
                    }
                },
                "required": ["wallet"]
            }).to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("invalid arguments: {e}")) }),
            };
            let rpc_url = parsed.config.get("rpc_url").cloned().unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());
            let price_api = parsed.config.get("price_api_url").cloned().unwrap_or_default();
            emit(PluginAction::Start, PluginOutcome::Attempting, "fetching portfolio", None);
            let result = brief(&parsed.wallet, &rpc_url, &price_api);
            match result {
                Some(b) => {
                    let output = serde_json::to_string(&b).map_err(|e| format!("JSON serialization failed: {e}"))?;
                    emit(PluginAction::Complete, PluginOutcome::Success, "portfolio fetched", None);
                    Ok(ToolResult { success: true, output, error: None })
                }
                None => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "failed to fetch portfolio", None);
                    Ok(ToolResult { success: false, output: String::new(), error: Some("Failed to fetch portfolio — check wallet address".to_string()) })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, _count: Option<usize>) {
        log_record(LogLevel::Info, &PluginEvent {
            function_name: "portfolio_brief::tool::execute".to_string(),
            action, outcome: Some(outcome), duration_ms: None, attrs: None, message: message.to_string(),
        });
    }

    export!(PortfolioBriefPlugin);
}

#[cfg(not(target_family = "wasm"))]
pub use portfolio_brief::*;
