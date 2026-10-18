//! ZeroClaw WIT tool plugin: `lending-health`.
//!
//! Checks lending position health factor on Kamino, MarginFi, Drift.
//! T0 (read-only) — RPC reads only.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod lending_health;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::lending_health::check_health;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct LendingHealth;

    const PLUGIN_NAME: &str = "lending-health";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "lending-health";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        wallet: String,
        protocol: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for LendingHealth {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    impl Tool for LendingHealth {
        fn name() -> String { TOOL_NAME.to_string() }

        fn description() -> String {
            "Check a lending position's health factor on Kamino, MarginFi, or Drift. \
             Returns green/caution/danger status for SOP-triggered alerts. \
             T0: read-only RPC queries only.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "wallet": {
                        "type": "string",
                        "description": "Solana wallet address.",
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]{32,44}$"
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Lending protocol: 'kamino', 'marginfi', or 'drift'.",
                        "enum": ["kamino", "marginfi", "drift"]
                    }
                },
                "required": ["wallet", "protocol"]
            }).to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("invalid arguments: {e}")) }),
            };
            let rpc_url = parsed.config.get("rpc_url").cloned().unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());
            emit(PluginAction::Start, PluginOutcome::Attempting, "checking health", None);
            let result = check_health(&parsed.wallet, &parsed.protocol, &rpc_url);
            match result {
                Some(h) => {
                    let output = serde_json::to_string(&h).map_err(|e| format!("JSON serialization failed: {e}"))?;
                    let outcome = match h.tier.as_str() {
                        "healthy" | "no_position" => PluginOutcome::Success,
                        "caution" => PluginOutcome::Warning,
                        _ => PluginOutcome::Failure,
                    };
                    emit(PluginAction::Complete, outcome, "health check complete", None);
                    Ok(ToolResult { success: true, output, error: None })
                }
                None => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "failed to check health", None);
                    Ok(ToolResult { success: false, output: String::new(), error: Some("Failed to check health — RPC error".to_string()) })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, _count: Option<usize>) {
        log_record(LogLevel::Info, &PluginEvent {
            function_name: "lending_health::tool::execute".to_string(),
            action, outcome: Some(outcome), duration_ms: None, attrs: None, message: message.to_string(),
        });
    }

    export!(LendingHealth);
}

#[cfg(not(target_family = "wasm"))]
pub use lending_health::*;
