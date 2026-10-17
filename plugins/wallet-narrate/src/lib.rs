//! ZeroClaw WIT tool plugin: `wallet-narrate`.
//!
//! Turns raw Solana transactions into human-readable narratives.
//! T0 (read-only) — RPC reads only, no signing.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod wallet_narrate;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::wallet_narrate::{narrate, narrate_address, Narrative};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct WalletNarrate;

    const PLUGIN_NAME: &str = "wallet-narrate";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "wallet-narrate";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        signature: Option<String>,
        address: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for WalletNarrate {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    impl Tool for WalletNarrate {
        fn name() -> String { TOOL_NAME.to_string() }

        fn description() -> String {
            "Turn a raw Solana transaction signature or wallet address into a human-readable \
             narrative the agent can say aloud: 'Received 250 USDC from 7xK...'. \
             T0: read-only RPC queries only.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "Transaction signature (base58). Provide this OR address, not both."
                    },
                    "address": {
                        "type": "string",
                        "description": "Wallet address to narrate the most recent transaction for. Provide this OR signature."
                    }
                }
            }).to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("invalid arguments: {e}")) }),
            };
            let rpc_url = parsed.config.get("rpc_url").cloned().unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());
            let narrative = if let Some(sig) = parsed.signature {
                emit(PluginAction::Start, PluginOutcome::Attempting, "fetching transaction", None);
                narrate(&sig, &rpc_url)
            } else if let Some(addr) = parsed.address {
                emit(PluginAction::Start, PluginOutcome::Attempting, "fetching recent transaction", None);
                narrate_address(&addr, &rpc_url)
            } else {
                return Ok(ToolResult { success: false, output: String::new(), error: Some("must provide either 'signature' or 'address'".to_string()) });
            };
            match narrative {
                Some(n) => {
                    let output = serde_json::to_string(&n).map_err(|e| format!("JSON serialization failed: {e}"))?;
                    emit(PluginAction::Complete, PluginOutcome::Success, "narrative generated", None);
                    Ok(ToolResult { success: true, output, error: None })
                }
                None => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "transaction not found", None);
                    Ok(ToolResult { success: false, output: String::new(), error: Some("transaction not found or RPC error".to_string()) })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, _count: Option<usize>) {
        log_record(LogLevel::Info, &PluginEvent {
            function_name: "wallet_narrate::tool::execute".to_string(),
            action, outcome: Some(outcome), duration_ms: None, attrs: None, message: message.to_string(),
        });
    }

    export!(WalletNarrate);
}

#[cfg(not(target_family = "wasm"))]
pub use wallet_narrate::*;
