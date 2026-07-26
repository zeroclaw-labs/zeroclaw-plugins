//! A ZeroClaw WIT tool plugin: `solana_token_risk`.
//!
//! Offline risk analyzer for Solana SPL / Token-2022 mints. The agent fetches
//! chain data with whatever HTTP tool the operator allows (e.g. a Solana RPC
//! `getAccountInfo` with jsonParsed encoding), then passes the JSON here; the
//! plugin never touches the network, holds no keys, and signs nothing (T0).
//!
//! The pure analysis core lives in [`risk`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
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

    use crate::risk::analyze;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaTokenRisk;

    const PLUGIN_NAME: &str = "solana-token-risk";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_token_risk";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint_account: serde_json::Value,
        #[serde(default)]
        largest_accounts: Option<serde_json::Value>,
        #[serde(default)]
        supply: Option<serde_json::Value>,
        #[serde(default)]
        metadata: Option<serde_json::Value>,
    }

    impl PluginInfo for SolanaTokenRisk {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaTokenRisk {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Analyze a Solana SPL or Token-2022 mint for rug/honeypot risk from \
             already-fetched RPC JSON. Checks mint/freeze authorities, dangerous \
             Token-2022 extensions (permanent delegate, transfer hooks, frozen-by-default, \
             transfer fees), holder concentration, and mutable metadata. Pure offline \
             analysis: pass in the jsonParsed getAccountInfo result (required), and \
             optionally getTokenLargestAccounts, getTokenSupply, and metadata JSON."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint_account": {
                        "type": "object",
                        "description": "jsonParsed getAccountInfo response (or its result.value) for the mint."
                    },
                    "largest_accounts": {
                        "type": "object",
                        "description": "Optional getTokenLargestAccounts response for holder concentration."
                    },
                    "supply": {
                        "type": "object",
                        "description": "Optional getTokenSupply response (needed with largest_accounts)."
                    },
                    "metadata": {
                        "type": "object",
                        "description": "Optional token metadata JSON (updateAuthority, isMutable)."
                    }
                },
                "required": ["mint_account"]
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
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            match analyze(
                &parsed.mint_account,
                parsed.largest_accounts.as_ref(),
                parsed.supply.as_ref(),
                parsed.metadata.as_ref(),
            ) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "analyzed mint",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string_pretty(&report)
                            .unwrap_or_else(|e| format!("serialization error: {e}")),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "analysis failed",
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

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_token_risk::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaTokenRisk);
}
