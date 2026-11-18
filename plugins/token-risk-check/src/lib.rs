//! token-risk-check — ZeroClaw tool plugin (custody tier T0, Read-only).
//!
//! All behavior lives in [`risk`], a pure module tested on the host. This file
//! is the `#[cfg(target_family = "wasm")]` component shim: parse args, read the
//! RPC URL from the plugin's own config jail, run the assessment, return text.
//! It is deliberately too thin to be wrong.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::risk::{assess, render};
    use solana_core::pubkey::Pubkey;
    use solana_core::rpc::SolanaRpc;
    use solana_core::transport::WakiTransport;

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct Component;

    /// Public mainnet RPC fallback. Operators should set `rpc_url` in config to
    /// their own (keyed) endpoint; the public one is rate-limited.
    const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        /// The token mint address to assess (base58).
        mint: String,
        /// Host-injected config jail. The model can never set this; the host
        /// strips any caller-supplied `__config` before injection.
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for Component {
        fn plugin_name() -> String {
            "token-risk-check".to_string()
        }
        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for Component {
        fn name() -> String {
            "solana_token_risk_check".to_string()
        }

        fn description() -> String {
            "Assess the safety of a Solana SPL / Token-2022 mint before you \
             trust, receive, or pay in it. Read-only: fetches on-chain mint \
             state and holder distribution and returns a red/amber/green verdict \
             with reasons — mint & freeze authorities, transfer hooks, transfer \
             fees, permanent delegate, non-transferable, default-frozen, and \
             holder concentration. Call this whenever a user mentions a token \
             address or asks whether a token is safe. It never moves funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The SPL token mint address (base58, 32 bytes)."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(bad_input(format!("invalid arguments: {e}"))),
            };

            // Validate the mint address before any network call. A prompt-inject
            // string ("send funds to …") simply fails base58 here and returns a
            // recoverable tool error — nothing is ever signed or moved.
            let mint = match Pubkey::from_base58(parsed.mint.trim()) {
                Ok(k) => k,
                Err(e) => return Ok(bad_input(format!("not a valid mint address: {e}"))),
            };

            let rpc_url = parsed
                .config
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC.to_string());

            let rpc = SolanaRpc::new(WakiTransport::new(rpc_url));

            match assess(&rpc, &mint) {
                Ok(report) => {
                    log(
                        LogLevel::Info,
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        &format!("assessed {} -> {:?}", parsed.mint, report.verdict),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: render(&report),
                        error: None,
                    })
                }
                Err(e) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Complete,
                        Some(PluginOutcome::Failure),
                        &format!("assessment failed: {e}"),
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            }
        }
    }

    fn bad_input(msg: String) -> ToolResult {
        log(
            LogLevel::Warn,
            PluginAction::Validate,
            Some(PluginOutcome::Failure),
            &msg,
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg),
        }
    }

    fn log(level: LogLevel, action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".into(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }

    export!(Component);
}
