//! A ZeroClaw WIT tool plugin: `token-risk-check`.
//!
//! Checks a Solana token mint for risk factors: mint/freeze authority status,
//! holder concentration, LP verification, and Token-2022 extensions. Produces
//! a risk score (0-100) with detailed reasoning, shaped to ~200 tokens for LLM
//! consumption.
//!
//! The pure risk-check logic lives in [`risk`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
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

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token-risk-check";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(default = "default_rpc_url")]
        rpc_url: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_rpc_url() -> String {
        "https://api.mainnet-beta.solana.com".to_string()
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
            "Check Solana token mint for risk factors: mint/freeze authority status, \
             holder concentration, LP verification, and Token-2022 extensions. \
             Provide a mint address to get a risk score (0-100) with detailed reasoning."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Solana mint/token address"
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": "RPC endpoint URL, defaults to mainnet-beta"
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
                        None,
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let result = crate::risk::check_token(&parsed.mint, &parsed.rpc_url);

            match result {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "token risk check complete",
                        None,
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "token risk check failed",
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

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        _count: Option<usize>,
    ) {
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