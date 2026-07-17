//! A ZeroClaw WIT tool plugin that creates Solana Pay transfer-request URLs.
//!
//! This is deliberately a custody-tier T1 component: it does not hold private
//! keys, sign transactions, call an RPC endpoint, or move funds. Operator
//! configuration constrains recipients, token mints, and maximum amounts.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod solana_pay;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::solana_pay::{build_request, PayConfig, PayRequest};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = "0.1.0";
    const TOOL_NAME: &str = "solana_pay_request";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(flatten)]
        request: PayRequest,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaPayRequest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPayRequest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Create a validated Solana Pay transfer-request URL. This tool never signs a \
             transaction or moves funds. Operator configuration can allowlist recipients \
             and token mints and cap the requested amount; a wallet must still display and \
             approve the request."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Base58 Solana recipient. Optional only when a configured default exists."
                    },
                    "amount": {
                        "type": "string",
                        "description": "Canonical decimal amount, with at most 9 fractional digits."
                    },
                    "spl_token": {
                        "type": "string",
                        "description": "Optional base58 SPL token mint. Omit for native SOL."
                    },
                    "references": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 8,
                        "description": "Optional unique reference public keys."
                    },
                    "label": {"type": "string", "maxLength": 64},
                    "message": {"type": "string", "maxLength": 200},
                    "memo": {"type": "string", "maxLength": 200}
                },
                "required": ["amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                        None,
                    );
                    return Ok(failure(format!("invalid arguments: {error}")));
                }
            };

            let config = match PayConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid configuration",
                        None,
                    );
                    return Ok(failure(format!("invalid configuration: {error}")));
                }
            };

            match build_request(&parsed.request, &config) {
                Ok(result) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "created unsigned Solana Pay request",
                        Some(result.reference_count),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&result)
                            .map_err(|error| format!("serialize result: {error}"))?,
                        error: None,
                    })
                }
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "request rejected",
                        None,
                    );
                    Ok(failure(error))
                }
            }
        }
    }

    fn failure(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        references: Option<usize>,
    ) {
        let attrs = references.map(|count| format!("{{\"references\":{count}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_pay_request::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayRequest);
}
