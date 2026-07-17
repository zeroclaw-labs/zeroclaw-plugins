//! A ZeroClaw WIT tool plugin that creates Solana Pay transfer-request URLs.
//!
//! The component holds no private keys, signs and broadcasts no transactions,
//! and calls no RPC endpoint. Operator configuration constrains recipients and
//! maximum native-SOL amounts. A generated URL asks a compatible wallet to
//! compose a transfer, so the wallet remains the review and approval boundary.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod solana_pay;

/// Manifest/package identity. Cargo metadata is the source of truth.
pub const PLUGIN_PACKAGE_ID: &str = env!("CARGO_PKG_NAME");
/// Immutable release identity. Cargo metadata is the source of truth.
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
/// WIT tool identity exposed to the model. This is intentionally not the
/// hyphenated manifest/package identifier used for installation and config.
pub const EXPORTED_TOOL_NAME: &str = "solana_pay_request";

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::{
        solana_pay::{build_request, PayConfig, PayRequest},
        EXPORTED_TOOL_NAME, PLUGIN_PACKAGE_ID, PLUGIN_VERSION,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(flatten)]
        request: PayRequest,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaPayRequest {
        fn plugin_name() -> String {
            PLUGIN_PACKAGE_ID.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPayRequest {
        fn name() -> String {
            EXPORTED_TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Create a validated native-SOL transfer-request URL. The URL asks a compatible \
             wallet to compose a transfer. This plugin cannot sign or broadcast a \
             transaction; operator configuration allowlists recipients and caps the amount."
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
                        "description": "Canonical native-SOL amount, with at most 9 fractional digits."
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
                        "created native-SOL transfer request URL",
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

#[cfg(test)]
mod tests {
    use super::{EXPORTED_TOOL_NAME, PLUGIN_PACKAGE_ID, PLUGIN_VERSION};

    #[test]
    fn package_and_exported_tool_identities_are_distinct_and_explicit() {
        assert_ne!(PLUGIN_PACKAGE_ID, EXPORTED_TOOL_NAME);
        assert_eq!(EXPORTED_TOOL_NAME, PLUGIN_PACKAGE_ID.replace('-', "_"));
        assert_eq!(PLUGIN_VERSION, env!("CARGO_PKG_VERSION"));

        let manifest = include_str!("../manifest.toml");
        assert!(manifest.contains(&format!("name = \"{PLUGIN_PACKAGE_ID}\"")));
        assert!(manifest.contains(&format!("version = \"{PLUGIN_VERSION}\"")));
    }
}
