//! A zero-permission ZeroClaw tool that creates Solana Pay transfer requests.

pub mod request;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::request::{build_request, parse_request_args};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_request";

    struct SolanaPayRequest;

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
            "Create a canonical Solana Pay transfer-request URI and QR payload for SOL or an \
             SPL token. Strictly validates recipient, decimal amount, optional mint, references, \
             memo, and URI size. T1 build-only: it holds no key and never signs or submits."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Base58 recipient wallet address."
                    },
                    "amount": {
                        "type": "string",
                        "pattern": "^[0-9]+(\\.[0-9]+)?$",
                        "description": "Positive decimal amount as a string, never a float."
                    },
                    "spl_token": {
                        "type": "string",
                        "description": "Optional SPL token mint. Omit for native SOL."
                    },
                    "references": {
                        "type": "array",
                        "maxItems": 5,
                        "uniqueItems": true,
                        "items": {"type": "string"},
                        "description": "Optional Solana Pay reference accounts for reconciliation."
                    },
                    "label": {
                        "type": "string",
                        "maxLength": 64,
                        "description": "Optional merchant or payment label."
                    },
                    "message": {
                        "type": "string",
                        "maxLength": 128,
                        "description": "Optional wallet-facing payment message."
                    },
                    "memo": {
                        "type": "string",
                        "maxLength": 128,
                        "description": "Optional exact on-chain memo."
                    }
                },
                "required": ["recipient", "amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let args = match parse_request_args(&args) {
                Ok(value) => value,
                Err(error) => return failure("invalid arguments", error),
            };
            let request = match build_request(args) {
                Ok(value) => value,
                Err(error) => return failure("invalid payment request", error),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "solana pay request created",
                Some(format!(
                    "{{\"asset\":\"{}\",\"references\":{}}}",
                    request.asset,
                    request.references.len()
                )),
            );
            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&request)
                    .map_err(|error| format!("serialize payment request: {error}"))?,
                error: None,
            })
        }
    }

    fn failure(context: &str, error: String) -> Result<ToolResult, String> {
        emit(PluginAction::Fail, PluginOutcome::Failure, context, None);
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(format!("{context}: {error}")),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<String>) {
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
