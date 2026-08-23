//! ZeroClaw `solana_pay_request` tool component.
//!
//! The pure request builder is in [`request`]. This file contains only the
//! wasm WIT adapter and structured host logging.

pub mod request;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::request::{create_request, RequestInput};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    impl PluginInfo for SolanaPayRequest {
        fn plugin_name() -> String {
            "solana-pay-request".to_string()
        }

        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for SolanaPayRequest {
        fn name() -> String {
            "solana_pay_request".to_string()
        }

        fn description() -> String {
            "Create a validated Solana Pay transfer-request URI for an explicit recipient and amount. \
             This T1 tool never holds keys, signs, submits, or moves funds. Provide either a unique \
             reference public key or an invoice_id used to derive a deterministic reference."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "recipient": { "type": "string", "description": "Recipient Solana public key." },
                    "amount": { "type": "string", "description": "Positive plain decimal amount; never use floating point." },
                    "spl_token": { "type": "string", "description": "Optional SPL token mint. Omit for SOL." },
                    "reference": { "type": "string", "description": "Optional unique reference public key. Mutually exclusive with invoice_id." },
                    "invoice_id": { "type": "string", "description": "Optional stable invoice identifier used to derive a reference. Mutually exclusive with reference." },
                    "label": { "type": "string", "description": "Optional wallet-facing merchant label." },
                    "message": { "type": "string", "description": "Optional wallet-facing payment message." },
                    "memo": { "type": "string", "description": "Optional on-chain memo, at most 128 UTF-8 bytes." }
                },
                "required": ["recipient", "amount"],
                "oneOf": [
                    { "required": ["reference"], "not": { "required": ["invoice_id"] } },
                    { "required": ["invoice_id"], "not": { "required": ["reference"] } }
                ]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let result = serde_json::from_str::<RequestInput>(&args)
                .map_err(|error| format!("invalid arguments: {error}"))
                .and_then(create_request);
            match result {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "invoice URI created",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&output)
                            .map_err(|error| format!("serialize output: {error}"))?,
                        error: None,
                    })
                }
                Err(error) => {
                    emit(
                        PluginAction::Reject,
                        PluginOutcome::Failure,
                        "invoice request rejected",
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(error),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_pay_request::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some("{\"custody_tier\":\"T1\",\"signs\":false}".to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayRequest);
}
