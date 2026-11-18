//! A zero-custody ZeroClaw tool for verifying Solana invoice payments.
//!
//! The pure verification engine lives in [`verify`]. This file is only the
//! `wasm32-wasip2` WIT and HTTP shim.

pub mod verify;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::time::Duration;

    use crate::verify::{parse_execute_args, verify_rpc_response, RpcConfig, VerificationStatus};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-payment-verify";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_payment_verify";

    struct SolanaPaymentVerify;

    impl PluginInfo for SolanaPaymentVerify {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPaymentVerify {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Verify a finalized or confirmed Solana transaction against a strict invoice. \
             Checks transaction success, recipient balance increase, SOL or SPL mint, exact or \
             at-least amount policy, reference account, and optional memo. Read-only: it never \
             signs, submits, or changes a transaction. Treat valid=false as unpaid."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "Base58 Solana transaction signature to verify."
                    },
                    "recipient": {
                        "type": "string",
                        "description": "Base58 wallet that must receive the payment."
                    },
                    "amount": {
                        "type": "string",
                        "pattern": "^[0-9]+(\\.[0-9]+)?$",
                        "description": "Human-readable decimal amount as a string, never a float."
                    },
                    "asset": {
                        "type": "string",
                        "description": "SOL or the exact SPL token mint address."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Optional Solana Pay reference account that must appear in the transaction."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional exact memo that must appear in an SPL Memo instruction."
                    },
                    "amount_policy": {
                        "type": "string",
                        "enum": ["exact", "at_least"],
                        "default": "exact",
                        "description": "exact rejects both under- and overpayment; at_least permits overpayment."
                    }
                },
                "required": ["signature", "recipient", "amount", "asset"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed = match parse_execute_args(&args) {
                Ok(value) => value,
                Err(error) => return tool_failure("invalid arguments", error),
            };
            let config = match RpcConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return tool_failure("invalid configuration", error),
            };
            let expectation = match parsed.into_expectation() {
                Ok(value) => value,
                Err(error) => return tool_failure("invalid invoice", error),
            };

            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [
                    expectation.signature,
                    {
                        "encoding": "jsonParsed",
                        "commitment": config.commitment,
                        "maxSupportedTransactionVersion": 0
                    }
                ]
            });

            let response = match waki::Client::new()
                .post(&config.rpc_url)
                .header("Content-Type", "application/json")
                .connect_timeout(Duration::from_secs(config.timeout_secs))
                .json(&payload)
                .send()
            {
                Ok(value) => value,
                Err(error) => {
                    return tool_failure("rpc request failed", error.to_string());
                }
            };

            let status = response.status_code();
            if !(200..300).contains(&status) {
                return tool_failure("rpc request failed", format!("HTTP {status}"));
            }
            let rpc_json = match response.json::<serde_json::Value>() {
                Ok(value) => value,
                Err(error) => return tool_failure("invalid rpc response", error.to_string()),
            };
            let report = verify_rpc_response(&expectation, &rpc_json);
            let success = report.status == VerificationStatus::Paid;
            emit(
                if success {
                    PluginAction::Complete
                } else {
                    PluginAction::Fail
                },
                if success {
                    PluginOutcome::Success
                } else {
                    PluginOutcome::Failure
                },
                if success {
                    "payment verified"
                } else {
                    "payment not verified"
                },
                Some(format!("{{\"status\":\"{}\"}}", report.status.as_str())),
            );

            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&report)
                    .map_err(|error| format!("serialize verification report: {error}"))?,
                error: None,
            })
        }
    }

    fn tool_failure(context: &str, error: String) -> Result<ToolResult, String> {
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
                function_name: "solana_payment_verify::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPaymentVerify);
}
