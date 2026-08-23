//! ZeroClaw WIT component: payment-watch (T0, read-only, SOP-triggered).
//!
//! Watches a Solana address for expected payments. Designed for cron/SOP
//! triggers — pairs with solana-pay-request to close the payment loop.

pub mod watch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0"
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use crate::watch::check_payment;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PaymentWatch;

    const PLUGIN_NAME: &str = "payment-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        address: String,
        expected_amount: f64,
        expected_mint: String,
        #[serde(default)]
        reference: Option<String>,
        #[serde(default)]
        rpc_url: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            "payment-watch".to_string()
        }

        fn description() -> String {
            "Watch a Solana address for an expected payment. Checks if a transaction \
             matching the given reference key and amount has been confirmed. \
             Designed for SOP/cron triggers. T0 read-only — no signing capability."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Solana address to watch for incoming payment"
                    },
                    "expected_amount": {
                        "type": "number",
                        "description": "Expected payment amount in token decimals"
                    },
                    "expected_mint": {
                        "type": "string",
                        "description": "Expected SPL token mint or 'SOL'"
                    },
                    "reference": {
                        "type": "string",
                        "description": "Reference key to match against the payment"
                    },
                    "rpc_url": {
                        "type": "string",
                        "description": "RPC endpoint URL (defaults to mainnet-beta)"
                    }
                },
                "required": ["address", "expected_amount", "expected_mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    log_record(
                        LogLevel::Warn,
                        &PluginEvent {
                            function_name: "payment_watch::tool::execute".into(),
                            action: PluginAction::Fail,
                            outcome: Some(PluginOutcome::Failure),
                            duration_ms: None,
                            attrs: None,
                            message: format!("invalid arguments: {e}"),
                        },
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let rpc_url = if parsed.rpc_url.is_empty() {
                parsed.config.get("rpc_url").cloned().unwrap_or_default()
            } else {
                parsed.rpc_url
            };

            let result = check_payment(
                &parsed.address,
                parsed.expected_amount,
                &parsed.expected_mint,
                parsed.reference.as_deref(),
                &rpc_url,
            );

            match result {
                Ok(status) => {
                    log_record(
                        LogLevel::Info,
                        &PluginEvent {
                            function_name: "payment_watch::tool::execute".into(),
                            action: PluginAction::Complete,
                            outcome: Some(PluginOutcome::Success),
                            duration_ms: None,
                            attrs: Some(format!("{{\"address\":\"{}\"}}", &parsed.address[..8.min(parsed.address.len())])),
                            message: "payment check completed".into(),
                        },
                    );
                    Ok(ToolResult {
                        success: true,
                        output: status,
                        error: None,
                    })
                }
                Err(e) => {
                    log_record(
                        LogLevel::Error,
                        &PluginEvent {
                            function_name: "payment_watch::tool::execute".into(),
                            action: PluginAction::Fail,
                            outcome: Some(PluginOutcome::Failure),
                            duration_ms: None,
                            attrs: None,
                            message: format!("payment check failed: {e}"),
                        },
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

    export!(PaymentWatch);
}