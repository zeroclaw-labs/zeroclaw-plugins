//! ZeroClaw WIT tool plugin: `solana-pay-request`.
//!
//! Generates a Solana Pay transfer request URL (`solana:` protocol) that an
//! agent can render as a QR code for payment.  This is a **T1** plugin — it
//! holds no secrets and returns only an unsigned URL.  The agent must arrange
//! for the user to sign and submit the resulting transaction.
//!
//! The pure build logic lives in [`pay`] with no wasm dependency, so it
//! compiles and tests on the host with `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod pay;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0"
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::pay::create_pay_request;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana-pay-request";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        recipient: String,
        amount: f64,
        mint: Option<String>,
        memo: Option<String>,
        reference: Option<String>,
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
            "Generate a Solana Pay transfer request URL. \
             The agent returns a solana: URL that can be rendered as a QR code for payment. \
             No secrets are held — this is T1 (builds URL only)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Recipient Solana address"
                    },
                    "amount": {
                        "type": "number",
                        "description": "Amount to request"
                    },
                    "mint": {
                        "type": "string",
                        "description": "SPL token mint address — omitted for SOL"
                    },
                    "memo": {
                        "type": "string",
                        "description": "Invoice memo"
                    },
                    "reference": {
                        "type": "string",
                        "description": "Reference key for payment tracking"
                    }
                },
                "required": ["recipient", "amount"]
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

            let rpc_url = parsed
                .config
                .get("rpc_url")
                .map(|s| s.as_str())
                .unwrap_or("https://api.mainnet-beta.solana.com");

            let output = create_pay_request(
                &parsed.recipient,
                parsed.amount,
                parsed.mint.as_deref(),
                parsed.memo.as_deref(),
                parsed.reference.as_deref(),
            );

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "built Solana Pay URL",
                None,
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
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
                function_name: "solana_pay_request::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayRequest);
}