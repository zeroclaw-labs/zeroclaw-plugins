//! A ZeroClaw WIT tool plugin: `solana_pay_request`.
//!
//! Builds a [Solana Pay](https://docs.solanapay.com/spec) transfer-request URL
//! for a SOL or SPL-token payment, to be rendered as a link or QR for a human's
//! wallet to scan and sign. This is a **zero-custody (T1)** tool: the agent
//! PROPOSES a payment; the human's wallet DISPOSES. It holds no private key and
//! makes no network call, so the worst a prompt-injection can do is produce a
//! request the human reviews and declines.
//!
//! The pure URL-builder core lives in [`pay`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod pay;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::pay::{build_url, PayRequest};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_request";

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
            "Build a Solana Pay transfer-request URL for a SOL or SPL-token payment, to be shown \
             as a link or QR code for a human's wallet to scan and sign. Holds no key and makes no \
             network call: it only PROPOSES a payment — the human approves and signs it in their \
             own wallet. Use it to request or invoice a payment, never to move funds directly."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Base58 Solana address to be paid (required)."
                    },
                    "amount": {
                        "type": "string",
                        "description": "Amount in SOL, or in the SPL token's UI units if spl_token is set. Non-negative decimal string, e.g. \"1.5\"."
                    },
                    "spl_token": {
                        "type": "string",
                        "description": "SPL token mint address. Omit for a native SOL payment."
                    },
                    "reference": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional base58 reference public keys for later transaction lookup."
                    },
                    "label": {
                        "type": "string",
                        "description": "Who is requesting the payment (shown in the wallet)."
                    },
                    "message": {
                        "type": "string",
                        "description": "What the payment is for (shown in the wallet)."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional SPL memo recorded on-chain with the transfer."
                    }
                },
                "required": ["recipient"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let req: PayRequest = match serde_json::from_str(&args) {
                Ok(r) => r,
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

            match build_url(&req) {
                Ok(url) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built solana pay url",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: url,
                        error: None,
                    })
                }
                Err(reason) => {
                    // Fails closed: an invalid/hostile request yields NO url; the reason
                    // is surfaced to the model as a normal (reactable) result, not a fault.
                    emit(
                        PluginAction::Reject,
                        PluginOutcome::Failure,
                        "rejected invalid pay request",
                    );
                    Ok(ToolResult {
                        success: false,
                        output: reason,
                        error: None,
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
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPayRequest);
}
