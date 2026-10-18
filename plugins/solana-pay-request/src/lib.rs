//! `solana-pay-request` — a ZeroClaw tool plugin that builds a Solana Pay
//! transfer-request URL (and a QR-ready payload) for a SOL or SPL-token payment.
//!
//! Custody tier T0: this plugin holds **no secrets** and makes
//! **no network calls**. It is pure computation — validate inputs, construct a
//! `solana:` URL. The pure core ([`pay`]) is fully host-testable with no wasm
//! toolchain and no RPC; the `#[cfg(target_family = "wasm")]` shim below only
//! wires the WIT tool interface to that core.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod pay;
pub mod solana_core;

pub use pay::{build_transfer_url, parse_and_validate, render_output, ValidatedRequest};

#[cfg(target_family = "wasm")]
#[allow(unsafe_code)]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::pay;
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
            "Build a Solana Pay transfer-request URL (and QR-ready payload) for a SOL or SPL-token \
             payment. Zero secrets, zero network: it only validates inputs and constructs a \
             `solana:` URL a wallet scans to pay. Given a recipient wallet and optional amount, SPL \
             mint, reference key(s), label, message, and memo, it returns the URL plus an identical \
             QR payload. All free text is stripped of control/bidi/zero-width characters and \
             percent-encoded, so a hostile memo or label can never inject a different recipient or \
             query parameter. Inputs: recipient (required), amount, spl_token, reference, label, \
             message, memo."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Base58 address of the recipient's NATIVE SOL wallet (not a token account; the payer's wallet derives the associated token account)."
                    },
                    "amount": {
                        "type": "string",
                        "description": "Optional payment amount in UI/display units (\"25\" = 25 USDC, \"0.5\" = 0.5 SOL), never lamports/raw. Non-negative decimal, a digit before '.', no sign, no scientific notation. Omit to let the payer enter the amount. Pass as a string for exact precision."
                    },
                    "spl_token": {
                        "type": "string",
                        "description": "Optional base58 SPL token mint. Present = SPL transfer of that mint; absent = native SOL. (The URL-style key `spl-token` is also accepted.)"
                    },
                    "reference": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional base58 reference pubkey(s): read-only tracking keys (e.g. an order/client id). A single string is also accepted."
                    },
                    "label": {
                        "type": "string",
                        "description": "Optional display label for the payment source (store/brand). Display-only, not written on-chain."
                    },
                    "message": {
                        "type": "string",
                        "description": "Optional display message describing the payment (item/order note). Display-only, not written on-chain."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional SPL memo written ON-CHAIN with the transfer."
                    }
                },
                "required": ["recipient"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // Pure, deterministic, fail-closed: validate then build. No key
            // material is touched and no network call is made.
            match pay::parse_and_validate(&args) {
                Ok(v) => {
                    let output = pay::render_output(&v);
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "solana pay transfer request built",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Reject,
                        PluginOutcome::Failure,
                        "request rejected by validation",
                    );
                    Ok(fail(e))
                }
            }
        }
    }

    fn fail(message: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
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
