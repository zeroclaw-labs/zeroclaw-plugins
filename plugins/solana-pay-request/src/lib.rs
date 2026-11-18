//! A ZeroClaw WIT tool plugin: `solana-pay-request`.
//!
//! Builds Solana Pay transfer-request URLs and QR-ready payloads: recipient,
//! amount, SPL mint, memo, reference key(s), label, message. Turns any
//! ZeroClaw agent on Telegram/WhatsApp into a payment terminal:
//! "charge table 4 for 25 USDC" → a `solana:` URL the host can render as a QR.
//!
//! CUSTODY TIER: T1 (build-only, zero secrets). The plugin performs no network
//! I/O and holds no key material of any kind — the payer's own wallet builds
//! and signs the transaction from the URL. Pair with `payment-watch` (T0) to
//! confirm settlement.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod solana_pay_request;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::solana_pay_request::{build, PayRequest};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana-pay-request";

    struct SolanaPayRequest;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        /// Recipient address (base58).
        recipient: String,
        /// Amount in SOL or SPL ui units.
        amount: f64,
        /// SPL mint address; omit or "SOL" for native SOL.
        #[serde(default)]
        mint: Option<String>,
        /// Invoice memo attached on-chain by the payer's wallet.
        #[serde(default)]
        memo: Option<String>,
        /// Reference key(s) for watch-side reconciliation.
        #[serde(default)]
        reference: Vec<String>,
        /// Merchant label for the payer UI.
        #[serde(default)]
        label: Option<String>,
        /// Charge description for the payer UI.
        #[serde(default)]
        message: Option<String>,
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
            "Build a Solana Pay transfer-request URL + QR-ready payload for a charge: recipient, \
             amount, optional SPL mint, memo, and reference keys. Zero secrets (T1): the payer's \
             wallet signs. Pair with payment-watch to confirm the payment lands."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "description": "Recipient address (base58)."},
                    "amount": {"type": "number", "description": "Amount in SOL or SPL ui units."},
                    "mint": {"type": "string", "description": "SPL mint address. Omit or 'SOL' for native SOL."},
                    "memo": {"type": "string", "description": "On-chain memo, e.g. 'Invoice #412'."},
                    "reference": {"type": "array", "items": {"type": "string"},
                        "description": "Reference public key(s) for payment-watch reconciliation."},
                    "label": {"type": "string", "description": "Merchant label shown in the payer's wallet."},
                    "message": {"type": "string", "description": "Charge description shown in the payer's wallet."}
                },
                "required": ["recipient", "amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(fail(&format!("invalid arguments: {e}")));
                }
            };
            let req = PayRequest {
                recipient: parsed.recipient,
                amount: parsed.amount,
                mint: parsed.mint,
                memo: parsed.memo,
                reference: parsed.reference,
                label: parsed.label,
                message: parsed.message,
            };
            match build(&req) {
                Ok(p) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        &p.summary,
                        Some(p.url.len()),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "url": p.url,
                            "qr_payload": p.qr_payload,
                            "summary": p.summary,
                        })
                        .to_string(),
                        error: None,
                    })
                }
                Err(e) => Ok(fail(&e)),
            }
        }
    }

    fn fail(msg: &str) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, msg, None);
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg.to_string()),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, url_len: Option<usize>) {
        let attrs = url_len.map(|n| format!("{{\"url_bytes\":{n}}}"));
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
