//! A ZeroClaw WIT tool plugin: `solana_pay_request`.
//!
//! Builds Solana Pay transfer-request URLs and QR-ready payloads so a
//! Telegram/Discord agent can act as a payment terminal without holding keys.
//!
//! Custody tier: **T1 Build** — unsigned URL only; a human wallet pays.
//!
//! Pure logic lives in [`pay`] (no wasm deps). The component shim below is
//! `#[cfg(target_family = "wasm")]` only.
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

    use std::collections::HashMap;

    use crate::pay::{build_pay_request, PayConfig, PayRequest};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaPayRequest;

    const PLUGIN_NAME: &str = "solana-pay-request";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_pay_request";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        recipient: String,
        #[serde(default)]
        amount: Option<f64>,
        /// SPL mint; omit for native SOL.
        #[serde(default, alias = "spl_token", alias = "spl-token")]
        mint: Option<String>,
        #[serde(default)]
        memo: Option<String>,
        /// Single reference pubkey (also accepts `references` array).
        #[serde(default)]
        reference: Option<String>,
        #[serde(default)]
        references: Option<Vec<String>>,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        message: Option<String>,
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
            "Build a Solana Pay transfer-request URL and QR-ready payload (custody T1: \
             no signing, no secrets). Args: recipient (wallet), amount, optional SPL mint, \
             memo, reference. Returns a solana: URL the user can open in a wallet or scan as QR. \
             Use when the user asks to charge, invoice, or request payment in SOL/USDC/SPL. \
             Never accepts private keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Base58 Solana wallet address that receives the funds."
                    },
                    "amount": {
                        "type": "number",
                        "description": "Decimal amount in UI units (e.g. 25 for 25 USDC). Omit for open-ended."
                    },
                    "mint": {
                        "type": "string",
                        "description": "SPL token mint address. Omit for native SOL."
                    },
                    "memo": {
                        "type": "string",
                        "description": "On-chain memo for invoice reconciliation (e.g. Invoice #412)."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Optional reference pubkey for findReference matching."
                    },
                    "references": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional list of reference pubkeys."
                    },
                    "label": {
                        "type": "string",
                        "description": "Merchant label shown in the wallet UI."
                    },
                    "message": {
                        "type": "string",
                        "description": "Short message shown in the wallet UI."
                    }
                },
                "required": ["recipient"]
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

            let mut references = parsed.references.unwrap_or_default();
            if let Some(r) = parsed.reference {
                if !r.trim().is_empty() {
                    references.push(r);
                }
            }

            let cfg = PayConfig::from_section(&parsed.config);
            let req = PayRequest {
                recipient: parsed.recipient,
                amount: parsed.amount,
                mint: parsed.mint,
                memo: parsed.memo,
                references,
                label: parsed.label,
                message: parsed.message,
            };

            match build_pay_request(&req, &cfg) {
                Ok(result) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built solana pay url",
                        None,
                    );
                    // Compact JSON for machines + summary for the model.
                    let output = serde_json::json!({
                        "custody_tier": result.custody_tier,
                        "url": result.url,
                        "qr_payload": result.qr_payload,
                        "summary": result.summary,
                    })
                    .to_string();
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "pay request refused",
                        None,
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            }
        }
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        extra: Option<&str>,
    ) {
        let attrs = extra.map(|s| format!("{{\"detail\":{}}}", serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())));
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
