//! A ZeroClaw WIT tool plugin: `brl_usdc_invoice`.
//!
//! Dual-rail invoice clerk: static PIX Copia e Cola (BRL) plus a Solana Pay
//! transfer-request URL (USDC), bound by one `invoice_id`. Custody tier **T1**
//! — no Solana private keys; merchant receive addresses and amount caps live in
//! the plugin's jailed config section (`config_read`).
//!
//! The pure issuance core lives in [`invoice_tool`] with no wasm dependency, so
//! it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod invoice_tool;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::invoice_tool::execute_invoice;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct BrlUsdcInvoice;

    const PLUGIN_NAME: &str = "brl-usdc-invoice";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "brl_usdc_invoice";

    impl PluginInfo for BrlUsdcInvoice {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for BrlUsdcInvoice {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Dual-rail PIX BRL + Solana Pay USDC invoice under one invoice_id. \
             Emits PIX Copia e Cola and a solana: transfer URL. No private keys; \
             caps, mint allowlist, and recipient_locked enforced in code (T1)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "amount_brl": {
                        "type": "string",
                        "description": "Invoice amount in BRL (2 decimal places, e.g. \"150.00\")."
                    },
                    "invoice_id": {
                        "type": "string",
                        "description": "Optional invoice id (memo/status). Empty → auto INV-XXXXXXXX."
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional short description (used in memo label)."
                    },
                    "payer_name": {
                        "type": "string",
                        "description": "Optional payer name (used in memo label if no description)."
                    },
                    "usdc_amount": {
                        "type": "string",
                        "description": "Optional explicit USDC amount; otherwise derived from BRL / offline rate."
                    },
                    "merchant_override": {
                        "type": "string",
                        "description": "Optional Solana recipient override; ignored when recipient_locked=true."
                    },
                    "mint_override": {
                        "type": "string",
                        "description": "Optional SPL mint override or alias USDC; must be in allowed_mints."
                    }
                },
                "required": ["amount_brl"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            match execute_invoice(&args) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "invoice built",
                        None,
                    );
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
                        "invoice rejected",
                        Some(&e),
                    );
                    // Validation / cap failures are soft: Ok(success: false), not Err.
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        detail: Option<&str>,
    ) {
        let attrs = detail.map(|d| {
            // Keep attrs small and JSON-ish; avoid dumping full payloads.
            let short = if d.len() > 120 { &d[..120] } else { d };
            format!(
                "{{\"detail\":{}}}",
                serde_json::to_string(short).unwrap_or_else(|_| "\"\"".into())
            )
        });
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "brl_usdc_invoice::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(BrlUsdcInvoice);
}
