//! ZeroClaw WIT tool plugin: `caixa_charge`.
//!
//! Brazil-first Solana Pay charge terminal. Pure logic in [`charge`]; this file
//! is the thin `#[cfg(target_family = "wasm")]` shim.

pub mod charge;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::charge::{execute_charge, ChargeArgs, ChargeConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct CaixaCharge;

    const PLUGIN_NAME: &str = "caixa-charge";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "caixa_charge";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(default)]
        amount_brl: Option<f64>,
        #[serde(default)]
        amount_usdc: Option<String>,
        #[serde(default)]
        recipient: Option<String>,
        invoice_id: String,
        #[serde(default)]
        memo_extra: Option<String>,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        mint: Option<String>,
        #[serde(default)]
        reference: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for CaixaCharge {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for CaixaCharge {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Cria uma cobrança Solana Pay em USDC a partir de um valor em BRL ou USDC. \
             Retorna URL solana: + payload para QR. Nunca assina e nunca guarda chave (T1). \
             Use quando o comerciante pedir para cobrar uma mesa/fatura (ex: 'Cobra mesa 4: R$ 25'). \
             Creates a Solana Pay USDC charge from BRL or USDC. Returns solana: URL + QR payload. \
             Never signs; holds no keys (custody T1)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "amount_brl": {
                        "type": "number",
                        "description": "Invoice amount in BRL. Quoted to USDC via HTTPS price API."
                    },
                    "amount_usdc": {
                        "type": "string",
                        "description": "Invoice amount in USDC decimal string (e.g. '25.00'). Use instead of amount_brl."
                    },
                    "recipient": {
                        "type": "string",
                        "description": "Merchant Solana address (base58). Defaults to config.recipient."
                    },
                    "invoice_id": {
                        "type": "string",
                        "description": "Invoice / table id (e.g. '412' or 'mesa-4'). Embedded as INV= in memo."
                    },
                    "memo_extra": {
                        "type": "string",
                        "description": "Optional extra memo text (no secrets)."
                    },
                    "message": {
                        "type": "string",
                        "description": "Optional Solana Pay message shown in wallets."
                    },
                    "mint": {
                        "type": "string",
                        "description": "SPL mint (must be allowlisted; default mainnet USDC)."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Optional Solana Pay reference; defaults to invoice_id."
                    }
                },
                "required": ["invoice_id"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = match ChargeConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "bad config");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            let charge_args = ChargeArgs {
                amount_brl: parsed.amount_brl,
                amount_usdc: parsed.amount_usdc,
                recipient: parsed.recipient,
                invoice_id: parsed.invoice_id,
                memo_extra: parsed.memo_extra,
                message: parsed.message,
                mint: parsed.mint,
                reference: parsed.reference,
            };

            let http = caixa_core::WakiHttpGet;
            match execute_charge(&charge_args, &cfg, Some(&http)) {
                Ok(out) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "charge built");
                    Ok(ToolResult {
                        success: true,
                        output: out.summary,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "charge refused");
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "caixa_charge::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(CaixaCharge);
}
