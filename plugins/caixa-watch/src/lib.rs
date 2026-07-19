//! ZeroClaw WIT tool plugin: `caixa_watch`.

pub mod watch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::watch::{execute_watch, WatchArgs, WatchConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct CaixaWatch;

    const PLUGIN_NAME: &str = "caixa-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "caixa_watch";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(default)]
        recipient: Option<String>,
        invoice_id: String,
        #[serde(default)]
        amount_usdc: Option<String>,
        #[serde(default)]
        mint: Option<String>,
        #[serde(default)]
        reference: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for CaixaWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for CaixaWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Verifica se uma fatura Caixa (INV=…) já foi paga on-chain e devolve um alerta curto para SOP/Telegram. \
             Somente leitura (T0). \
             Checks whether a Caixa invoice (INV=…) has been paid on-chain and returns a short alert for SOP/Telegram. \
             Read-only (custody T0)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": { "type": "string", "description": "Merchant address to watch (base58)." },
                    "invoice_id": { "type": "string", "description": "Invoice id to match in memo (INV=)." },
                    "amount_usdc": { "type": "string", "description": "Optional expected USDC amount for the alert text." },
                    "mint": { "type": "string", "description": "Optional mint (informational)." },
                    "reference": { "type": "string", "description": "Optional Solana Pay reference to match." }
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
            let cfg = match WatchConfig::from_section(&parsed.config) {
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
            let wargs = WatchArgs {
                recipient: parsed.recipient,
                invoice_id: parsed.invoice_id,
                amount_usdc: parsed.amount_usdc,
                mint: parsed.mint,
                reference: parsed.reference,
            };
            let transport = caixa_core::WakiTransport;
            match execute_watch(&wargs, &cfg, &transport) {
                Ok(out) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        if out.paid { "paid" } else { "waiting" },
                    );
                    Ok(ToolResult {
                        success: true,
                        output: out.summary,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "watch failed");
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
                function_name: "caixa_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(CaixaWatch);
}
