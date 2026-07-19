//! ZeroClaw WIT tool plugin: `caixa_transfer_build`.

pub mod transfer;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::transfer::{execute_transfer_build, TransferArgs, TransferConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct CaixaTransferBuild;

    const PLUGIN_NAME: &str = "caixa-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "caixa_transfer_build";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        source_owner: String,
        destination: String,
        amount_usdc: String,
        #[serde(default)]
        invoice_id: Option<String>,
        #[serde(default)]
        memo_extra: Option<String>,
        #[serde(default)]
        amount_brl: Option<String>,
        #[serde(default)]
        mint: Option<String>,
        #[serde(default = "default_true")]
        create_dest_ata: bool,
        #[serde(default)]
        nonce_authority: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_true() -> bool {
        true
    }

    impl PluginInfo for CaixaTransferBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for CaixaTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Monta uma transação SPL USDC NÃO ASSINADA (base64) com durable nonce, ATA e memo de fatura. \
             Um humano ou Squads assina. Nunca segura chave (T1). \
             Builds an UNSIGNED SPL USDC transaction (base64) with durable nonce, ATA create, and invoice memo. \
             A human or Squads signs. Holds no keys (custody T1)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "source_owner": { "type": "string", "description": "Source wallet (fee payer / token owner), base58." },
                    "destination": { "type": "string", "description": "Destination wallet owner, base58." },
                    "amount_usdc": { "type": "string", "description": "USDC decimal amount, e.g. '25.00'." },
                    "invoice_id": { "type": "string", "description": "Optional invoice id for INV= memo." },
                    "amount_brl": { "type": "string", "description": "Optional BRL amount for BRL= memo field." },
                    "memo_extra": { "type": "string", "description": "Optional extra memo text." },
                    "mint": { "type": "string", "description": "Allowlisted SPL mint; default USDC." },
                    "create_dest_ata": { "type": "boolean", "description": "Prepend create-idempotent ATA (default true)." },
                    "nonce_authority": { "type": "string", "description": "Nonce authority if different from source_owner." }
                },
                "required": ["source_owner", "destination", "amount_usdc"]
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
            let cfg = match TransferConfig::from_section(&parsed.config) {
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
            let targs = TransferArgs {
                source_owner: parsed.source_owner,
                destination: parsed.destination,
                amount_usdc: parsed.amount_usdc,
                invoice_id: parsed.invoice_id,
                memo_extra: parsed.memo_extra,
                amount_brl: parsed.amount_brl,
                mint: parsed.mint,
                create_dest_ata: parsed.create_dest_ata,
                nonce_authority: parsed.nonce_authority,
            };
            let transport = caixa_core::WakiTransport;
            match execute_transfer_build(&targs, &cfg, &transport) {
                Ok(out) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "tx built");
                    Ok(ToolResult {
                        success: true,
                        output: out.summary,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "build refused");
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
                function_name: "caixa_transfer_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(CaixaTransferBuild);
}
