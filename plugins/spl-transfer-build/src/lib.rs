//! ZeroClaw WIT tool plugin: `spl_transfer_build`.
//!
//! Builds an **unsigned** SPL token transfer transaction (legacy wire format,
//! base64) with optional destination ATA create + memo. Optional durable nonce
//! for approval-queue blockhash safety.
//!
//! Custody **T1 Build** — no keys, no sign, no submit.
//!
//! Build:  cargo build --target wasm32-wasip2 --release

pub mod codec;
pub mod transfer;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::transfer::{
        build_spl_transfer, build_to_json, HttpPost, TransferConfig, TransferRequest,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SplTransferBuild;

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "spl_transfer_build";
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

    struct WakiHttp;

    impl HttpPost for WakiHttp {
        fn post_json(
            &self,
            url: &str,
            body: &str,
            headers: &[(String, String)],
        ) -> Result<String, String> {
            let parsed: serde_json::Value =
                serde_json::from_str(body).map_err(|e| format!("json body: {e}"))?;
            let mut req = waki::Client::new()
                .post(url)
                .connect_timeout(CONNECT_TIMEOUT)
                .header("Content-Type", "application/json")
                .json(&parsed);
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("content-type") {
                    continue;
                }
                if k.eq_ignore_ascii_case("authorization") {
                    req = req.header("Authorization", v.clone());
                } else if k.eq_ignore_ascii_case("x-api-key") {
                    req = req.header("X-Api-Key", v.clone());
                }
            }
            let resp = req.send().map_err(|e| format!("http send: {e}"))?;
            let status = resp.status_code();
            let val: serde_json::Value = resp.json().map_err(|e| format!("http body: {e}"))?;
            let text = val.to_string();
            if status >= 400 {
                return Err(format!("HTTP {status}: {text}"));
            }
            Ok(text)
        }
    }

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        from: String,
        to: String,
        amount: f64,
        mint: String,
        #[serde(default)]
        decimals: Option<u8>,
        #[serde(default)]
        memo: Option<String>,
        #[serde(default)]
        fee_payer: Option<String>,
        #[serde(default)]
        token_2022: Option<bool>,
        #[serde(default)]
        nonce_account: Option<String>,
        #[serde(default)]
        nonce_authority: Option<String>,
        #[serde(default)]
        require_dest_ata: Option<bool>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SplTransferBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SplTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an unsigned SPL token transfer transaction (base64 wire format) for a human \
             or host approval gate to sign (custody T1: no keys). Handles destination ATA \
             creation, transferChecked, optional memo, optional durable nonce. \
             Returns a human-readable summary for the approval UI. Never accepts private keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "from": {
                        "type": "string",
                        "description": "Source token owner wallet (base58). Signs the transfer."
                    },
                    "to": {
                        "type": "string",
                        "description": "Destination wallet owner (base58). ATA is derived."
                    },
                    "amount": {
                        "type": "number",
                        "description": "Decimal UI amount (e.g. 25 for 25 USDC)."
                    },
                    "mint": {
                        "type": "string",
                        "description": "SPL token mint address."
                    },
                    "decimals": {
                        "type": "integer",
                        "description": "Token decimals; fetched from mint account if omitted."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional on-chain memo for invoice reconciliation."
                    },
                    "fee_payer": {
                        "type": "string",
                        "description": "Fee payer if different from from (default: from)."
                    },
                    "token_2022": {
                        "type": "boolean",
                        "description": "Use Token-2022 program (default from config/false)."
                    },
                    "nonce_account": {
                        "type": "string",
                        "description": "Optional durable nonce account to avoid blockhash expiry in approval queues."
                    },
                    "nonce_authority": {
                        "type": "string",
                        "description": "Nonce authority (default fee_payer)."
                    },
                    "require_dest_ata": {
                        "type": "boolean",
                        "description": "If true, fail when destination ATA is missing instead of creating it."
                    }
                },
                "required": ["from", "to", "amount", "mint"]
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

            let cfg = TransferConfig::from_section(&parsed.config);
            let req = TransferRequest {
                from: parsed.from,
                to: parsed.to,
                amount: parsed.amount,
                mint: parsed.mint,
                decimals: parsed.decimals,
                memo: parsed.memo,
                fee_payer: parsed.fee_payer,
                token_2022: parsed.token_2022,
                nonce_account: parsed.nonce_account,
                nonce_authority: parsed.nonce_authority,
                require_dest_ata: parsed.require_dest_ata.unwrap_or(false),
            };

            match build_spl_transfer(&WakiHttp, &cfg, &req) {
                Ok(built) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built unsigned spl transfer",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: build_to_json(&built),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "transfer build refused",
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

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "spl_transfer_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SplTransferBuild);
}
