//! ZeroClaw WIT tool plugin: `token-risk-check` (custody tier T0).
//!
//! Assesses a Solana mint for dangerous controls: mint/freeze authority,
//! Token-2022 permanent delegate / transfer hook / fees, and holder
//! concentration signals. Read-only. Never signs. Never holds keys.
//!
//! Pure core: [`risk`]. Wasm shim below does HTTP via host `wasi:http` (waki).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo test
//!         cargo build --target wasm32-wasip2 --release

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::risk::{
        analyze_from_rpc_payloads, das_get_asset, reject_unsafe_intent, report_to_agent_output,
        rpc_get_account_info, rpc_get_token_largest_accounts, rpc_get_token_supply, parse_pubkey,
        PluginConfig, CUSTODY_TIER,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::Value;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(default)]
        include_holders: Option<bool>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Assess Solana mint risk (T0 read-only): mint/freeze authorities, \
             Token-2022 permanent delegate / transfer hook / transfer fees, and \
             holder concentration. Returns green/amber/red with short reasons. \
             Never signs transactions or accepts private keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Solana mint address (base58 pubkey)."
                    },
                    "include_holders": {
                        "type": "boolean",
                        "description": "If true, also call getTokenLargestAccounts for concentration (default true)."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            if let Some(msg) = reject_unsafe_intent(&args) {
                emit(PluginAction::Fail, PluginOutcome::Failure, "unsafe intent rejected", None);
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(msg),
                });
            }

            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            if let Err(e) = parse_pubkey(&parsed.mint) {
                emit(PluginAction::Fail, PluginOutcome::Failure, "bad mint", None);
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e),
                });
            }

            let cfg = PluginConfig::from_section(&parsed.config);
            let include_holders = parsed.include_holders.unwrap_or(true);

            let account_body = rpc_get_account_info(&parsed.mint, &cfg.commitment);
            let account_resp = match post_rpc(&cfg.rpc_url, &account_body) {
                Ok(v) => v,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "rpc error", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("rpc getAccountInfo failed: {e}")),
                    });
                }
            };
            if let Some(err) = account_resp.get("error") {
                emit(PluginAction::Fail, PluginOutcome::Failure, "rpc error body", None);
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("rpc error: {err}")),
                });
            }
            let account_result = account_resp
                .get("result")
                .cloned()
                .unwrap_or(Value::Null);

            let supply_result = {
                let body = rpc_get_token_supply(&parsed.mint, &cfg.commitment);
                post_rpc(&cfg.rpc_url, &body)
                    .ok()
                    .and_then(|v| v.get("result").cloned())
            };

            let largest_result = if include_holders {
                let body = rpc_get_token_largest_accounts(&parsed.mint, &cfg.commitment);
                post_rpc(&cfg.rpc_url, &body)
                    .ok()
                    .and_then(|v| v.get("result").cloned())
            } else {
                None
            };

            // Optional DAS enrichment is best-effort and never required.
            if let Some(das) = cfg.das_url.as_ref() {
                let _ = post_rpc(das, &das_get_asset(&parsed.mint));
            }

            match analyze_from_rpc_payloads(
                &parsed.mint,
                &account_result,
                supply_result.as_ref(),
                largest_result.as_ref(),
            ) {
                Ok(report) => {
                    let output = report_to_agent_output(&report);
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "risk scored",
                        Some(report.risk.as_str()),
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "analyze failed", None);
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    fn post_rpc(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .map_err(|e| e.to_string())
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        risk: Option<&str>,
    ) {
        let attrs = risk.map(|r| {
            format!(
                "{{\"custody_tier\":\"{CUSTODY_TIER}\",\"risk\":\"{r}\"}}"
            )
        });
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
