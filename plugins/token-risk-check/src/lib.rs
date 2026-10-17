//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Given an SPL token mint, it reads the token's on-chain facts and returns a
//! red/amber/green risk verdict with reasons: is the mint or freeze authority
//! still active, how concentrated are the top holders, is it a Token-2022 mint
//! with extensions. Read-only (T0): it holds no key and never signs. It **fails
//! closed** — anything it cannot verify is reported as high risk.
//!
//! Pure scoring lives in [`risk`] and the RPC substrate in [`rpc`]; both are
//! host-testable with a plain `cargo test`. Build:
//!   rustup target add wasm32-wasip2 && cargo build --target wasm32-wasip2 --release

pub mod risk;
pub mod rpc;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::json;

    use crate::risk::assess;
    use crate::rpc;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";

    #[derive(serde::Deserialize)]
    struct Args {
        mint: String,
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
            "Check an SPL token mint for on-chain risk before touching it: whether the mint or \
             freeze authority is still active, how concentrated the top holders are, and whether \
             it is a Token-2022 mint with extensions. Read-only. Returns a red/amber/green verdict \
             with reasons, and fails closed (reports high risk) on anything it cannot verify."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 SPL token mint address to assess."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Args = match serde_json::from_str(&args) {
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
            let mint = parsed.mint.trim().to_string();
            if mint.is_empty() {
                emit(
                    PluginAction::Reject,
                    PluginOutcome::Failure,
                    "empty mint",
                    None,
                );
                return Ok(ToolResult {
                    success: false,
                    output: "`mint` is required".to_string(),
                    error: None,
                });
            }

            let url = rpc::rpc_url(&parsed.config);

            // getAccountInfo is required; a transport/RPC failure is surfaced (success:false).
            let acct = match rpc::call(
                &url,
                "getAccountInfo",
                json!([mint, {"encoding": "jsonParsed"}]),
            ) {
                Ok(v) => match rpc::result(&v) {
                    Ok(r) => r.clone(),
                    Err(e) => {
                        emit(
                            PluginAction::Fail,
                            PluginOutcome::Failure,
                            "rpc error",
                            None,
                        );
                        return Ok(ToolResult {
                            success: false,
                            output: e,
                            error: None,
                        });
                    }
                },
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "rpc call failed",
                        None,
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: e,
                        error: None,
                    });
                }
            };

            // getTokenLargestAccounts is best-effort; concentration is skipped if it fails.
            let largest = rpc::call(&url, "getTokenLargestAccounts", json!([mint]))
                .ok()
                .and_then(|v| rpc::result(&v).ok().cloned());

            let report = assess(&mint, &acct, largest.as_ref());
            let verdict = report.verdict.as_str().to_string();
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "assessed token risk",
                Some(format!("{{\"verdict\":\"{verdict}\"}}")),
            );

            Ok(ToolResult {
                success: true,
                output: report.to_json().to_string(),
                error: None,
            })
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<String>) {
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
