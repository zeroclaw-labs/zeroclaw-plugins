//! PixZClaw dashboard tool plugin: `pixzclaw_brief` (T0).
//!
//! Telegram-friendly cash card: USDC + SOL balances, 7d sparkline, recent
//! on-chain activity with PixZClaw memos. No private keys.
//!
//! Build: cargo build --target wasm32-wasip2 --release

pub mod brief_tool;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::Value;
    use solana_wasm_core::{HttpTransport, RpcError};

    use crate::brief_tool::{
        execute_from_args_with_http, now_unix, BriefConfig, ExecuteArgs, DEFAULT_LOOKBACK,
        DEFAULT_RECENT,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PixzclawBrief;

    const PLUGIN_NAME: &str = "pixzclaw-brief";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "pixzclaw_brief";

    struct WakiTransport;

    impl HttpTransport for WakiTransport {
        fn post_json(&self, url: &str, body: &Value) -> Result<Value, RpcError> {
            waki::Client::new()
                .post(url)
                .json(body)
                .send()
                .map_err(|e| RpcError::new(e.to_string()))?
                .json::<Value>()
                .map_err(|e| RpcError::new(e.to_string()))
        }
    }

    impl PluginInfo for PixzclawBrief {
        fn plugin_name() -> String {
            PLUGIN_NAME.into()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.into()
        }
    }

    impl Tool for PixzclawBrief {
        fn name() -> String {
            TOOL_NAME.into()
        }

        fn description() -> String {
            "PixZClaw dashboard (caixa): show USDC/SOL balances, 7-day activity sparkline, \
             and recent on-chain payments for the merchant wallet. Read-only T0 — never moves funds. \
             Call when the user asks for /caixa, dashboard, recebíveis, saldo, or treasury brief."
                .into()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "lookback": {
                        "type": "integer",
                        "description": "Max signatures to scan (default 30)."
                    },
                    "recent_limit": {
                        "type": "integer",
                        "description": "How many recent lines to list (default 5)."
                    }
                }
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "bad args");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            // Ensure config path works even if merchant only in config
            let _cfg = BriefConfig::from_map(&parsed.config);
            let lookback = parsed.lookback.unwrap_or(DEFAULT_LOOKBACK);
            let recent = parsed.recent_limit.unwrap_or(DEFAULT_RECENT);
            let mut args2 = parsed;
            // re-pack for helper
            let exec = ExecuteArgs {
                lookback: Some(lookback),
                recent_limit: Some(recent),
                merchant: args2.merchant.take(),
                config: args2.config,
            };

            match execute_from_args_with_http(exec, WakiTransport, now_unix()) {
                Ok(output) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "brief ok");
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "brief err");
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
                function_name: "pixzclaw_brief::tool::execute".into(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.into(),
            },
        );
    }

    export!(PixzclawBrief);
}
