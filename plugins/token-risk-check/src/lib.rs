//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Given an SPL token mint address, returns a red/amber/green risk verdict:
//! mint/freeze authorities, holder concentration, and Token-2022 extensions
//! (transfer fees, transfer hooks, permanent delegate, non-transferable,
//! default-frozen). Read-only (custody tier T0): no keys, no signing, no
//! state — the only secret it can ever see is the operator's RPC URL.
//!
//! The pure assessment core lives in [`risk`] and [`rpc`] with no wasm/http
//! dependency, so it compiles and tests on the host with a plain `cargo test`
//! against canned RPC fixtures; this file is the thin component shim that
//! wires it to the `tool-plugin` WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

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

    use serde_json::{json, Value};

    use crate::risk::{run_check, RiskConfig};
    use crate::rpc::RpcTransport;
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
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// JSON-RPC over the host's wasi:http via waki.
    struct WakiTransport {
        rpc_url: String,
    }

    impl RpcTransport for WakiTransport {
        fn call(&self, method: &str, params: &Value) -> Result<Value, String> {
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });
            let resp: Value = waki::Client::new()
                .post(&self.rpc_url)
                .json(&body)
                .connect_timeout(std::time::Duration::from_secs(10))
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?
                .json()
                .map_err(|e| format!("rpc response not json: {e}"))?;
            if let Some(err) = resp.get("error") {
                return Err(format!("rpc error: {err}"));
            }
            resp.get("result")
                .cloned()
                .ok_or_else(|| "rpc response missing result".to_string())
        }
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
            "Assess the on-chain risk of a Solana SPL token mint before interacting \
             with it. Returns a red/amber/green verdict with reasons: active \
             mint/freeze authorities, holder concentration, and Token-2022 \
             extensions (transfer fees, transfer hooks, permanent delegate, \
             non-transferable, default-frozen). Read-only; takes a mint address, \
             never a wallet or amount."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The SPL token mint address to assess (base58)."
                    }
                },
                "required": ["mint"]
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
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = RiskConfig::from_section(&parsed.config);
            let transport = WakiTransport {
                rpc_url: cfg.rpc_url.clone(),
            };

            match run_check(&transport, &parsed.mint, &cfg) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "assessed mint",
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
                        "assessment failed",
                    );
                    // Bad input / RPC trouble is a normal tool response the
                    // model can react to, not a plugin fault.
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
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
