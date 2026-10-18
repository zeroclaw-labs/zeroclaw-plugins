//! A ZeroClaw WIT tool plugin: `token-risk-check`.
//!
//! Red/amber/green risk assessment for any Solana SPL / Token-2022 mint:
//! mint & freeze authority, dangerous Token-2022 extensions, and holder
//! concentration — in ~200 tokens of shaped output.
//!
//! The pure risk core lives in [`risk`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//! (Layout mirrors `plugins/redact-text`, the canonical reference plugin.)
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::risk::{self, Rpc};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::{json, Value};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    /// Live JSON-RPC over the host's wasi:http (`http_client` permission).
    struct WakiRpc {
        rpc_url: String,
    }

    impl Rpc for WakiRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, String> {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
            let resp: Value = waki::Client::new()
                .post(&self.rpc_url)
                .json(&body)
                .send()
                .map_err(|e| format!("rpc transport error: {e}"))?
                .json()
                .map_err(|e| format!("rpc bad json: {e}"))?;
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
            risk::NAME.to_string()
        }

        fn description() -> String {
            risk::DESCRIPTION.to_string()
        }

        fn parameters_schema() -> String {
            risk::parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // The host injects this plugin's jailed config section into args
            // as `__config` (config_read permission). The RPC endpoint is
            // taken from there ONLY — an `rpc_url` in the LLM-visible args is
            // deliberately ignored (see README threat model).
            let rpc_url = serde_json::from_str::<Value>(&args)
                .ok()
                .and_then(|v| {
                    v.get("__config")?
                        .get("rpc_url")?
                        .as_str()
                        .map(str::to_string)
                })
                .unwrap_or_else(|| DEFAULT_RPC.to_string());

            let rpc = WakiRpc { rpc_url };
            match risk::execute(&rpc, &args) {
                Ok(output) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "risk report produced");
                    Ok(ToolResult { success: true, output, error: None })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "risk check failed");
                    Ok(ToolResult { success: false, output: String::new(), error: Some(e) })
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
