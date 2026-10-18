//! ZeroClaw WIT tool plugin: `tx_xray`.
//!
//! Give it any base64 unsigned transaction and it returns a short receipt of
//! what the bytes actually do, with hazard flags and an optional simulation
//! verdict. Built so approval gates render truth instead of the agent's own
//! description of itself.
//!
//! The pure logic lives in [`core`]; this shim wires it to the `tool-plugin`
//! WIT world with the blocking `waki` client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::core::{run, XrayArgs};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use quorum_core::rpc::Rpc;
    use serde_json::Value;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TxXray;

    const PLUGIN_NAME: &str = "tx-xray";
    const PLUGIN_VERSION: &str = "0.1.0";
    const TOOL_NAME: &str = "tx_xray";

    struct WakiRpc {
        url: String,
    }

    impl Rpc for WakiRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, String> {
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params
            });
            let resp = waki::Client::new()
                .post(&self.url)
                .json(&body)
                .send()
                .map_err(|e| format!("rpc http error: {e:?}"))?;
            let v: Value = resp
                .json()
                .map_err(|e| format!("rpc decode error: {e:?}"))?;
            if let Some(err) = v.get("error") {
                return Err(format!("rpc error: {err}"));
            }
            v.get("result")
                .cloned()
                .ok_or_else(|| "rpc response missing result".to_string())
        }
    }

    /// Offline stand-in used when simulation is disabled; any call is a bug.
    struct NoRpc;
    impl Rpc for NoRpc {
        fn call(&self, method: &str, _params: Value) -> Result<Value, String> {
            Err(format!("network disabled for this call: {method}"))
        }
    }

    impl PluginInfo for TxXray {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TxXray {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Decode a base64 unsigned Solana transaction into a short truthful receipt: \
             every instruction described from the bytes, Squads proposals unwrapped to show \
             the inner transfer, unknown programs and risky patterns flagged, and an \
             optional simulation verdict. Use before approving anything."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "unsigned_tx_base64": {
                        "type": "string",
                        "description": "The base64 encoded transaction to inspect."
                    },
                    "simulate": {
                        "type": "boolean",
                        "description": "Also simulate through the RPC (default true)."
                    }
                },
                "required": ["unsigned_tx_base64"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Value = match serde_json::from_str(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };
            let cfg = parsed.get("__config").cloned().unwrap_or(Value::Null);
            let tool_args: XrayArgs = match serde_json::from_value(parsed.clone()) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };
            emit(PluginAction::Start, None, "decoding transaction");
            let result = if tool_args.simulate {
                let rpc_url =
                    match cfg.get("rpc_url").and_then(|v| v.as_str()) {
                        Some(u) if u.starts_with("https://") => u.to_string(),
                        _ => return Ok(fail(
                            "config rpc_url missing or not https; set it or pass simulate=false"
                                .into(),
                        )),
                    };
                run(&WakiRpc { url: rpc_url }, &cfg, &tool_args)
            } else {
                run(&NoRpc, &cfg, &tool_args)
            };
            match result {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "receipt built",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, Some(PluginOutcome::Failure), &e);
                    Ok(fail(e))
                }
            }
        }
    }

    fn fail(msg: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg),
        }
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "tx_xray::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TxXray);
}
