//! ZeroClaw WIT tool plugin: `squads_propose`.
//!
//! Builds a Squads v4 payment proposal as an unsigned transaction. The agent
//! proposes; the multisig disposes. The plugin holds no keys and signs
//! nothing.
//!
//! The pure logic lives in [`core`] with no wasm dependency, so it compiles
//! and tests on the host with a plain `cargo test`; this shim wires the same
//! logic to the `tool-plugin` WIT world with the blocking `waki` client.
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

    use crate::core::{run, ProposeArgs};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use quorum_core::rpc::Rpc;
    use serde_json::Value;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SquadsPropose;

    const PLUGIN_NAME: &str = "squads-propose";
    const PLUGIN_VERSION: &str = "0.1.0";
    const TOOL_NAME: &str = "squads_propose";

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

    impl PluginInfo for SquadsPropose {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SquadsPropose {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Draft a Squads v4 multisig payment proposal as an unsigned transaction. \
             Recipients must exist in the operator's address book and tokens must be on \
             the config allowlist; amounts are capped per proposal. Funds move only after \
             the multisig quorum approves in the Squads app. This tool holds no keys and \
             cannot sign, approve, or execute anything."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Recipient name from the operator's address book. Raw addresses are rejected."
                    },
                    "amount": {
                        "type": "string",
                        "description": "Decimal amount as a string, for example \"150\" or \"12.5\"."
                    },
                    "token": {
                        "type": "string",
                        "description": "Token symbol from the config allowlist, for example \"USDC\"."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional short memo attached to the proposal."
                    }
                },
                "required": ["recipient", "amount", "token"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: Value = match serde_json::from_str(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };
            let cfg = parsed.get("__config").cloned().unwrap_or(Value::Null);
            if cfg.is_null() {
                return Ok(fail(
                    "no config injected: grant config_read and set the plugin config".into(),
                ));
            }
            let rpc_url = match cfg.get("rpc_url").and_then(|v| v.as_str()) {
                Some(u) if u.starts_with("https://") => u.to_string(),
                _ => return Ok(fail("config rpc_url missing or not https".into())),
            };
            let tool_args: ProposeArgs = match serde_json::from_value(parsed.clone()) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };
            emit(PluginAction::Start, None, "building proposal");
            let rpc = WakiRpc { url: rpc_url };
            match run(&rpc, &cfg, &tool_args) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "proposal built",
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
                function_name: "squads_propose::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SquadsPropose);
}
