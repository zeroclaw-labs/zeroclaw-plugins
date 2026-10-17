//! ZeroClaw WIT tool plugin: `squads_watch`.
//!
//! The treasury heartbeat: reports pending Squads proposals, approval counts,
//! and outcomes since a cursor, sized for SOP schedules and group chat pings.
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

    use crate::core::{run, WatchArgs};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use quorum_core::rpc::Rpc;
    use serde_json::Value;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SquadsWatch;

    const PLUGIN_NAME: &str = "squads-watch";
    const PLUGIN_VERSION: &str = "0.1.0";
    const TOOL_NAME: &str = "squads_watch";

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

    impl PluginInfo for SquadsWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SquadsWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check the configured Squads v4 multisig for treasury activity: pending \
             proposals with approval counts, executed and rejected outcomes since a cursor, \
             and whether members need to vote. Read only; the watched multisig is fixed in \
             operator config."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "cursor": {
                        "type": "integer",
                        "description": "Last transaction index already reported; scanning starts after it."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum proposals to report (default 10, max 20)."
                    }
                }
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
            let tool_args: WatchArgs = match serde_json::from_value(parsed.clone()) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };
            emit(PluginAction::Query, None, "checking multisig");
            match run(&WakiRpc { url: rpc_url }, &cfg, &tool_args) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "status built",
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
                function_name: "squads_watch::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SquadsWatch);
}
