//! A ZeroClaw WIT tool plugin: `depin_uptime_watch`.
//!
//! Checks recent Solana DePIN memo attestations and returns a shaped freshness
//! verdict (`OK` / `STALE` / `MISSING`). Custody **T0**: read-only RPC, no keys,
//! no signing, no submit path.
//!
//! The pure watcher core lives in [`watch`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test` (mocked RPC). The
//! wasm component is a `#[cfg(target_family = "wasm")]` shim that calls into
//! that core and emits structured `log-record` events (never stdout).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod watch;

#[allow(dead_code, unused_imports, clippy::wrong_self_convention)]
#[path = "vendor/solana_core/lib.rs"]
pub mod solana_core;

pub use solana_core::{error, ix, keys, nonce, rpc, shape, tx, CoreError, CoreResult};

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::rpc::HttpClient;
    use crate::watch;
    use crate::{CoreError, CoreResult};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DepinUptimeWatch;
    struct WakiHttp;

    const PLUGIN_NAME: &str = "depin-uptime-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_uptime_watch";

    impl HttpClient for WakiHttp {
        fn post_json(&self, url: &str, body: &Value) -> CoreResult<Value> {
            const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
            waki::Client::new()
                .post(url)
                .connect_timeout(CONNECT_TIMEOUT)
                .json(body)
                .send()
                .map_err(|e| CoreError::msg(e.to_string()))?
                .json::<Value>()
                .map_err(|e| CoreError::msg(e.to_string()))
        }
    }

    impl PluginInfo for DepinUptimeWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for DepinUptimeWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check recent Solana DePIN attestation memos and return an uptime freshness verdict (T0)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string",
                        "description": "Stable device identifier to check."
                    },
                    "max_age_secs": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Optional freshness threshold overriding plugin config."
                    }
                },
                "required": ["device_id"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let (args_json, config) = match split_execute_args(&args) {
                Ok(parsed) => parsed,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                        None,
                    );
                    return Ok(failure(format!("invalid arguments: {e}")));
                }
            };

            let now_unix = now_unix()?;
            match watch::execute(&args_json, &config, &WakiHttp, now_unix) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "checked uptime",
                        Some(format!(
                            "{{\"verdict\":{},\"age_secs\":{}}}",
                            json_string(verdict_label(&output.verdict)),
                            output
                                .age_secs
                                .map(|age| age.to_string())
                                .unwrap_or_else(|| "null".to_string())
                        )),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: output.summary,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "uptime watch failed",
                        None,
                    );
                    Ok(failure(e))
                }
            }
        }
    }

    fn split_execute_args(args: &str) -> Result<(String, HashMap<String, String>), String> {
        let mut value: Value =
            serde_json::from_str(args).map_err(|e| format!("invalid JSON: {e}"))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "arguments must be a JSON object".to_string())?;
        let config = match object.remove("__config") {
            Some(Value::Object(config)) => config
                .into_iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key, value.to_string()))
                        .ok_or_else(|| "__config values must be strings".to_string())
                })
                .collect::<Result<HashMap<_, _>, _>>()?,
            Some(_) => return Err("__config must be an object".to_string()),
            None => HashMap::new(),
        };

        Ok((value.to_string(), config))
    }

    fn now_unix() -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|e| format!("system time before unix epoch: {e}"))
    }

    fn failure(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<String>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_uptime_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    fn verdict_label(verdict: &watch::Verdict) -> &'static str {
        match verdict {
            watch::Verdict::Ok => "OK",
            watch::Verdict::Stale => "STALE",
            watch::Verdict::Missing => "MISSING",
        }
    }

    fn json_string(value: &str) -> String {
        serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
    }

    export!(DepinUptimeWatch);
}
