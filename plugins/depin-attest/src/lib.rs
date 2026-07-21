//! A ZeroClaw WIT tool plugin for DePIN attestation memo payloads.

pub mod attest;

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

    use crate::attest;
    use crate::rpc::HttpClient;
    use crate::{CoreError, CoreResult};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DepinAttest;
    struct WakiHttp;

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_attest";

    impl HttpClient for WakiHttp {
        fn post_json(&self, url: &str, body: &Value) -> CoreResult<Value> {
            waki::Client::new()
                .post(url)
                .json(body)
                .send()
                .map_err(|e| CoreError::msg(e.to_string()))?
                .json::<Value>()
                .map_err(|e| CoreError::msg(e.to_string()))
        }
    }

    impl PluginInfo for DepinAttest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for DepinAttest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an unsigned durable-nonce Solana memo attestation from a device sensor reading (T1)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string",
                        "description": "Stable device identifier to attest."
                    },
                    "reading": {
                        "type": "number",
                        "description": "Finite sensor reading value."
                    },
                    "unit": {
                        "type": "string",
                        "description": "Unit for the sensor reading."
                    },
                    "metric": {
                        "type": "string",
                        "description": "Sensor metric name, constrained by plugin config."
                    },
                    "memo_prefix": {
                        "type": "string",
                        "description": "Optional memo prefix; defaults to ZCDEPIN."
                    }
                },
                "required": ["device_id", "reading", "unit", "metric"]
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
            match attest::execute(&args_json, &config, &WakiHttp, now_unix) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built attestation",
                        Some(format!(
                            "{{\"nonce_account\":{},\"durability\":{}}}",
                            json_string(&output.nonce_account),
                            json_string(output.durability)
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
                        "attestation failed",
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
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    fn json_string(value: &str) -> String {
        serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
    }

    export!(DepinAttest);
}
