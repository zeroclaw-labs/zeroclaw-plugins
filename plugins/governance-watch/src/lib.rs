//! A read-only ZeroClaw tool for watching Realms governance proposals.
//!
//! The policy and response parsing live in [`governance_watch`]. The wasm-only
//! component below is deliberately thin: it injects jailed plugin config and
//! performs one `wasi:http` request through `waki`.

pub mod governance_watch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::governance_watch::{watch, HttpClient, WatchArgs, WatchConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::Value;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "governance-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "governance_watch";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        realm: String,
        #[serde(default)]
        states: Vec<String>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        since_unix: Option<i64>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct WakiHttp;

    impl HttpClient for WakiHttp {
        fn get_json(&mut self, url: &str) -> Result<Value, String> {
            waki::Client::new()
                .get(url)
                .send()
                .map_err(|e| format!("Realms request failed: {e}"))?
                .json::<Value>()
                .map_err(|e| format!("Realms returned invalid JSON: {e}"))
        }
    }

    struct GovernanceWatch;

    impl PluginInfo for GovernanceWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for GovernanceWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read Realms DAO proposals and return bounded, structured status and vote summaries. \
             Proposal text is treated as untrusted data and description links are never fetched."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "realm": {
                        "type": "string",
                        "description": "The Realms DAO public key."
                    },
                    "states": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "draft", "signing_off", "voting", "succeeded",
                                "executing", "completed", "cancelled", "defeated", "vetoed"
                            ]
                        },
                        "description": "Proposal states to include. Uses operator defaults when omitted."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 20,
                        "description": "Maximum proposals to return, also capped by operator config."
                    },
                    "since_unix": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Only include proposals updated at or after this Unix timestamp."
                    }
                },
                "required": ["realm"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return Ok(failure(format!("invalid arguments: {error}"))),
            };

            let config = match WatchConfig::from_section(&parsed.config) {
                Ok(config) => config,
                Err(error) => return Ok(failure(error)),
            };
            let watch_args = WatchArgs {
                realm: parsed.realm,
                states: parsed.states,
                limit: parsed.limit,
                since_unix: parsed.since_unix,
            };

            match watch(&mut WakiHttp, &watch_args, &config) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "returned governance proposal summaries",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(error) => Ok(failure(error)),
            }
        }
    }

    fn failure(error: String) -> ToolResult {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "governance watch request rejected",
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "governance_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(GovernanceWatch);
}
