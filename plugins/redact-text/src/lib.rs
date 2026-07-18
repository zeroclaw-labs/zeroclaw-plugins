//! A ZeroClaw WIT tool plugin: `redact`.
//!
//! Scrubs secrets and PII out of text before it reaches a log, a channel, or a
//! model: email addresses, bearer/API tokens, and any literal patterns the
//! operator configures. The redaction policy is read from this plugin's own
//! jailed config section (`config_read` permission), making it the canonical
//! example of a config-driven tool plugin.
//!
//! The pure redaction core lives in [`redact`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod redact;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::redact::{redact, RedactConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct RedactText;

    const PLUGIN_NAME: &str = "redact-text";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "redact";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        text: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for RedactText {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for RedactText {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Redact secrets and PII from text before it reaches a log, channel, or model. \
             Masks emails, bearer/API tokens, and any operator-configured literal patterns. \
             The redaction policy is read from this plugin's own jailed config section."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to redact."
                    }
                },
                "required": ["text"]
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
                        None,
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = RedactConfig::from_section(&parsed.config);
            let (output, count) = redact(&parsed.text, &cfg);

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "redacted input",
                Some(count),
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        redactions: Option<usize>,
    ) {
        let attrs = redactions.map(|n| format!("{{\"redactions\":{n}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "redact_text::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(RedactText);
}
