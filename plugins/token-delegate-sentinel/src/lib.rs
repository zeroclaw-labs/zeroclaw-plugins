//! ZeroClaw tool plugin for read-only Solana token-delegate audits.
//!
//! The security-sensitive parsing and classification logic is host-testable.
//! Only this thin component shim depends on WIT and `wasi:http`.

pub mod address;
pub mod audit;
pub mod config;
pub mod rpc;
pub mod token_account;

#[cfg(target_family = "wasm")]
mod component {
    use std::time::Duration;

    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::audit::run_audit;
    use crate::config::{parse_invocation, SentinelConfig};
    use crate::rpc::{HttpTransport, TransportError};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-delegate-sentinel";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_delegate_audit";

    struct WakiTransport;

    impl HttpTransport for WakiTransport {
        fn post_json(
            &self,
            url: &str,
            request: &str,
            max_bytes: usize,
        ) -> Result<String, TransportError> {
            let response = waki::Client::new()
                .post(url)
                .header("content-type", "application/json")
                .body(request)
                .connect_timeout(Duration::from_secs(10))
                .send()
                .map_err(|_| TransportError::Unavailable)?;
            if !(200..300).contains(&response.status_code()) {
                return Err(TransportError::Unavailable);
            }

            let mut bytes = Vec::new();
            loop {
                let remaining = max_bytes.saturating_sub(bytes.len());
                let chunk = response
                    .chunk(remaining.saturating_add(1) as u64)
                    .map_err(|_| TransportError::InvalidResponse)?;
                let Some(chunk) = chunk else {
                    break;
                };
                bytes.extend_from_slice(&chunk);
                if bytes.len() > max_bytes {
                    return Err(TransportError::ResponseTooLarge);
                }
            }
            String::from_utf8(bytes).map_err(|_| TransportError::InvalidResponse)
        }
    }

    struct TokenDelegateSentinel;

    impl PluginInfo for TokenDelegateSentinel {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenDelegateSentinel {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read-only audit of SPL Token and Token-2022 account delegate fields and allowance exposure. Returns deterministic, chat-ready Markdown; preserve its sections and links verbatim. Never creates, signs, or submits a transaction."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed = match parse_invocation(&args) {
                Ok(value) => value,
                Err(_) => return failure("INVALID_ARGUMENTS"),
            };
            let config = match SentinelConfig::from_section(&parsed.config) {
                Ok(config) => config,
                Err(error) => return failure(error.code()),
            };

            match run_audit(&config, &WakiTransport) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        report.finding_count(),
                        Some((report.snapshot_slots.minimum, report.snapshot_slots.maximum)),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report.render(),
                        error: None,
                    })
                }
                Err(error) => failure(error.code()),
            }
        }
    }

    fn failure(code: &str) -> Result<ToolResult, String> {
        emit(PluginAction::Fail, PluginOutcome::Failure, 0, None);
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(code.to_string()),
        })
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        findings: usize,
        slots: Option<(u64, u64)>,
    ) {
        let attrs = match slots {
            Some((minimum, maximum)) => {
                format!("{{\"findings\":{findings},\"slot_min\":{minimum},\"slot_max\":{maximum}}}")
            }
            None => format!("{{\"findings\":{findings}}}"),
        };
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_delegate_sentinel::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(attrs),
                message: if matches!(action, PluginAction::Complete) {
                    "token delegate audit completed".to_string()
                } else {
                    "token delegate audit failed".to_string()
                },
            },
        );
    }

    export!(TokenDelegateSentinel);
}
