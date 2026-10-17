//! A ZeroClaw WIT tool plugin: `kamino_guard`.
//!
//! Watches a Kamino Lend obligation and warns before it gets liquidated:
//! tiered health-factor warnings, a liquidation-price forecast, ranked
//! remedies, and unsigned repay/deposit transactions the operator signs and
//! submits themselves.
//!
//! The pure guard logic lives behind the [`guard`] seam
//! ([`guard::Transport`], [`guard::run`]) with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim, backed by a
//! `waki` (wasi:http) transport.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod args;
pub mod config;
pub mod guard;
pub mod health;
pub mod kamino;
pub mod net;
pub mod remedy;
pub mod report;
pub mod rescue;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::guard::{self, HttpRequest, HttpResponse, Method, Transport};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct KaminoGuard;

    const PLUGIN_NAME: &str = "liquidation-guard";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "kamino_guard";

    impl PluginInfo for KaminoGuard {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for KaminoGuard {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Kamino Lend health guard: tiered liquidation warnings, \
             liquidation-price forecast, ranked remedies, and unsigned \
             repay/deposit transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["check", "portfolio", "rescue", "deposit"],
                        "description": "Which guard operation to run."
                    },
                    "wallet": {
                        "type": "string",
                        "description": "Wallet public key to inspect."
                    },
                    "market": {
                        "type": "string",
                        "description": "Kamino Lend market to scope the lookup to."
                    },
                    "obligation": {
                        "type": "string",
                        "description": "Specific obligation account to inspect."
                    },
                    "repay_ui_amount": {
                        "type": "number",
                        "description": "UI amount to repay when action is \"rescue\"."
                    },
                    "deposit_ui_amount": {
                        "type": "number",
                        "description": "UI amount to deposit when action is \"deposit\"."
                    },
                    "prev_snapshot": {
                        "type": "string",
                        "description": "Previous snapshot to diff against, if any."
                    }
                },
                "required": ["action"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // Log the action name only — never args or payload content, which
            // may carry wallet addresses or hostile payload strings.
            //
            // Whitelisted against the four known actions rather than echoed.
            // This runs *before* `args::parse_call` validates anything, so an
            // unrecognised value is arbitrary model-controlled text of
            // arbitrary length — and it would otherwise reach the host's logs
            // verbatim on all three records below.
            let action = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| v.get("action").and_then(|a| a.as_str()).map(str::to_string))
                .filter(|a| matches!(a.as_str(), "check" | "portfolio" | "rescue" | "deposit"))
                .unwrap_or_else(|| "invalid".to_string());
            emit(
                LogLevel::Info,
                PluginAction::Start,
                None,
                &format!("kamino_guard execute: action={action}"),
            );

            let mut transport = WakiTransport;
            let out = guard::run(&args, &mut transport);

            if out.success {
                emit(
                    LogLevel::Info,
                    PluginAction::Complete,
                    Some(PluginOutcome::Success),
                    &format!("kamino_guard {action} completed"),
                );
                Ok(ToolResult {
                    success: true,
                    output: out.text,
                    error: None,
                })
            } else {
                emit(
                    LogLevel::Warn,
                    PluginAction::Fail,
                    Some(PluginOutcome::Failure),
                    &format!("kamino_guard {action} failed"),
                );
                Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(out.text),
                })
            }
        }
    }

    fn emit(level: LogLevel, action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "liquidation_guard::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    /// `waki`-backed (wasi:http) implementation of [`Transport`], used by the
    /// wasm component. Forwards the response body, status, and the `date`
    /// response header verbatim.
    struct WakiTransport;

    impl Transport for WakiTransport {
        fn fetch(&mut self, req: &HttpRequest) -> Result<HttpResponse, String> {
            let client = waki::Client::new();
            let builder = match req.method {
                Method::Get => client.get(&req.url),
                Method::Post => client.post(&req.url),
            };
            let builder = match &req.body {
                Some(body) => builder
                    .header("Content-Type", "application/json")
                    .body(body.clone()),
                None => builder,
            };

            let resp = builder.send().map_err(|e| e.to_string())?;
            let status = resp.status_code();
            let date_header = resp
                .header("date")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body_bytes = resp.body().map_err(|e| e.to_string())?;
            let body = String::from_utf8(body_bytes).map_err(|e| e.to_string())?;

            Ok(HttpResponse {
                status,
                body,
                date_header,
            })
        }
    }

    export!(KaminoGuard);
}
