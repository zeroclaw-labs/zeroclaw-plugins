//! ogige — ZeroClaw WIT tool plugin: Solana transaction safety gate.
//!
//! Decodes a base64 Solana transaction, narrates what it does in plain English,
//! classifies danger primitives, and returns a structured ALLOW / HOLD / REJECT
//! verdict. Never signs or sends — custody tier T0/T1 gate only.
//!
//! Pure logic lives in [`guard`] / [`core`] (host-testable). The wasm component
//! reuses the exact same path through the thin shim below.
//!
//! Build: rustup target add wasm32-wasip2
//! cargo build --target wasm32-wasip2 --release

pub mod core;
pub mod guard;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::guard::{analyze, report_json, GuardConfig, Verdict};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaGuard;

    const PLUGIN_NAME: &str = "solana-guard";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_guard";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        transaction: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaGuard {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaGuard {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Solana transaction safety gate. Pass a base64-encoded transaction; \
             returns a human-readable narration plus a structured ALLOW / HOLD / REJECT \
             verdict. Never signs or broadcasts — use before approving any on-chain action."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "transaction": {
                        "type": "string",
                        "description": "Base64-encoded Solana transaction (legacy or v0)."
                    }
                },
                "required": ["transaction"]
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

            let cfg = GuardConfig::from_section(&parsed.config);
            match analyze(&parsed.transaction, &cfg) {
                Ok(report) => {
                    let action = match report.verdict {
                        Verdict::Allow => PluginAction::Approve,
                        Verdict::Hold => PluginAction::Defer,
                        Verdict::Reject => PluginAction::Reject,
                    };
                    emit(
                        action,
                        PluginOutcome::Success,
                        &report.summary,
                        Some(report.verdict),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report_json(&report),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &e, None);
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, verdict: Option<Verdict>) {
        let attrs = verdict.map(|v| serde_json::json!({ "verdict": v }).to_string());
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_guard::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaGuard);
}
