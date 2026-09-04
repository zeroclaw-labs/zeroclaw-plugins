//! ZeroClaw WIT tool plugin: `approval_recheck` (part of the Aval suite).
//!
//! Read-only (T0) verification of a pending unsigned transaction at the
//! moment of approval: decodes the bytes, re-fetches the accounts they touch,
//! and answers the only question that matters at signing time — is what the
//! human is about to sign still exactly what they think it is?
//!
//! Pure logic in [`recheck`]; this file is the wasm shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod core;
pub mod recheck;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::core::rpc::HttpPost;
    use crate::recheck::{parameters_schema, recheck, RecheckArgs};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct ApprovalRecheck;

    const PLUGIN_NAME: &str = "approval-recheck";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "approval_recheck";

    struct WakiHttp;

    impl HttpPost for WakiHttp {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(url)
                .headers([("Content-Type", "application/json")])
                .body(body.as_bytes())
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?;
            let status = resp.status_code();
            let bytes = resp
                .body()
                .map_err(|e| format!("rpc response unreadable: {e}"))?;
            if !(200..300).contains(&status) {
                return Err(format!("rpc returned HTTP {status}"));
            }
            String::from_utf8(bytes).map_err(|_| "rpc response is not UTF-8".to_string())
        }
    }

    impl PluginInfo for ApprovalRecheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for ApprovalRecheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Verify a pending unsigned Solana transaction at the moment of approval: is the \
             durable nonce still fresh, do balances still hold, and what exactly would a \
             signature authorize? Decodes the transaction bytes themselves — never trusts \
             the conversation. Read-only; run this before every signature."
                .to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema().to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: RecheckArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };

            match recheck(&WakiHttp, &parsed) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        report.verdict.as_str(),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "verdict": report.verdict.as_str(),
                            "headline": report.headline,
                            "actions": report.actions,
                            "warnings": report.warnings,
                        })
                        .to_string(),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "recheck failed");
                    Ok(fail(e))
                }
            }
        }
    }

    fn fail(error: String) -> ToolResult {
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
                function_name: "approval_recheck::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(ApprovalRecheck);
}
