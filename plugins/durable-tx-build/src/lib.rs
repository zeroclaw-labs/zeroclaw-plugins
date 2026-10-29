//! ZeroClaw WIT tool plugin: `durable_tx_build` (part of the Aval suite).
//!
//! Builds an *unsigned* Solana transfer anchored to a durable nonce account,
//! so the transaction stays valid while it waits in a human approval queue —
//! minutes, hours, or days. The plugin holds no key material at any point
//! (custody tier T1): the human authority signs in their own wallet.
//!
//! All logic lives in [`build`] with no wasm dependency; this file is the
//! `#[cfg(target_family = "wasm")]` shim required by the plugin contract.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod build;
pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::build::{build_transfer, parameters_schema, BuildArgs};
    use crate::core::rpc::HttpPost;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DurableTxBuild;

    const PLUGIN_NAME: &str = "durable-tx-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "durable_tx_build";

    /// Outbound HTTPS through the host's wasi:http; TLS is host-side.
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

    impl PluginInfo for DurableTxBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for DurableTxBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an unsigned Solana transfer (SOL or SPL token) anchored to a durable \
             nonce account, so it never expires while a human decides whether to sign. \
             Enforces the operator's mint allowlist and per-transaction cap; holds no keys. \
             Returns a base64 transaction plus a plain-language summary for the approval prompt."
                .to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema().to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: BuildArgs = match serde_json::from_str(&args) {
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

            match build_transfer(&WakiHttp, &parsed) {
                Ok(built) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "transfer built",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::json!({
                            "summary": built.summary,
                            "transaction_base64": built.transaction_base64,
                            "expires": "never (durable nonce)",
                        })
                        .to_string(),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "refused or failed",
                    );
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
                function_name: "durable_tx_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(DurableTxBuild);
}
