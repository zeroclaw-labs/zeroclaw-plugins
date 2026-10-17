//! ZeroClaw WIT tool plugin: `nonce_status`.
//!
//! Read-only inspection of the operator's durable nonce account: current
//! nonce, authority, rent state and whether `spl_transfer_build` can use it.
//! One RPC call; holds no keys, moves nothing.
//!
//! All logic lives in [`core`]; this file is the thin
//! `#[cfg(target_family = "wasm")]` component shim plus the waki transport.
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

    use crate::core::{run, Lookups};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct NonceStatus;

    struct WakiRpc {
        rpc_url: String,
    }

    impl Lookups for WakiRpc {
        fn rpc(&mut self, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(&self.rpc_url)
                .header("Content-Type", "application/json")
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc transport: {e}"))?;
            let status = resp.status_code();
            let bytes = resp.body().map_err(|e| format!("rpc body: {e}"))?;
            if status != 200 {
                return Err(format!("rpc http status {status}"));
            }
            String::from_utf8(bytes).map_err(|e| format!("rpc utf8: {e}"))
        }
    }

    impl PluginInfo for NonceStatus {
        fn plugin_name() -> String {
            env!("CARGO_PKG_NAME").to_string()
        }
        fn plugin_version() -> String {
            env!("CARGO_PKG_VERSION").to_string()
        }
    }

    impl Tool for NonceStatus {
        fn name() -> String {
            "nonce_status".to_string()
        }

        fn description() -> String {
            "Inspect the operator's durable nonce account: current nonce value, authority \
             and rent status, and whether spl_transfer_build can use it right now. \
             Read-only, one RPC call. Use when a durable-nonce transfer fails or before \
             issuing payment requests that will wait in an approval queue."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "account": { "type": "string", "description": "Optional base58 nonce account to inspect. Defaults to the operator's configured nonce_account." }
                },
                "required": []
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            log_record(
                LogLevel::Info,
                &PluginEvent {
                    function_name: "nonce_status::tool::execute".into(),
                    action: PluginAction::Query,
                    outcome: None,
                    duration_ms: None,
                    attrs: None,
                    message: "inspecting nonce account".into(),
                },
            );
            let rpc_url = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| {
                    v.get("__config")?
                        .get("rpc_url")?
                        .as_str()
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let mut transport = WakiRpc { rpc_url };
            match run(&args, &mut transport) {
                Ok(output) => {
                    log_record(
                        LogLevel::Info,
                        &PluginEvent {
                            function_name: "nonce_status::tool::execute".into(),
                            action: PluginAction::Complete,
                            outcome: Some(PluginOutcome::Success),
                            duration_ms: None,
                            attrs: None,
                            message: "status complete".into(),
                        },
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    log_record(
                        LogLevel::Warn,
                        &PluginEvent {
                            function_name: "nonce_status::tool::execute".into(),
                            action: PluginAction::Fail,
                            outcome: Some(PluginOutcome::Failure),
                            duration_ms: None,
                            attrs: None,
                            message: format!("status failed: {e}"),
                        },
                    );
                    Ok(ToolResult {
                        success: false,
                        output: format!("{e}"),
                        error: Some(format!("{e}")),
                    })
                }
            }
        }
    }

    export!(NonceStatus);
}
