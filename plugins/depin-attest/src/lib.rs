//! A ZeroClaw WIT tool plugin: `depin_attest`.
//!
//! Turns a sensor reading from a DePIN device (a Raspberry Pi running
//! ZeroClaw, its GPIO/I2C sensors read by the host's hardware tools) into an
//! **unsigned** Solana transaction carrying a hash-chained attestation memo.
//! A human — or the host's approval gate plus a wallet — signs and submits.
//! The chain of memos on the device address is publicly verifiable:
//! sequence numbers are monotonic and each attestation commits to the
//! on-chain signature of the previous one.
//!
//! Custody tier: **T1 (build, never sign)**. The plugin holds no keys and the
//! transaction it builds carries a single memo instruction — no transfer is
//! even expressible. Worst case under total prompt injection: a bogus reading
//! is *proposed*, the human reads it in the approval gate, and even a
//! rubber-stamped approval costs only the network fee.
//!
//! The pure logic lives in [`att`], [`tx`], and [`rpc`] with no wasm
//! dependency, so it compiles and tests on the host with a plain `cargo test`;
//! the wasm component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod att;
pub mod rpc;
pub mod tx;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::Value;

    use crate::att;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DepinAttest;

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_attest";

    fn post_json(url: &str, body: &Value) -> Result<String, String> {
        let resp = waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?;
        let bytes = resp.body().map_err(|e| format!("RPC body read failed: {e}"))?;
        String::from_utf8(bytes).map_err(|e| format!("RPC body is not UTF-8: {e}"))
    }

    fn log(level: LogLevel, action: PluginAction, outcome: PluginOutcome, msg: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: msg.to_string(),
            },
        );
    }

    fn now_unix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
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
            "Build an UNSIGNED Solana attestation transaction for a sensor reading \
             from this device (temperature, humidity, uptime — whatever the operator \
             allowlisted in config). Returns a base64 transaction carrying a \
             hash-chained memo, plus a summary for the approval gate. It cannot \
             sign, cannot transfer funds, and refuses readings outside the \
             operator's configured bounds. Use after taking a real hardware reading."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "metric": {
                        "type": "string",
                        "description": "Metric name — must be on the operator's configured allowlist (e.g. temp_c)"
                    },
                    "value": {
                        "type": "number",
                        "description": "The sensor reading, within the operator's configured bounds"
                    },
                    "unit": {
                        "type": "string",
                        "description": "Optional unit — if given, must match the configured unit for the metric"
                    }
                },
                "required": ["metric", "value"]
            })
            .to_string()
        }

        fn execute(args_json: String) -> Result<ToolResult, String> {
            log(
                LogLevel::Info,
                PluginAction::Start,
                PluginOutcome::Success,
                "depin_attest invoked",
            );
            let mut post = |url: &str, body: &Value| post_json(url, body);
            match att::run(&args_json, &mut post, now_unix()) {
                Ok(out) => {
                    log(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "unsigned attestation built",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: out,
                        error: None,
                    })
                }
                Err(e) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &e,
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    export!(DepinAttest);
}
