//! A ZeroClaw WIT tool plugin: `depin_attest`.
//!
//! Packages an edge-node sensor/health reading into an unsigned, durable-
//! nonce Solana transaction targeting the well-known SPL Memo program. This
//! plugin never holds a signing key and never submits anything itself
//! (custody tier T1; see README.md) -- it only ever returns an unsigned
//! transaction for a human or the host to sign.
//!
//! The pure core lives in [`depin_attest`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod depin_attest;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::depin_attest::{self, AttestConfig, AttestParams};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    use zeroclaw_solana_core::crypto::blockhash_from_base58;

    struct DepinAttest;

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        nonce_value: String,
        node_id: String,
        reading: String,
        uptime_seconds: u64,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
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
            depin_attest::name().to_string()
        }

        fn description() -> String {
            depin_attest::description().to_string()
        }

        fn parameters_schema() -> String {
            depin_attest::parameters_schema().to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let cfg = match AttestConfig::from_section(&parsed.config) {
                Ok(cfg) => cfg,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid config");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            let nonce_value = match blockhash_from_base58(&parsed.nonce_value) {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid nonce_value",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            let params = AttestParams {
                nonce_value,
                node_id: parsed.node_id,
                reading: parsed.reading,
                uptime_seconds: parsed.uptime_seconds,
            };

            match depin_attest::attest(params, &cfg) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "attestation tx built",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &e);
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(DepinAttest);
}
