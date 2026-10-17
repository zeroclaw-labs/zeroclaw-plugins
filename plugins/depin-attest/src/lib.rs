//! A ZeroClaw WIT **tool plugin**: `depin-attest`.
//!
//! Palinurus Track C (DePIN) — attests a physical sensor reading to Solana via
//! the Solana Attestation Service (SAS `create_attestation`) with a durable
//! nonce (the blockhash-expiry fix). T1 default (unsigned — human/Squads
//! multisig signs) + T2 opt-in (scoped session key signs + submits with
//! program allowlist + caps + fail-closed injection test).
//!
//! The pure attestation core lives in [`depin_attest`] with no wasm dependency,
//! so it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod depin_attest;

// Host-only demo driver (`--features demo`): a reqwest-backed Rpc impl that
// runs execute_t1 against a real devnet durable-nonce account on camera
// (chunk 6 of the recording guide). Excluded from the wasm component build.
#[cfg(feature = "demo")]
pub mod demo_rpc;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DepinAttest;

    thread_local! {
        static DAILY_CAP: std::cell::RefCell<crate::depin_attest::DailyCapState> =
            std::cell::RefCell::new(crate::depin_attest::DailyCapState::default());
    }

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_attest";

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
            "Attest a physical sensor reading to Solana as a durable-nonce unsigned \
             transaction (SAS create_attestation, memo fallback). The agent proposes; \
             a human or Squads multisig signs. The attestation PDA is cryptographically \
             bound to the reading. Returns the attestation PDA, tx bytes (base64), and \
             a devnet explorer URL in ~200 tokens."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "sensor_id": {
                        "type": "string",
                        "description": "Identifier of the physical sensor (e.g. 'bme280-1')."
                    },
                    "value": {
                        "type": "number",
                        "description": "The numeric reading."
                    },
                    "unit": {
                        "type": "string",
                        "description": "Unit of the reading (e.g. 'celsius', 'hPa', '%RH')."
                    },
                    "timestamp": {
                        "type": "integer",
                        "description": "Unix seconds when the reading was taken."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional human-readable note appended as a memo instruction."
                    }
                },
                "required": ["sensor_id", "value", "unit", "timestamp"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            use crate::depin_attest::{execute_entry, AttestConfig, AttestError, SensorReading};
            use std::collections::HashMap;

            #[derive(serde::Deserialize)]
            struct ExecuteArgs {
                sensor_id: String,
                value: f64,
                unit: String,
                timestamp: i64,
                #[serde(default)]
                memo: Option<String>,
                #[serde(rename = "__config", default)]
                config: HashMap<String, String>,
            }

            emit(PluginAction::Start, None, "execute received sensor reading");

            // 1. Parse args.
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, Some(PluginOutcome::Failure), "invalid arguments");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            // 2. Build config (fail closed on missing/malformed).
            let cfg = match AttestConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(AttestError::Config(msg)) => {
                    emit(PluginAction::Fail, Some(PluginOutcome::Failure), "config error");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("config error: {msg}")),
                    });
                }
                Err(e) => {
                    emit(PluginAction::Fail, Some(PluginOutcome::Failure), "config error");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("config error: {e:?}")),
                    });
                }
            };

            // 3. Build the reading.
            let reading = SensorReading {
                sensor_id: parsed.sensor_id,
                value: parsed.value,
                unit: parsed.unit,
                timestamp: parsed.timestamp,
            };

            // 4. Create the RPC client (waki, wasm-only).
            let rpc = palinurus_core::WakiRpc::new(
                cfg.rpc_endpoint.clone(),
                cfg.rpc_api_key.clone(),
            );

            // 5. Execute (T1 or T2 based on custody_mode).
            let memo = parsed.memo.as_deref();
            let result = DAILY_CAP.with(|cap| {
                let mut cap = cap.borrow_mut();
                execute_entry(&reading, memo, &cfg, &rpc, Some(&mut cap))
            });
            match result {
                Ok(out) => {
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "attestation built (unsigned, durable-nonce)",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: out.summary,
                        error: None,
                    })
                }
                Err(e) => {
                    let msg = format!("{e:?}");
                    emit(PluginAction::Fail, Some(PluginOutcome::Failure), "attestation failed");
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(msg),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(DepinAttest);
}