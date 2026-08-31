//! A ZeroClaw WIT tool plugin: `kiosk_attest`.
//!
//! Builds an UNSIGNED, hash-chained, durable-nonce memo attestation transaction
//! for the ProofKiosk. Custody tier T1: holds no key, signs nothing. The
//! transaction contains only the Memo and System (advance-nonce) programs, so
//! it is structurally incapable of moving funds. RPC endpoint, device id, and
//! the nonce account/authority come from operator config, never the model.
//!
//! The pure core lives in [`attest`] (host-tested with mocked RPC); the wasm
//! component reuses it through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod attest;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::attest::{execute_attest, AttestArgs, AttestConfig};
    use kiosk_core::rpc::WakiTransport;
    use kiosk_core::shape;

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct KioskAttest;

    const PLUGIN_NAME: &str = "kiosk-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "kiosk_attest";

    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct ExecuteArgs {
        kind: Option<String>,
        metric: Option<String>,
        value: Option<f64>,
        ts: Option<u64>,
        event: Option<String>,
        payment_sig: Option<String>,
        item: Option<String>,
        #[serde(rename = "__config")]
        config: HashMap<String, String>,
    }

    impl PluginInfo for KioskAttest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for KioskAttest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Record a tamper-evident, hash-chained attestation of a sensor reading or a \
             sale event on Solana. Pass kind=\"reading\" with metric and value (the metric \
             must be in the operator's allowlist and the value within its bounds), or \
             kind=\"event\" with an event label (optionally item and payment_sig). Returns an \
             UNSIGNED durable-nonce transaction (base64) for the operator's signer to submit — \
             this tool never signs and cannot move funds. Device id, nonce account/authority, \
             and RPC endpoint are fixed by operator config and cannot be set here. Before \
             recording, state what you are attesting (the metric and value, or the event) so it \
             can be previewed."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["reading", "event"], "description": "Attestation kind. Default `reading`." },
                    "metric": { "type": "string", "description": "Reading: metric name (must be in the operator allowlist), e.g. `temp_c`." },
                    "value": { "type": "number", "description": "Reading: numeric value, bounded by the operator's allowlist." },
                    "ts": { "type": "integer", "description": "Unix seconds for the record; defaults to now." },
                    "event": { "type": "string", "description": "Event: a short event label, e.g. `sale`." },
                    "payment_sig": { "type": "string", "description": "Event: the payment signature this event attests to." },
                    "item": { "type": "string", "description": "Event: the item id involved." }
                },
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            emit(PluginAction::Start, None, "attestation requested");

            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        Some(PluginOutcome::Failure),
                        "invalid arguments",
                    );
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };
            if let Err(e) = strict_check(&args) {
                emit(
                    PluginAction::Reject,
                    Some(PluginOutcome::Failure),
                    "unknown field rejected",
                );
                return Ok(fail(e));
            }

            let cfg = match AttestConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        Some(PluginOutcome::Failure),
                        "config rejected",
                    );
                    return Ok(fail(e.to_string()));
                }
            };
            let attest_args = AttestArgs {
                kind: parsed.kind,
                metric: parsed.metric,
                value: parsed.value,
                ts: parsed.ts,
                event: parsed.event,
                payment_sig: parsed.payment_sig,
                item: parsed.item,
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let transport = WakiTransport::new(cfg.rpc_url.clone());

            match execute_attest(&attest_args, &cfg, transport, now) {
                Ok(out) => {
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "attestation built",
                    );
                    // Summary is token-budgeted; the base64 tx is bounded and small.
                    let output = shape::clamp(
                        &format!("{}\nunsigned_tx_base64={}", out.summary, out.tx_base64),
                        shape::DEFAULT_BUDGET_TOKENS,
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        Some(PluginOutcome::Failure),
                        "attestation failed",
                    );
                    Ok(fail(e.to_string()))
                }
            }
        }
    }

    /// Reject any model-supplied key outside the declared schema.
    fn strict_check(raw: &str) -> Result<(), String> {
        const ALLOWED: [&str; 8] = [
            "kind",
            "metric",
            "value",
            "ts",
            "event",
            "payment_sig",
            "item",
            "__config",
        ];
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("invalid arguments: {e}"))?;
        if let Some(obj) = v.as_object() {
            for key in obj.keys() {
                if !ALLOWED.contains(&key.as_str()) {
                    return Err(format!("unknown argument `{key}` rejected (fail closed)"));
                }
            }
        }
        Ok(())
    }

    fn fail(message: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        }
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "kiosk_attest::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(KioskAttest);
}
