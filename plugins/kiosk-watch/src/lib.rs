//! A ZeroClaw WIT tool plugin: `kiosk_watch`.
//!
//! Verifies a ProofKiosk Solana Pay payment on-chain before actuation, and
//! checks the device attestation heartbeat. Custody tier T0: it holds no key
//! and signs nothing — read-only JSON-RPC via the operator-configured endpoint.
//! The recipient, mint, and RPC URL come from the operator's jailed config
//! section, never from the model.
//!
//! The pure verification core lives in [`watch`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test` (RPC mocked); the
//! wasm component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod watch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::watch::{
        verify_heartbeat, verify_payment, Heartbeat, Verdict, WatchArgs, WatchConfig, WatchError,
    };
    use kiosk_core::rpc::WakiTransport;

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct KioskWatch;

    const PLUGIN_NAME: &str = "kiosk-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "kiosk_watch";

    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct ExecuteArgs {
        mode: Option<String>,
        reference: Option<String>,
        expected_amount: Option<String>,
        window_s: Option<u64>,
        device_address: Option<String>,
        max_silence_s: Option<u64>,
        #[serde(rename = "__config")]
        config: HashMap<String, String>,
    }

    impl PluginInfo for KioskWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for KioskWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check whether a kiosk payment has been received on-chain before delivering an item. \
             Pass the `reference` and `expected_amount` from the charge; returns success=true ONLY \
             when a Solana payment of that exact USDC amount to the operator's address has landed \
             at the configured finality — deliver only then. success=false means pending, expired, \
             or a mismatch (do not deliver). Set mode=\"heartbeat\" with device_address and \
             max_silence_s to instead check the device's attestation freshness. The recipient, \
             mint, and RPC endpoint are fixed by operator config and cannot be set here. State the \
             result plainly (paid / still pending / mismatch) before any downstream action such as \
             releasing an item."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["payment", "heartbeat"],
                        "description": "Verification mode. Default `payment`."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Payment mode: the Solana Pay reference pubkey from the charge."
                    },
                    "expected_amount": {
                        "type": "string",
                        "description": "Payment mode: expected USDC amount as a decimal string, e.g. \"1.5\"."
                    },
                    "window_s": {
                        "type": "integer",
                        "description": "Payment mode: acceptance window in seconds; an older matching payment is Expired."
                    },
                    "device_address": {
                        "type": "string",
                        "description": "Heartbeat mode: the device attestation address to scan."
                    },
                    "max_silence_s": {
                        "type": "integer",
                        "description": "Heartbeat mode: max seconds since the newest attestation before it is Stale."
                    }
                },
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            emit(PluginAction::Start, None, "verify requested");

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
            // Strict allowlist over the raw model-facing keys: smuggled config
            // keys (rpc_url, merchant_address, …) fail closed even though
            // `__config` rides in the same JSON object.
            if let Err(e) = strict_check(&args) {
                emit(
                    PluginAction::Reject,
                    Some(PluginOutcome::Failure),
                    "unknown field rejected",
                );
                return Ok(fail(e));
            }

            let cfg = match WatchConfig::from_section(&parsed.config) {
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
            let watch_args = WatchArgs {
                mode: parsed.mode.clone(),
                reference: parsed.reference,
                expected_amount: parsed.expected_amount,
                window_s: parsed.window_s,
                device_address: parsed.device_address,
                max_silence_s: parsed.max_silence_s,
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let transport = WakiTransport::new(cfg.rpc_url.clone());

            let heartbeat_mode = parsed.mode.as_deref() == Some("heartbeat");
            if heartbeat_mode {
                match verify_heartbeat(&watch_args, &cfg, transport, now) {
                    Ok(h) => Ok(finish_heartbeat(h)),
                    Err(e) => Ok(fail_or_negative(e)),
                }
            } else {
                match verify_payment(&watch_args, &cfg, transport, now) {
                    Ok(v) => Ok(finish_payment(v)),
                    Err(e) => Ok(fail_or_negative(e)),
                }
            }
        }
    }

    /// Map a payment verdict to a ToolResult. success==true ONLY for a verified
    /// payment — the single, unambiguous condition the actuation SOP gates on.
    fn finish_payment(v: Verdict) -> ToolResult {
        let paid = v.is_paid();
        let outcome = if paid {
            PluginOutcome::Success
        } else {
            PluginOutcome::Failure
        };
        emit(
            PluginAction::Complete,
            Some(outcome),
            if paid { "paid" } else { "not paid" },
        );
        ToolResult {
            success: paid,
            output: v.summary(),
            error: None,
        }
    }

    fn finish_heartbeat(h: Heartbeat) -> ToolResult {
        let live = h.is_live();
        let outcome = if live {
            PluginOutcome::Success
        } else {
            PluginOutcome::Failure
        };
        emit(
            PluginAction::Complete,
            Some(outcome),
            if live { "live" } else { "not live" },
        );
        ToolResult {
            success: live,
            output: h.summary(),
            error: None,
        }
    }

    /// Bad input is a caller error; an RPC/decode failure is a plugin-level
    /// failure. Either way success=false, so the relay never fires on a failure.
    fn fail_or_negative(e: WatchError) -> ToolResult {
        emit(
            PluginAction::Fail,
            Some(PluginOutcome::Failure),
            "verification failed",
        );
        fail(e.to_string())
    }

    /// Reject any model-supplied key outside the declared schema.
    fn strict_check(raw: &str) -> Result<(), String> {
        const ALLOWED: [&str; 7] = [
            "mode",
            "reference",
            "expected_amount",
            "window_s",
            "device_address",
            "max_silence_s",
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
                function_name: "kiosk_watch::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(KioskWatch);
}
