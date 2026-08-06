//! A ZeroClaw WIT tool plugin: `solana-tx-authorize`.
//!
//! Pre-sign Solana transaction authorization. The agent (or a human) supplies
//! an unsigned transaction as base64; the plugin decodes it, simulates it,
//! compares it to the declared intent, enforces the operator's spend policy
//! from its own jailed config section (`config_read`), and returns ALLOW,
//! REVIEW, DENY or UNKNOWN with machine reason codes. It holds no keys, signs
//! nothing, and keeps no state (T0).
//!
//! The pure authorization core lives in [`authorize`] with no wasm dependency,
//! so it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod authorize;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::authorize;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use safe_hands_core::rpc::{RpcTransport, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaTxAuthorize;

    const PLUGIN_NAME: &str = "solana-tx-authorize";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana-tx-authorize";

    impl PluginInfo for SolanaTxAuthorize {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaTxAuthorize {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "REQUIRED before signing, approving, or relaying any Solana transaction or transfer intent. \
             Decodes it, simulates it, compares it to the declared intent, and enforces the operator's \
             spend policy (caps, mint allowlist, blocked addresses, durable-nonce detection). \
             Returns ALLOW, REVIEW, DENY or UNKNOWN with reasons and a next_action. Never skip for money \
             movement. Do NOT call for read-only questions (prices, balances, history) — this tool is \
             only for value-moving actions."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "transaction_base64": {
                        "type": "string",
                        "description": "The unsigned Solana transaction (base64) to authorize. Required."
                    },
                    "intent": {
                        "type": "object",
                        "description": "Declared intent the transaction must match: {action, mint, amount_raw, recipient, memo?}. Strongly recommended — without it the verdict is at most REVIEW.",
                        "properties": {
                            "action": {"type": "string"},
                            "mint": {"type": "string"},
                            "amount_raw": {"type": "string"},
                            "recipient": {"type": "string"},
                            "memo": {"type": "string"}
                        },
                        "required": ["action", "amount_raw", "recipient"]
                    },
                    "detail_level": {
                        "type": "string",
                        "enum": ["slim", "full"],
                        "description": "slim (default) returns the compact verdict; full adds evidence digests."
                    },
                    "context": {
                        "type": "string",
                        "description": "Where this request originated (logged, never trusted)."
                    }
                },
                "required": ["transaction_base64"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // Config arrives host-injected; a caller-supplied __config is
            // stripped by the host before we ever see it.
            let config: HashMap<String, String> = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| v.get("__config").cloned())
                .and_then(|c| serde_json::from_value(c).ok())
                .unwrap_or_default();

            let rpc_url = config.get("rpc_url").cloned().unwrap_or_default();
            let transport: Option<WakiTransport> = if rpc_url.starts_with("https://") {
                Some(WakiTransport::new(rpc_url))
            } else {
                None
            };

            let started = std::time::Instant::now();
            let out = authorize::run(&args, transport.as_ref().map(|t| t as &dyn RpcTransport));

            let (action, outcome, level) = if out.success {
                (
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    LogLevel::Info,
                )
            } else {
                (PluginAction::Fail, PluginOutcome::Failure, LogLevel::Warn)
            };
            log_record(
                level,
                &PluginEvent {
                    function_name: "solana_tx_authorize::tool::execute".to_string(),
                    action,
                    outcome: Some(outcome),
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                    attrs: None,
                    message: out
                        .error
                        .clone()
                        .unwrap_or_else(|| "verdict issued".to_string()),
                },
            );

            Ok(ToolResult {
                success: out.success,
                output: out.output,
                error: out.error,
            })
        }
    }

    export!(SolanaTxAuthorize);
}
