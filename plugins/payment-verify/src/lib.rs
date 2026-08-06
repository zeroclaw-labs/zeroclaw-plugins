//! A ZeroClaw WIT tool plugin: `payment-verify`.
//!
//! Confirms whether a Solana Pay invoice was paid, using only finalized chain
//! evidence read from two independent RPC endpoints that must agree. The
//! invoice reference is re-derived from the order, so verification needs no
//! record that the invoice was ever created.
//!
//! Custody tier T0: read only. It holds no keys and authorizes nothing. A
//! reported payer address is evidence, never permission to send money back.
//!
//! The pure verifier core lives in [`verify`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod verify;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::verify;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use safe_hands_core::rpc::{RpcTransport, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PaymentVerify;

    const PLUGIN_NAME: &str = "payment-verify";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "payment-verify";

    impl PluginInfo for PaymentVerify {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for PaymentVerify {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Issue and check a Solana USDC invoice in one call. Nothing is stored: the invoice \
             reference is derived from the order id, so this same call both returns the Solana \
             Pay payment link for an unpaid order and reports the finalized on-chain result once \
             it is paid. Use it to charge a customer AND to check an order. Status is PAID, \
             UNPAID, UNDERPAID, OVERPAID, LATE, REVIEW or UNKNOWN. UNKNOWN means the evidence \
             could not be trusted and is never proof of non-payment. The settlement currency is \
             fixed by the operator's configuration — do not attempt to specify one. Read-only: \
             holds no keys, moves no funds, authorizes no refund."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "order_id": {
                        "type": "string",
                        "description": "The same order identifier the invoice was created with. The reference is re-derived from it."
                    },
                    "amount_raw": {
                        "type": "string",
                        "description": "The invoiced amount in raw smallest units as a decimal string. Reported alongside the observed amount; never overwritten by it."
                    },
                    "expiry_unix": {
                        "type": "integer",
                        "description": "Optional invoice expiry as unix seconds. A payment finalized after this is reported LATE rather than PAID."
                    },
                    "label": {
                        "type": "string",
                        "description": "Optional merchant name shown in the customer's wallet on the payment link."
                    },
                    "message": {
                        "type": "string",
                        "description": "Optional description shown in the customer's wallet on the payment link."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional on-chain memo. Keep it minimal; never put customer personal data on-chain."
                    }
                },
                "required": ["order_id", "amount_raw"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let config: HashMap<String, String> = serde_json::from_str::<serde_json::Value>(&args)
                .ok()
                .and_then(|v| v.get("__config").cloned())
                .and_then(|c| serde_json::from_value(c).ok())
                .unwrap_or_default();

            let endpoint = |key: &str| -> Option<WakiTransport> {
                config
                    .get(key)
                    .filter(|url| url.starts_with("https://"))
                    .map(|url| WakiTransport::new(url.clone()))
            };
            let primary = endpoint("rpc_url");
            // Two endpoints only count as corroboration if they are two
            // endpoints. A copy-pasted fallback queries one provider twice and
            // silently turns a 2-of-2 agreement gate into 1-of-1 — while the
            // receipt still reports that primary and fallback agreed. Drop the
            // fallback instead, so the result is honestly single-sourced.
            let fallback = match (config.get("rpc_url"), config.get("rpc_url_fallback")) {
                (Some(a), Some(b)) if a.trim() == b.trim() => None,
                _ => endpoint("rpc_url_fallback"),
            };

            let started = std::time::Instant::now();
            let out = verify::run(
                &args,
                primary.as_ref().map(|t| t as &dyn RpcTransport),
                fallback.as_ref().map(|t| t as &dyn RpcTransport),
            );

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
                    function_name: "payment_verify::tool::execute".to_string(),
                    action,
                    outcome: Some(outcome),
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                    attrs: None,
                    message: out
                        .error
                        .clone()
                        .unwrap_or_else(|| "invoice verified".to_string()),
                },
            );

            Ok(ToolResult {
                success: out.success,
                output: out.output,
                error: out.error,
            })
        }
    }

    export!(PaymentVerify);
}
