//! A ZeroClaw WIT tool plugin: `spl-transfer-build`.
//!
//! Builds an unsigned SOL/SPL transfer transaction: ATA-aware, optional
//! invoice memo, matching intent object for `solana-tx-authorize`. The builder
//! holds no keys and signs nothing (T1); a human or the host signs its output.
//! It refuses to emit a transaction that violates the operator's own spend
//! policy.
//!
//! The pure builder core lives in [`transfer`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod transfer;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::transfer;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use safe_hands_core::rpc::{RpcTransport, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SplTransferBuild;

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "spl-transfer-build";

    impl PluginInfo for SplTransferBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SplTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an unsigned SOL or SPL-token transfer transaction (base64) with a matching intent \
             object. Use when the user wants to send funds. The output is unsigned: pass it to \
             solana-tx-authorize for the mandatory policy check, then a human or the host signs. \
             Handles ATA creation and optional invoice memos. This tool never signs or submits."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Destination wallet (base58). For SPL transfers the tokens land in the recipient's ATA, created idempotently."
                    },
                    "amount_raw": {
                        "type": "string",
                        "description": "Amount in raw smallest units as a decimal string (lamports for SOL, base units for SPL)."
                    },
                    "mint": {
                        "type": "string",
                        "description": "SPL mint address. Omit for a native SOL transfer."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional memo (invoice id etc.), max 566 bytes."
                    },
                    "token_program": {
                        "type": "string",
                        "description": "Token program override (default: classic SPL Token)."
                    }
                },
                "required": ["recipient", "amount_raw"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
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
            let out = transfer::run(&args, transport.as_ref().map(|t| t as &dyn RpcTransport));

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
                    function_name: "spl_transfer_build::tool::execute".to_string(),
                    action,
                    outcome: Some(outcome),
                    duration_ms: Some(started.elapsed().as_millis() as u64),
                    attrs: None,
                    message: out
                        .error
                        .clone()
                        .unwrap_or_else(|| "transfer built".to_string()),
                },
            );

            Ok(ToolResult {
                success: out.success,
                output: out.output,
                error: out.error,
            })
        }
    }

    export!(SplTransferBuild);
}
