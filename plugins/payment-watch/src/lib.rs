//! A ZeroClaw WIT tool plugin: `check_payment`.
//!
//! Watches an operator-configured Solana address for an expected SPL payment
//! (amount + mint + optional memo reference) and reports a compact,
//! chain-verified confirmation. Custody tier: **T0 (Read)** — read-only RPC,
//! no keys, no value movement.
//!
//! Pairs with `nonce-transfer-build` to close the loop: the agent proposes a
//! payment, a human approves it, and this tool confirms it landed — from the
//! chain, never from a chat message. Wire it to a cron SOP for "ping me when
//! invoice #412 is paid".
//!
//! The pure matching core lives in [`watch`]; host tests feed it fixture RPC
//! responses. Build:
//!     rustup target add wasm32-wasip2
//!     cargo build --target wasm32-wasip2 --release

pub mod watch;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::watch::{match_payment, WatchArgs, WatchConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_wasi_core::rpc;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PaymentWatch;

    const PLUGIN_NAME: &str = "payment-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "check_payment";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        #[serde(flatten)]
        watch: WatchArgs,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    fn rpc_call(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string().into_bytes())
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("RPC HTTP {status}"));
        }
        let bytes = resp.body().map_err(|e| format!("RPC body read: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("RPC bad JSON: {e}"))
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check whether an expected SPL token payment has arrived at the operator's \
             watched address. Reports PAID/NOT PAID from on-chain data only (never from \
             messages). Read-only; holds no keys. Optionally match amount, mint, and a \
             memo reference like an invoice number."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "expected_amount": {
                        "type": "string",
                        "description": "Expected token amount, e.g. \"25\". Omit to match any amount."
                    },
                    "expected_mint": {
                        "type": "string",
                        "description": "Expected SPL mint address (base58). Omit to match any mint."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Memo substring to match, e.g. \"invoice #412\". Omit to skip memo matching."
                    }
                },
                "required": []
            })
            .to_string()
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

            let cfg = match WatchConfig::from_section(&parsed.config) {
                Ok(c) => c,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "missing config");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("operator config error: {e}")),
                    });
                }
            };

            // Scan recent signatures, then pull + parse each transaction.
            let observed = (|| -> Result<Vec<_>, String> {
                let sigs_resp = rpc_call(
                    &cfg.rpc_url,
                    &rpc::get_signatures_for_address(&cfg.watch_address, cfg.scan_limit),
                )?;
                let sigs = rpc::unwrap_result(&sigs_resp)?
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let mut all = Vec::new();
                for entry in sigs.iter().take(cfg.scan_limit as usize) {
                    let sig = match entry.get("signature").and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => continue,
                    };
                    // Skip txs the RPC already marks failed.
                    if entry.get("err").map(|e| !e.is_null()).unwrap_or(false) {
                        continue;
                    }
                    let tx_resp = rpc_call(&cfg.rpc_url, &rpc::get_transaction(sig))?;
                    if let Ok(mut transfers) =
                        rpc::parse_inbound_transfers(&tx_resp, sig, &cfg.watch_address)
                    {
                        all.append(&mut transfers);
                    }
                    if !all.is_empty()
                        && (parsed.watch.expected_amount.is_none()
                            || match_found(&parsed.watch, &all))
                    {
                        break; // early exit once a candidate matched
                    }
                }
                Ok(all)
            })();

            let observed = match observed {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "rpc scan failed",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            let out = match_payment(&parsed.watch, &observed);
            emit(PluginAction::Complete, PluginOutcome::Success, "scan done");
            Ok(ToolResult {
                success: true,
                output: out.render(),
                error: None,
            })
        }
    }

    fn match_found(args: &WatchArgs, observed: &[solana_wasi_core::rpc::ObservedTransfer]) -> bool {
        let rendered = match_payment(args, observed).render();
        rendered.contains("PAID ✅")
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "payment_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(PaymentWatch);
}
