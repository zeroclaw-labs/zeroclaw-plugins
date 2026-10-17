//! A ZeroClaw WIT tool plugin: `wallet_narrate`.
//!
//! Turns raw Solana transactions into sentences a human reads in a chat
//! window: *"Received 250 USDC from 7xK…gAsU. Swapped 1 SOL → 190 USDC on
//! Jupiter."* Given a wallet address it fetches the most recent signatures
//! (`getSignaturesForAddress`) and each transaction (`getTransaction`,
//! `jsonParsed`), then narrates the balance movements for that wallet in a
//! few hundred tokens — never the raw kilobytes the RPC sent.
//!
//! Custody tier: **T0 (read-only)**. No keys, no transaction building, no
//! signing. The only secrets this plugin can ever hold is an operator-supplied
//! RPC URL from its own jailed config section.
//!
//! The pure narration core lives in [`narrate`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod narrate;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::narrate::{
        compose_report, effective_limit, narrate_transaction, parse_signatures, validate_address,
        NarrateConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct WalletNarrate;

    const PLUGIN_NAME: &str = "wallet-narrate";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "wallet_narrate";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        address: String,
        #[serde(default)]
        limit: Option<u64>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn rpc_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|e| format!("rpc request failed: {e}"))?
            .json::<serde_json::Value>()
            .map_err(|e| format!("rpc response was not json: {e}"))
    }

    impl PluginInfo for WalletNarrate {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for WalletNarrate {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Narrate the recent on-chain activity of a Solana wallet address as short \
             human-readable sentences (transfers, swaps, fees, memos). Read-only: takes a \
             base58 address, returns text. It cannot build, sign, or send transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Base58 Solana wallet address to narrate."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                        "description": "How many recent transactions to narrate (default 5, max 10)."
                    }
                },
                "required": ["address"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let started = std::time::Instant::now();
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return fail(started, format!("invalid arguments: {e}")),
            };

            if let Err(e) = validate_address(&parsed.address) {
                return fail(started, e);
            }
            let cfg = NarrateConfig::from_section(&parsed.config);
            let limit = effective_limit(parsed.limit, &cfg);

            let sig_body = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "getSignaturesForAddress",
                "params": [parsed.address, {"limit": limit}]
            });
            let sig_resp = match rpc_post(&cfg.rpc_url, &sig_body) {
                Ok(v) => v,
                Err(e) => return fail(started, e),
            };
            if let Some(err) = sig_resp.get("error") {
                return fail(started, format!("rpc error: {err}"));
            }
            let signatures = parse_signatures(&sig_resp);

            let mut narrations = Vec::new();
            for sig in signatures.iter().take(limit) {
                let tx_body = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "getTransaction",
                    "params": [sig, {
                        "encoding": "jsonParsed",
                        "maxSupportedTransactionVersion": 0
                    }]
                });
                match rpc_post(&cfg.rpc_url, &tx_body) {
                    Ok(tx_resp) => {
                        if let Some(s) = narrate_transaction(&parsed.address, &tx_resp, &cfg) {
                            narrations.push(s);
                        }
                    }
                    // One unfetchable transaction should not sink the report.
                    Err(_) => narrations.push("[one transaction could not be fetched]".to_string()),
                }
            }

            let report = compose_report(&parsed.address, &narrations);
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "narrated wallet activity",
                Some(started.elapsed().as_millis() as u64),
                Some(narrations.len()),
            );
            Ok(ToolResult {
                success: true,
                output: report,
                error: None,
            })
        }
    }

    fn fail(started: std::time::Instant, message: String) -> Result<ToolResult, String> {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            &message,
            Some(started.elapsed().as_millis() as u64),
            None,
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        })
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        duration_ms: Option<u64>,
        narrated: Option<usize>,
    ) {
        let attrs = narrated.map(|n| format!("{{\"transactions\":{n}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "wallet_narrate::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(WalletNarrate);
}
