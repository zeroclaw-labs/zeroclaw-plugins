//! A custody-free ZeroClaw tool that explains recent Solana wallet activity.
//!
//! The pure parser and narrator live in [`activity`]. The wasm-only shim makes
//! bounded HTTPS reads against an operator-configured Solana JSON-RPC endpoint.

pub mod activity;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::{json, Value};

    use crate::activity::{
        parse_signatures, summarize_transaction, ActivityReport, ActivityRequest,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "wallet-activity-narrator";
    const PLUGIN_VERSION: &str = "0.1.0";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteEnvelope {
        address: String,
        #[serde(default)]
        limit: Option<u8>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct WalletActivityNarrator;

    impl PluginInfo for WalletActivityNarrator {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for WalletActivityNarrator {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Read recent Solana wallet transactions and explain each as received, sent, swap, or contract activity. Read-only: never accepts keys, signs, or submits transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Base58 Solana wallet address."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5,
                        "default": 3,
                        "description": "Number of recent transactions to explain."
                    }
                },
                "required": ["address"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            emit(
                PluginAction::Start,
                PluginOutcome::Success,
                "wallet activity lookup started",
            );

            let envelope: ExecuteEnvelope = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return Ok(failure(format!("invalid arguments: {error}"))),
            };
            let request = ActivityRequest {
                address: envelope.address,
                limit: envelope.limit,
            };
            if let Err(error) = request.validate() {
                return Ok(failure(error));
            }
            let limit = request.effective_limit();

            let rpc_url = envelope
                .config
                .get("rpc_url")
                .map(String::as_str)
                .unwrap_or(DEFAULT_RPC_URL);
            if !is_https(rpc_url) {
                return Ok(failure("rpc_url must use https".to_string()));
            }

            let signatures_response = match rpc_call(
                rpc_url,
                1,
                "getSignaturesForAddress",
                json!([
                    request.address,
                    {"commitment": "confirmed", "limit": limit}
                ]),
            ) {
                Ok(value) => value,
                Err(error) => return Ok(failure(format!("signature lookup failed: {error}"))),
            };
            let signatures = match parse_signatures(&signatures_response.to_string(), limit) {
                Ok(value) => value,
                Err(error) => return Ok(failure(error)),
            };

            let mut transactions = Vec::new();
            let mut unavailable = 0u8;
            for (index, meta) in signatures.iter().enumerate() {
                let transaction_response = match rpc_call(
                    rpc_url,
                    (index + 2) as u64,
                    "getTransaction",
                    json!([
                        meta.signature,
                        {
                            "commitment": "confirmed",
                            "encoding": "jsonParsed",
                            "maxSupportedTransactionVersion": 0
                        }
                    ]),
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        unavailable = unavailable.saturating_add(1);
                        continue;
                    }
                };
                match summarize_transaction(
                    &request.address,
                    &meta.signature,
                    &transaction_response.to_string(),
                ) {
                    Ok(Some(item)) => transactions.push(item),
                    Ok(None) | Err(_) => unavailable = unavailable.saturating_add(1),
                }
            }

            let report = ActivityReport {
                address: request.address,
                transaction_count: transactions.len(),
                unavailable,
                transactions,
                note: "Read-only RPC interpretation; labels may be incomplete for unfamiliar programs."
                    .to_string(),
            };
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "wallet activity lookup completed",
            );
            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&report)
                    .map_err(|error| format!("serialize report: {error}"))?,
                error: None,
            })
        }
    }

    fn rpc_call(url: &str, id: u64, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        let response = waki::Client::new()
            .post(url)
            .json(&body)
            .send()
            .map_err(|error| error.to_string())?
            .json::<Value>()
            .map_err(|error| error.to_string())?;
        if let Some(error) = response.get("error") {
            return Err(format!("RPC returned {error}"));
        }
        Ok(response)
    }

    fn is_https(url: &str) -> bool {
        url.starts_with("https://") && !url.chars().any(char::is_whitespace)
    }

    fn failure(error: String) -> ToolResult {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "wallet activity lookup failed",
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "wallet_activity_narrator::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(WalletActivityNarrator);
}
