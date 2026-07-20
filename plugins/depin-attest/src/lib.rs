//! A ZeroClaw WIT tool plugin: `depin-attest`.
//!
//! Builds unsigned Solana versioned transactions that commit a DePIN device
//! attestation on-chain with a durable-nonce replay guard. T1 custody: no
//! signing, no secret keys held by the plugin. The human or multisig signs
//! externally.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod core;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::core::{AttestConfig, AttestInput, Reading, ReadingKind, SolanaRpc, attest};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DepinAttest;

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_attest";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        device_id: Option<String>,
        reading: ReadingPayload,
        nonce_counter: u64,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    #[derive(serde::Deserialize)]
    struct ReadingPayload {
        kind: String,
        value: String,
        ts: u64,
        device_sig: String,
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
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an unsigned Solana transaction that commits a DePIN device \
             attestation on-chain with a durable-nonce replay guard. T1 custody: \
             no signing, no secret keys held. The agent proposes, a human or \
             Squads multisig signs."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string",
                        "description": "Unique device identifier (e.g. 'pi-001'). Overrides config.device_id if set."
                    },
                    "reading": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "description": "Reading type: 'uptime_seconds', 'temperature_celsius', 'humidity_percent', or 'custom'."
                            },
                            "value": {
                                "type": "string",
                                "description": "String-encoded reading value."
                            },
                            "ts": {
                                "type": "integer",
                                "description": "Unix timestamp in seconds. Must be within 300s of current time."
                            },
                            "device_sig": {
                                "type": "string",
                                "description": "Hex-encoded ed25519 signature over (device_id || kind || value || ts). Advisory at T1."
                            }
                        },
                        "required": ["kind", "value", "ts", "device_sig"]
                    },
                    "nonce_counter": {
                        "type": "integer",
                        "description": "Monotonic counter. Must be > last_committed_counter. Advances each attestation."
                    }
                },
                "required": ["reading", "nonce_counter"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments", None);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let device_id = parsed
                .config
                .get("device_id")
                .filter(|v| !v.is_empty())
                .cloned()
                .or_else(|| parsed.device_id)
                .unwrap_or_default();

            let rpc_url = parsed
                .config
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| "https://api.devnet.solana.com".into());

            let nonce_account = parsed
                .config
                .get("nonce_account")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_default();

            let nonce_authority = parsed
                .config
                .get("nonce_authority")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_default();

            let last_committed_counter = parsed
                .config
                .get("last_committed_counter")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            let cfg = AttestConfig {
                rpc_url,
                device_id: device_id.clone(),
                nonce_account,
                nonce_authority,
                last_committed_counter,
            };

            let input = AttestInput {
                device_id,
                reading: Reading {
                    kind: ReadingKind {
                        kind: parsed.reading.kind,
                        value: parsed.reading.value,
                    },
                    ts: parsed.reading.ts,
                    device_sig: parsed.reading.device_sig,
                },
                nonce_counter: parsed.nonce_counter,
            };

            let wasm_rpc = WasmRpc {
                rpc_url: cfg.rpc_url.clone(),
            };

            match attest(&input, &wasm_rpc, &cfg) {
                Ok(result) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "attestation built",
                        Some(input.nonce_counter),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: result.summary,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &e.to_string(), None);
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            }
        }
    }

    // ---------------------------------------------------------------------------
    // WasmRpc — Solana RPC over waki (blocking wasi:http)
    // ---------------------------------------------------------------------------

    struct WasmRpc {
        rpc_url: String,
    }

    impl SolanaRpc for WasmRpc {
        fn get_recent_blockhash(
            &self,
        ) -> Result<crate::core::RpcBlockhashResponse, crate::core::AttestError> {
            let url = format!("{}/", self.rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getRecentBlockhash",
                "params": [{"commitment": "finalized"}]
            });
            waki::Client::new()
                .post(&url)
                .json(&body)
                .send()
                .map_err(|e| crate::core::AttestError::RpcError(e.to_string()))?
                .json::<crate::core::RpcBlockhashResponse>()
                .map_err(|e| crate::core::AttestError::RpcError(e.to_string()))
        }

        fn get_account_info(
            &self,
            pubkey_b58: &str,
        ) -> Result<crate::core::RpcNonceAccountResponse, crate::core::AttestError> {
            let url = format!("{}/", self.rpc_url.trim_end_matches('/'));
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [pubkey_b58, {"encoding": "base58", "commitment": "finalized"}]
            });
            waki::Client::new()
                .post(&url)
                .json(&body)
                .send()
                .map_err(|e| crate::core::AttestError::RpcError(e.to_string()))?
                .json::<crate::core::RpcNonceAccountResponse>()
                .map_err(|e| crate::core::AttestError::RpcError(e.to_string()))
        }
    }

    // ---------------------------------------------------------------------------
    // Logging — fire-and-forget via log_record. Never stdout.
    // ---------------------------------------------------------------------------

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        nonce_counter: Option<u64>,
    ) {
        let attrs = nonce_counter.map(|n| format!("{{\"nonce_counter\":{n}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(DepinAttest);
}
