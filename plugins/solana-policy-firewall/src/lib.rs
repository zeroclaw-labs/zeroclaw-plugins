//! ZeroClaw `tool-plugin` that evaluates serialized Solana transactions before
//! a wallet or human is asked to sign.
//!
//! The pure parser and policy engine are ordinary Rust modules with no WASM or
//! network dependency. The component shim below only injects operator config,
//! performs host-mediated JSON-RPC calls, and emits structured ZeroClaw logs.

pub mod firewall;
pub mod programs;
pub mod rpc;
pub mod transaction;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use base64::Engine;
    use serde_json::{json, Value};

    use crate::firewall::{evaluate, DecisionReceipt};
    use crate::rpc::{RpcAccount, RpcClient, SimulationResult};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = env!("CARGO_PKG_NAME");
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_transaction_policy_check";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        transaction_base64: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct WakiRpc {
        url: String,
    }

    impl WakiRpc {
        fn post(&self, payload: &Value) -> Result<Value, String> {
            if !self.url.starts_with("https://") {
                return Err("rpc_url must use https".to_string());
            }
            let response = waki::Client::new()
                .post(&self.url)
                .json(payload)
                .send()
                .map_err(|error| format!("RPC transport failed: {error}"))?
                .json::<Value>()
                .map_err(|error| format!("RPC JSON failed: {error}"))?;
            if let Some(error) = response.get("error") {
                return Err(format!("RPC returned {error}"));
            }
            Ok(response)
        }
    }

    impl RpcClient for WakiRpc {
        fn get_account(&mut self, address: &str) -> Result<Option<RpcAccount>, String> {
            let response = self.post(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [address, {"encoding": "base64", "commitment": "confirmed"}]
            }))?;
            let value = &response["result"]["value"];
            if value.is_null() {
                return Ok(None);
            }
            let owner = value["owner"]
                .as_str()
                .ok_or_else(|| "getAccountInfo result has no owner".to_string())?;
            let encoded = value["data"]
                .as_array()
                .and_then(|parts| parts.first())
                .and_then(Value::as_str)
                .ok_or_else(|| "getAccountInfo result has no base64 data".to_string())?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| format!("account data is invalid base64: {error}"))?;
            Ok(Some(RpcAccount {
                owner: owner.to_string(),
                data,
            }))
        }

        fn get_fee_for_message(&mut self, message_base64: &str) -> Result<Option<u64>, String> {
            let response = self.post(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "getFeeForMessage",
                "params": [message_base64, {"commitment": "confirmed"}]
            }))?;
            let value = &response["result"]["value"];
            if value.is_null() {
                return Ok(None);
            }
            value
                .as_u64()
                .map(Some)
                .ok_or_else(|| "getFeeForMessage result is not a u64 or null".to_string())
        }

        fn get_minimum_balance_for_rent_exemption(
            &mut self,
            data_len: usize,
        ) -> Result<u64, String> {
            let response = self.post(&json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "getMinimumBalanceForRentExemption",
                "params": [data_len, {"commitment": "confirmed"}]
            }))?;
            response["result"]
                .as_u64()
                .ok_or_else(|| "getMinimumBalanceForRentExemption result is not a u64".to_string())
        }

        fn simulate_transaction(
            &mut self,
            transaction_base64: &str,
        ) -> Result<SimulationResult, String> {
            let response = self.post(&json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "simulateTransaction",
                "params": [transaction_base64, {
                    "encoding": "base64",
                    "sigVerify": false,
                    "replaceRecentBlockhash": false,
                    "commitment": "confirmed"
                }]
            }))?;
            let value = &response["result"]["value"];
            if value.is_null() {
                return Err("simulateTransaction result is null".to_string());
            }
            let error = value
                .get("err")
                .filter(|error| !error.is_null())
                .map(|error| error.to_string());
            Ok(SimulationResult {
                error,
                units_consumed: value.get("unitsConsumed").and_then(Value::as_u64),
                slot: response["result"]["context"]["slot"].as_u64(),
            })
        }
    }

    struct SolanaPolicyFirewall;

    impl PluginInfo for SolanaPolicyFirewall {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPolicyFirewall {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Fail-closed pre-sign firewall for serialized Solana transactions. \
             It derives intent from final transaction bytes, resolves v0 lookup \
             tables and SPL token owners, enforces operator-owned fee-payer, \
             signer, program, recipient, mint, amount, priority-fee and writable-\
             account limits, rejects authority/delegate/opaque instructions, and \
             simulates the exact transaction. It never signs or submits."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "transaction_base64": {
                        "type": "string",
                        "description": "Complete unsigned Solana transaction wire bytes encoded as base64. Policy is never accepted from tool arguments."
                    }
                },
                "required": ["transaction_base64"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(arguments) => arguments,
                Err(error) => {
                    emit_failure("invalid arguments");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {error}")),
                    });
                }
            };
            let rpc_url = parsed.config.get("rpc_url").cloned().unwrap_or_default();
            let mut rpc = WakiRpc { url: rpc_url };
            let receipt = evaluate(&parsed.transaction_base64, &parsed.config, &mut rpc);
            emit_receipt(&receipt);

            match serde_json::to_string(&receipt) {
                Ok(output) => Ok(ToolResult {
                    success: true,
                    output,
                    error: None,
                }),
                Err(error) => Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("receipt serialization failed: {error}")),
                }),
            }
        }
    }

    fn emit_receipt(receipt: &DecisionReceipt) {
        let action = if receipt.allowed() {
            PluginAction::Approve
        } else {
            PluginAction::Reject
        };
        let outcome = if receipt.allowed() {
            PluginOutcome::Success
        } else {
            PluginOutcome::Failure
        };
        log_record(
            if receipt.allowed() {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            &PluginEvent {
                function_name: "solana_policy_firewall::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(
                    json!({
                        "receipt_hash": receipt.receipt_hash,
                        "verdict": receipt.verdict,
                        "violations": receipt.violations.len()
                    })
                    .to_string(),
                ),
                message: if receipt.allowed() {
                    "transaction passed pre-sign policy".to_string()
                } else {
                    "transaction denied by pre-sign policy".to_string()
                },
            },
        );
    }

    fn emit_failure(message: &str) {
        log_record(
            LogLevel::Error,
            &PluginEvent {
                function_name: "solana_policy_firewall::tool::execute".to_string(),
                action: PluginAction::Fail,
                outcome: Some(PluginOutcome::Failure),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPolicyFirewall);
}
