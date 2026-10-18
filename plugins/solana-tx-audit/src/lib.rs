//! ZeroClaw tool plugin: `solana_tx_audit`.
//!
//! The Solana parsing and policy engine live in `solsafe-core`; this file is a
//! thin WIT component shim plus a wasm-only JSON-RPC adapter.

pub fn parameters_schema_json() -> String {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "transaction_base64": {"type": "string", "minLength": 1, "maxLength": 10000},
            "declared_intent": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "action": {"type": "string", "enum": ["swap", "transfer", "stake", "vote", "unknown"]},
                    "input_mint": {"type": "string"},
                    "output_mint": {"type": "string"},
                    "amount": {"type": "string"},
                    "max_amount": {"type": "string"},
                    "expected_recipient": {"type": "string"},
                    "expected_programs": {"type": "array", "items": {"type": "string"}, "maxItems": 32},
                    "expected_signer": {"type": "string"},
                    "memo": {"type": "string", "maxLength": 180}
                }
            },
            "options": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "simulate": {"type": "boolean"},
                    "strict": {"type": "boolean"}
                }
            }
        },
        "required": ["transaction_base64"]
    })
    .to_string()
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::{json, Value};
    use solsafe_core::{audit_json, redact_url, RpcClient, SolSafeError};

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-tx-audit";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_tx_audit";

    struct HttpRpc {
        url: String,
    }

    impl RpcClient for HttpRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, SolSafeError> {
            if !self.url.starts_with("https://") {
                return Err(SolSafeError::Rpc("RPC URL must use HTTPS".to_string()));
            }
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
            });
            let resp = waki::Client::new()
                .post(&self.url)
                .json(&body)
                .send()
                .map_err(|e| {
                    SolSafeError::Rpc(
                        format!("RPC transport failed for {}", redact_url(&self.url))
                            .replace(&e.to_string(), "transport error"),
                    )
                })?;
            let value = resp
                .json::<Value>()
                .map_err(|_| SolSafeError::Rpc("RPC response was malformed JSON".to_string()))?;
            if let Some(err) = value.get("error") {
                let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
                return Err(SolSafeError::Rpc(format!("JSON-RPC error code {code}")));
            }
            Ok(value.get("result").cloned().unwrap_or(value))
        }
    }

    struct SolanaTxAudit;

    impl PluginInfo for SolanaTxAudit {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaTxAudit {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Inspect an unsigned Solana transaction before approval. Decodes programs, transfers, signers, recipients, authority changes, expiry, and configured simulation. Never signs or submits.".to_string()
        }

        fn parameters_schema() -> String {
            crate::parameters_schema_json()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            emit(PluginAction::Start, None, "request_received");
            let cfg_rpc = serde_json::from_str::<Value>(&args)
                .ok()
                .and_then(|v| v.get("__config").cloned())
                .and_then(|c| c.get("rpc_url").and_then(Value::as_str).map(str::to_string));
            let rpc = cfg_rpc.map(|url| HttpRpc { url });
            let result = audit_json(&args, rpc.as_ref().map(|r| r as &dyn RpcClient));
            match result {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        Some(PluginOutcome::Success),
                        "approval_payload_created",
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
                        "request_failed",
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    })
                }
            }
        }
    }

    fn emit(action: PluginAction, outcome: Option<PluginOutcome>, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_tx_audit::tool::execute".to_string(),
                action,
                outcome,
                duration_ms: None,
                attrs: Some("{\"plugin\":\"solana-tx-audit\"}".to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(SolanaTxAudit);
}

pub use solsafe_core::*;
