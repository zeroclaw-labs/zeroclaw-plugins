//! ZeroClaw WIT tool plugin: read-only Solana Realms governance monitoring.

pub mod governance;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::governance::{
        build_rpc_request, format_summary, parse_execute_args, parse_rpc_response, RuntimeConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "governance-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    struct GovernanceWatch;

    impl PluginInfo for GovernanceWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for GovernanceWatch {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "List recent SPL Governance ProposalV2 accounts from Solana Realms. Read-only: it cannot vote, sign, transfer funds, or build transactions. On-chain text is returned as explicitly untrusted data and suspected prompt injection is withheld."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "governance": {
                        "type": "string",
                        "description": "Required 32-byte base58 Governance account pubkey whose proposals will be listed."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5,
                        "default": 3,
                        "description": "Maximum recent proposals returned."
                    }
                },
                "required": ["governance"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            match execute_inner(&args) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "queried governance proposals",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "governance query failed",
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(error),
                    })
                }
            }
        }
    }

    fn execute_inner(args: &str) -> Result<String, String> {
        let query = parse_execute_args(args)?;
        let raw: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
        let section: HashMap<String, String> = raw
            .get("__config")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| format!("invalid plugin config: {e}"))?
            .unwrap_or_default();
        let config = RuntimeConfig::from_section(&section)?;
        let request = build_rpc_request(&query.governance)?;
        let response = waki::Client::new()
            .post(&config.rpc_url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .map_err(|e| format!("Solana RPC request failed: {e}"))?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("Solana RPC returned HTTP {status}"));
        }
        let body = response
            .body()
            .map_err(|e| format!("failed to read Solana RPC response: {e}"))?;
        let body = String::from_utf8(body)
            .map_err(|_| "Solana RPC returned non-UTF-8 JSON".to_string())?;
        let proposals = parse_rpc_response(&body)?;
        Ok(format_summary(&proposals, query.limit))
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "governance_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some("{\"network\":\"solana-mainnet\",\"mode\":\"read-only\"}".to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(GovernanceWatch);
}
