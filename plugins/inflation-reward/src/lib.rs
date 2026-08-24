//! Inspect the latest available inflation reward for a public Solana account.

pub mod inflation_reward;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::inflation_reward::{
        build_report, expected_decoded_len, parse_rpc_response, render_report, rpc_request,
        validate_identifier, RpcConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use serde_json::Value;
    use std::collections::HashMap;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "inflation-reward";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        account_address: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct Plugin;

    impl PluginInfo for Plugin {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for Plugin {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn description() -> String {
            "Inspect the latest available inflation reward for a public Solana account. Read-only: cannot sign, fund, approve, or submit transactions.".to_string()
        }
        fn parameters_schema() -> String {
            serde_json::json!({
                "type":"object",
                "additionalProperties":false,
                "properties":{"account_address":{"type":"string","minLength":32,"maxLength":88,"pattern":"^[1-9A-HJ-NP-Za-km-z]+$","description":"Base58-encoded public Solana identifier."}},
                "required":["account_address"]
            }).to_string()
        }
        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return tool_error(format!("invalid arguments: {error}")),
            };
            if let Err(error) = validate_identifier(
                &parsed.account_address,
                "account_address",
                expected_decoded_len(),
            ) {
                return tool_error(error);
            }
            let config = match RpcConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "querying configured Solana RPC",
            );
            let request = rpc_request(&parsed.account_address, 1, &config.commitment);
            let response = match post_json(&config.rpc_url, &request) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let result = match parse_rpc_response(&response) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let query = parsed.account_address.to_string();
            let output = match render_report(&build_report(query, result)) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "read-only RPC report completed",
            );
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|error| format!("Solana RPC request failed: {error}"))?
            .json::<Value>()
            .map_err(|error| format!("Solana RPC returned invalid JSON: {error}"))
    }

    fn tool_error(message: String) -> Result<ToolResult, String> {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "read-only RPC query failed closed",
        );
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "inflation_reward::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(Plugin with_types_in self);
}
