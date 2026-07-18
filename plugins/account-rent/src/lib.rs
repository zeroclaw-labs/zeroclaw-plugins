//! Read-only Solana account rent inspection for ZeroClaw.

pub mod account_rent;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde::Deserialize;
    use serde_json::Value;

    use crate::account_rent::{
        account_request, build_report, parse_account_response, parse_rent_response, render_report,
        rent_request, validate_pubkey, AccountRentConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "account-rent";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        account_address: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct AccountRent;

    impl PluginInfo for AccountRent {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for AccountRent {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Inspect a Solana account's owner, data size, lamport balance, and current rent-exemption threshold. Read-only: cannot sign, fund, resize, close, or submit transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "account_address": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                        "description": "Base58 Solana account address."
                    }
                },
                "required": ["account_address"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return tool_error(format!("invalid arguments: {error}")),
            };
            if let Err(error) = validate_pubkey(&parsed.account_address, "account_address") {
                return tool_error(error);
            }
            let config = match AccountRentConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "querying account and rent threshold",
            );
            let account_json = match post_json(
                &config.rpc_url,
                &account_request(&parsed.account_address, 1, &config.commitment),
            ) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let account = match parse_account_response(&account_json, &parsed.account_address) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let rent_json = match post_json(
                &config.rpc_url,
                &rent_request(account.data_len, 2, &config.commitment),
            ) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let minimum = match parse_rent_response(&rent_json) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            let report = build_report(&parsed.account_address, &account, minimum);
            let output = match render_report(&report) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "account rent report completed",
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
            "account rent inspection failed closed",
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
                function_name: "account_rent::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(AccountRent with_types_in self);
}
