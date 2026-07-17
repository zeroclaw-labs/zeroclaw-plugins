//! Read-only Solana validator monitoring for ZeroClaw.
//!
//! The pure parsing and policy core is in [`validator_health`]. This file is a
//! thin wasm shim: validate arguments, issue three JSON-RPC reads, shape the
//! result, and emit structured host logs. It cannot sign or submit a
//! transaction and never accepts a key or RPC endpoint from tool arguments.

pub mod validator_health;

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

    use crate::validator_health::{
        analyze, epoch_request, inflation_reward_request, parse_epoch_response,
        parse_reward_response, parse_vote_accounts_response, render_report, validate_pubkey,
        vote_accounts_request, ValidatorConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "validator-health";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        vote_account: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct ValidatorHealth;

    impl PluginInfo for ValidatorHealth {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for ValidatorHealth {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Check a Solana validator vote account without custody risk. Returns current or \
             delinquent status, activated stake, commission, vote/root lag, epoch credits, \
             and the previous epoch reward. Read-only: cannot sign, send, stake, or move funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "vote_account": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                        "description": "Base58 Solana validator vote-account public key."
                    }
                },
                "required": ["vote_account"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return tool_error(format!("invalid arguments: {error}")),
            };

            if let Err(error) = validate_pubkey(&parsed.vote_account) {
                return tool_error(error);
            }

            let config = match ValidatorConfig::from_section(&parsed.config) {
                Ok(config) => config,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "querying configured Solana RPC",
            );

            let epoch_json = match post_json(&config.rpc_url, &epoch_request(&config.commitment)) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let epoch = match parse_epoch_response(&epoch_json) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            let vote_json = match post_json(
                &config.rpc_url,
                &vote_accounts_request(&parsed.vote_account, &config.commitment),
            ) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let vote = match parse_vote_accounts_response(&vote_json, &parsed.vote_account) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            let reward = if epoch.epoch == 0 {
                None
            } else {
                let reward_json = match post_json(
                    &config.rpc_url,
                    &inflation_reward_request(
                        &parsed.vote_account,
                        epoch.epoch - 1,
                        &config.commitment,
                    ),
                ) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
                match parse_reward_response(&reward_json, epoch.epoch - 1) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                }
            };

            let report = analyze(
                &parsed.vote_account,
                &epoch,
                vote.as_ref(),
                reward.as_ref(),
                &config,
            );
            let output = match render_report(&report) {
                Ok(output) => output,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "validator health report completed",
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
            "validator health check failed closed",
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
                function_name: "validator_health::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(ValidatorHealth);
}
