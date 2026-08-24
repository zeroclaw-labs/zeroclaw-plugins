//! Read-only Solana stake-account monitoring for ZeroClaw.
//!
//! The pure parsing and policy core is in [`stake_monitor`]. This file is a
//! thin wasm shim: it validates arguments, issues bounded JSON-RPC reads,
//! shapes the result, and emits structured host logs. It cannot build, sign,
//! submit, delegate, deactivate, withdraw, or otherwise move funds.

pub mod stake_monitor;

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

    use crate::stake_monitor::{
        account_request, analyze, epoch_request, inflation_reward_request, parse_account_response,
        parse_epoch_response, parse_reward_response, parse_vote_accounts_response, render_report,
        validate_pubkey, vote_accounts_request, StakeMonitorConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "stake-monitor";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        stake_account: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct StakeMonitor;

    impl PluginInfo for StakeMonitor {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for StakeMonitor {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Inspect one Solana stake account without custody risk. Returns its lifecycle, \
             delegated stake, validator status and commission, vote lag, lockup metadata, \
             and prior-epoch reward. Read-only: cannot sign, delegate, deactivate, withdraw, \
             claim, or move funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "stake_account": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                        "description": "Base58 Solana stake-account public key."
                    }
                },
                "required": ["stake_account"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return tool_error(format!("invalid arguments: {error}")),
            };

            if let Err(error) = validate_pubkey(&parsed.stake_account, "stake_account") {
                return tool_error(error);
            }

            let config = match StakeMonitorConfig::from_section(&parsed.config) {
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

            let account_json = match post_json(
                &config.rpc_url,
                &account_request(&parsed.stake_account, &config.commitment),
            ) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let account = match parse_account_response(&account_json, &parsed.stake_account) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            let validator = if let Some(vote_account) = account.vote_account.as_deref() {
                let vote_json = match post_json(
                    &config.rpc_url,
                    &vote_accounts_request(vote_account, &config.commitment),
                ) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
                match parse_vote_accounts_response(&vote_json, vote_account) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                }
            } else {
                None
            };

            let reward = if account.vote_account.is_some() && epoch.epoch > 0 {
                let reward_json = match post_json(
                    &config.rpc_url,
                    &inflation_reward_request(
                        &parsed.stake_account,
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
            } else {
                None
            };

            let report = analyze(
                &parsed.stake_account,
                &epoch,
                &account,
                validator.as_ref(),
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
                "stake account report completed",
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
            "stake account check failed closed",
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
                function_name: "stake_monitor::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(StakeMonitor);
}
