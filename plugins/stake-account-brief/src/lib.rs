//! Read-only Solana stake-account monitoring for ZeroClaw.
//!
//! The pure parsing and policy core is in [`stake_account`]. This file is a
//! thin wasm shim: validate public arguments, issue fixed read-only JSON-RPC
//! calls, shape the result, and emit structured host logs. It cannot sign or
//! submit a transaction and never accepts a private key.

pub mod stake_account;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::Value;

    use crate::stake_account::{
        account_info_request, build_brief, epoch_info_request, inflation_reward_request,
        parse_account_response, parse_epoch_response, parse_reward_response, parse_tool_args,
        parse_vote_accounts_response, render_brief, vote_accounts_request, StakeConfig, StakeKind,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "stake-account-brief";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const MAX_RPC_RESPONSE_BYTES: usize = 256 * 1024;

    struct StakeAccountBrief;

    impl PluginInfo for StakeAccountBrief {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for StakeAccountBrief {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Inspect one public Solana stake account using read-only RPC. Returns its epoch-based \
             schedule phase, delegated amount, validator current/delinquent status, commission, \
             network activated stake, and prior-epoch reward. T0 custody: cannot sign, send, \
             delegate, deactivate, or move funds."
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
                        "description": "Base58 public key of the Solana stake account to inspect."
                    }
                },
                "required": ["stake_account"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed = match parse_tool_args(&args) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let config = match StakeConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "querying configured Solana RPC",
            );

            let account_json = match post_json(
                &config.rpc_url,
                &account_info_request(&parsed.stake_account, &config.commitment),
            ) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let account = match parse_account_response(&account_json, &parsed.stake_account) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            let epoch_json =
                match post_json(&config.rpc_url, &epoch_info_request(&config.commitment)) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
            let epoch = match parse_epoch_response(&epoch_json) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            let validator = if let Some(vote_account) = account.vote_account.as_deref() {
                let validator_json = match post_json(
                    &config.rpc_url,
                    &vote_accounts_request(vote_account, &config.commitment),
                ) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
                match parse_vote_accounts_response(&validator_json, vote_account) {
                    Ok(value) => Some(value),
                    Err(error) => return tool_error(error),
                }
            } else {
                None
            };

            let reward = if account.kind == StakeKind::Delegated && epoch.epoch > 0 {
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

            let brief = build_brief(
                &parsed.stake_account,
                &account,
                &epoch,
                validator.as_ref(),
                reward.as_ref(),
            );
            let output = match render_brief(&brief) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "stake-account brief completed",
            );
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("Solana RPC");
        let response = waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|_| format!("{method} request failed"))?;
        if !(200..300).contains(&response.status_code()) {
            return Err(format!("{method} returned a non-success HTTP status"));
        }
        let mut response_body = Vec::new();
        loop {
            let remaining = MAX_RPC_RESPONSE_BYTES.saturating_sub(response_body.len());
            let chunk = response
                .chunk(remaining.saturating_add(1) as u64)
                .map_err(|_| format!("{method} response read failed"))?;
            let Some(mut chunk) = chunk else {
                break;
            };
            if remaining == 0 || chunk.len() > remaining {
                return Err(format!("{method} response exceeded the size limit"));
            }
            response_body.append(&mut chunk);
        }
        serde_json::from_slice::<Value>(&response_body)
            .map_err(|_| format!("{method} returned invalid JSON"))
    }

    fn tool_error(message: String) -> Result<ToolResult, String> {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "stake-account brief failed closed",
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
                function_name: "stake_account_brief::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(StakeAccountBrief);
}
