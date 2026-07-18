//! Read-only Solana program upgrade-authority inspection for ZeroClaw.

pub mod program_authority;

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

    use crate::program_authority::{
        account_request, build_report, inspect_program_account, parse_account_response,
        parse_programdata, render_report, validate_pubkey, ProgramAuthorityConfig, ProgramLoader,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "program-authority";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        program_id: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct ProgramAuthority;

    impl PluginInfo for ProgramAuthority {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for ProgramAuthority {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Inspect a Solana executable account and report its loader, ProgramData address, \
             deployment slot, and current upgrade authority. Read-only: cannot sign, deploy, \
             upgrade, close, or move funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "program_id": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                        "description": "Base58 Solana executable program address."
                    }
                },
                "required": ["program_id"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return tool_error(format!("invalid arguments: {error}")),
            };
            if let Err(error) = validate_pubkey(&parsed.program_id, "program_id") {
                return tool_error(error);
            }
            let config = match ProgramAuthorityConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "querying program account",
            );
            let program_json = match post_json(
                &config.rpc_url,
                &account_request(&parsed.program_id, 1, &config.commitment),
            ) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let account = match parse_account_response(&program_json, &parsed.program_id) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let loader = match inspect_program_account(&account) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            let programdata = if let ProgramLoader::Upgradeable {
                programdata_address,
            } = &loader
            {
                let programdata_json = match post_json(
                    &config.rpc_url,
                    &account_request(programdata_address, 2, &config.commitment),
                ) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
                let programdata_account =
                    match parse_account_response(&programdata_json, programdata_address) {
                        Ok(value) => value,
                        Err(error) => return tool_error(error),
                    };
                match parse_programdata(&programdata_account) {
                    Ok(value) => Some(value),
                    Err(error) => return tool_error(error),
                }
            } else {
                None
            };

            let report =
                match build_report(&parsed.program_id, &account, &loader, programdata.as_ref()) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
            let output = match render_report(&report) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "program authority report completed",
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
            "program authority inspection failed closed",
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
                function_name: "program_authority::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(ProgramAuthority with_types_in self);
}
