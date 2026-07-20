//! A policy-gated ZeroClaw tool that builds unsigned Realms vote transactions.
//!
//! All validation and transaction-envelope checks live in [`vote_build`]. The
//! wasm component only injects jailed operator config and provides `wasi:http`.

pub mod vote_build;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::vote_build::{build_vote, HttpClient, VoteBuildArgs, VoteBuildConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde_json::Value;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "governance-vote-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "governance_vote_build";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        realm: String,
        proposal: String,
        wallet: String,
        vote: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct WakiHttp;

    impl HttpClient for WakiHttp {
        fn get_json(&mut self, url: &str) -> Result<Value, String> {
            waki::Client::new()
                .get(url)
                .send()
                .map_err(|e| format!("Realms request failed: {e}"))?
                .json::<Value>()
                .map_err(|e| format!("Realms returned invalid JSON: {e}"))
        }

        fn post_json(&mut self, url: &str, body: &Value) -> Result<Value, String> {
            waki::Client::new()
                .post(url)
                .json(body)
                .send()
                .map_err(|e| format!("Realms request failed: {e}"))?
                .json::<Value>()
                .map_err(|e| format!("Realms returned invalid JSON: {e}"))
        }
    }

    struct GovernanceVoteBuild;

    impl PluginInfo for GovernanceVoteBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for GovernanceVoteBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an unsigned Realms governance vote transaction for an operator-allowlisted DAO \
             and vote kind. Never holds keys, signs, sends, or enables paid account creation."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "realm": {
                        "type": "string",
                        "description": "Allowlisted Realms DAO public key."
                    },
                    "proposal": {
                        "type": "string",
                        "description": "Proposal public key in the DAO."
                    },
                    "wallet": {
                        "type": "string",
                        "description": "Public key of the wallet that will review and sign externally."
                    },
                    "vote": {
                        "type": "string",
                        "enum": ["approve", "deny", "abstain", "veto"],
                        "description": "Operator-allowlisted vote kind to build."
                    }
                },
                "required": ["realm", "proposal", "wallet", "vote"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return Ok(failure(format!("invalid arguments: {error}"))),
            };
            let config = match VoteBuildConfig::from_section(&parsed.config) {
                Ok(config) => config,
                Err(error) => return Ok(failure(error)),
            };
            let build_args = VoteBuildArgs {
                realm: parsed.realm,
                proposal: parsed.proposal,
                wallet: parsed.wallet,
                vote: parsed.vote,
            };

            match build_vote(&mut WakiHttp, &build_args, &config) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built unsigned governance vote transaction",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(error) => Ok(failure(error)),
            }
        }
    }

    fn failure(error: String) -> ToolResult {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "governance vote build rejected",
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "governance_vote_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(GovernanceVoteBuild);
}
