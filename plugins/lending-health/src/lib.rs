//! Lending health tool plugin for ZeroClaw: read-only Kamino lending position
//! health for a Solana wallet.
//!
//! v0.1: HTTP against Kamino's public API. Two round trips per invocation:
//! one users/obligations lookup, then one metrics/history per obligation.
//! v0.2 (planned): swap HTTP for on-chain reads with hand-rolled borsh.
//!
//! The pure parsing and policy core lives in [`lending_health`] with zero
//! wasm or HTTP dependency, so it compiles and tests on the host with plain
//! `cargo test`. The wasm component below reuses that logic through a thin
//! shim: validate arguments, discover obligations, fetch metrics, aggregate.
//! It cannot sign or submit a transaction, and never accepts an endpoint
//! from tool arguments.

pub mod lending_health;

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

    use crate::lending_health::{
        aggregate_positions, analyze, metrics_history_url, parse_metrics_history_response,
        parse_user_obligations_response, render_report, user_obligations_url, validate_pubkey,
        LendingConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "lending-health";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        wallet: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct LendingHealth;

    impl PluginInfo for LendingHealth {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for LendingHealth {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Check the health of every Kamino Lend position owned by a Solana wallet. \
             Given a base58 wallet public key, discovers the wallet's obligations on \
             the configured Kamino market, fetches each position's latest metrics, \
             and returns a compact green/amber/red report per position plus an \
             overall alert level equal to the worst tier across all positions. \
             Read-only: cannot sign, borrow, repay, deposit, withdraw, or move funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "wallet": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                        "description": "Base58 Solana wallet public key. The plugin looks up all of this wallet's Kamino Lend obligations on the configured market."
                    }
                },
                "required": ["wallet"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return tool_error(format!("invalid arguments: {error}")),
            };

            if let Err(error) = validate_pubkey(&parsed.wallet) {
                return tool_error(format!("wallet: {error}"));
            }

            let config = match LendingConfig::from_section(&parsed.config) {
                Ok(config) => config,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "discovering Kamino obligations for wallet",
            );

            let obligations_url = user_obligations_url(
                &config.api_base_url,
                &config.market_pubkey,
                &parsed.wallet,
                &config.env,
            );
            let obligations_json = match get_json(&obligations_url) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };
            let obligation_addresses = match parse_user_obligations_response(&obligations_json) {
                Ok(list) => list,
                Err(error) => return tool_error(error),
            };

            let mut positions = Vec::with_capacity(obligation_addresses.len());
            for obligation in &obligation_addresses {
                emit(
                    PluginAction::Query,
                    PluginOutcome::Success,
                    "fetching obligation metrics",
                );
                let metrics_url = metrics_history_url(
                    &config.api_base_url,
                    &config.market_pubkey,
                    obligation,
                    &config.env,
                );
                let metrics_json = match get_json(&metrics_url) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
                let snapshot = match parse_metrics_history_response(&metrics_json, obligation) {
                    Ok(value) => value,
                    Err(error) => return tool_error(error),
                };
                positions.push(analyze(obligation, &snapshot, &config));
            }

            let report = aggregate_positions(&parsed.wallet, &config, positions);
            let output = match render_report(&report) {
                Ok(value) => value,
                Err(error) => return tool_error(error),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "lending health check completed",
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn get_json(url: &str) -> Result<Value, String> {
        waki::Client::new()
            .get(url)
            .send()
            .map_err(|error| format!("Kamino API request failed: {error}"))?
            .json::<Value>()
            .map_err(|error| format!("Kamino API returned invalid JSON: {error}"))
    }

    fn tool_error(message: String) -> Result<ToolResult, String> {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "lending health check failed closed",
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
                function_name: "lending_health::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(LendingHealth);
}
