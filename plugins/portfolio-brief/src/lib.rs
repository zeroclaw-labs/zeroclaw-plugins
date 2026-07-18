//! ZeroClaw `portfolio-brief` tool plugin.
//!
//! The pure parsing, validation, and rendering logic lives in [`portfolio`].
//! This module only wires that core to the tool-plugin WIT world and performs
//! the three read-only HTTP queries required for a portfolio snapshot.

pub mod portfolio;

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

    use crate::portfolio::{
        balance_request, merge_holdings, parse_balance_response, parse_price_response,
        parse_token_accounts_response, price_url, render_brief, select_price_mints,
        token_accounts_request, validate_pubkey, PortfolioConfig, TOKEN_2022_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "portfolio-brief";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Deserialize)]
    struct ExecuteArgs {
        wallet: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct PortfolioBrief;

    impl PluginInfo for PortfolioBrief {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for PortfolioBrief {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Create a compact, read-only Solana wallet brief with SOL and SPL token balances, USD values, and 24-hour price changes. Never signs or submits transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "wallet": {
                        "type": "string",
                        "description": "Base58 Solana wallet public key to inspect."
                    }
                },
                "required": ["wallet"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            match execute_inner(&args) {
                Ok((output, positions, priced)) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "portfolio brief created",
                        Some(format!("{{\"positions\":{positions},\"priced\":{priced}}}")),
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
                        "portfolio brief failed",
                        None,
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

    fn execute_inner(args: &str) -> Result<(String, usize, usize), String> {
        let parsed: ExecuteArgs =
            serde_json::from_str(args).map_err(|e| format!("invalid arguments: {e}"))?;
        validate_pubkey(&parsed.wallet)?;
        let cfg = PortfolioConfig::from_section(&parsed.config)?;

        let lamports =
            parse_balance_response(&post_json(&cfg.rpc_url, &balance_request(&parsed.wallet))?)?;

        let legacy = parse_token_accounts_response(&post_json(
            &cfg.rpc_url,
            &token_accounts_request(&parsed.wallet, TOKEN_PROGRAM_ID),
        )?)?;
        let token_2022 = parse_token_accounts_response(&post_json(
            &cfg.rpc_url,
            &token_accounts_request(&parsed.wallet, TOKEN_2022_PROGRAM_ID),
        )?)?;

        let holdings = merge_holdings(lamports, legacy.into_iter().chain(token_2022));
        let price_mints = select_price_mints(&holdings, cfg.max_price_ids);
        let prices = if price_mints.is_empty() {
            HashMap::new()
        } else {
            let url = price_url(&cfg.price_api_url, &price_mints)?;
            parse_price_response(&get_json(&url, &cfg.jupiter_api_key)?)?
        };

        let priced = holdings
            .iter()
            .filter(|holding| prices.contains_key(&holding.mint))
            .count();
        let output = render_brief(
            &parsed.wallet,
            &holdings,
            &prices,
            &cfg.labels,
            cfg.max_positions,
        );
        Ok((output, holdings.len(), priced))
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?
            .json::<Value>()
            .map_err(|e| format!("RPC returned invalid JSON: {e}"))
    }

    fn get_json(url: &str, api_key: &str) -> Result<Value, String> {
        let mut request = waki::Client::new()
            .get(url)
            .header("Accept", "application/json");
        if !api_key.is_empty() {
            request = request.header("x-api-key", api_key);
        }
        request
            .send()
            .map_err(|e| format!("price request failed: {e}"))?
            .json::<Value>()
            .map_err(|e| format!("price API returned invalid JSON: {e}"))
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<String>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "portfolio_brief::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(PortfolioBrief);
}
