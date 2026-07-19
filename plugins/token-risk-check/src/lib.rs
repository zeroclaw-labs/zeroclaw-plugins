//! ZeroClaw `token-risk-check` tool plugin.
//!
//! Custody tier T0: the component performs read-only Solana JSON-RPC and
//! market-data requests. It cannot construct, sign, or submit transactions and
//! never accepts a private key. The only LLM-controlled input is a base58 mint,
//! validated as a 32-byte public key before any request leaves the sandbox.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde::Deserialize;
    use serde_json::{json, Value};

    use crate::risk::{
        assess, parse_holder_accounts, parse_largest_token_accounts, parse_market_pairs,
        parse_mint_account, render_report, validate_mint, RiskConfig, RiskEvidence,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token-risk-check";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct TokenRiskCheck;

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read-only Solana token risk check. Given a mint public key, inspect mint/freeze authority, Token-2022 transfer fees/hooks/permanent delegate, owner-level holder concentration, and DEX liquidity. Returns compact red/amber/green evidence. Never signs or submits transactions."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "mint": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "pattern": "^[1-9A-HJ-NP-Za-km-z]+$",
                        "description": "Solana SPL or Token-2022 mint public key."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return failure("INVALID_ARGUMENTS", &error.to_string()),
            };
            if let Err(error) = validate_mint(&parsed.mint) {
                return failure("INVALID_MINT", &error);
            }
            let cfg = match RiskConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return failure("INVALID_CONFIG", &error),
            };

            let mint_response = match rpc(
                &cfg.rpc_url,
                "getAccountInfo",
                json!([parsed.mint, {"encoding":"jsonParsed","commitment":"confirmed"}]),
            ) {
                Ok(value) => value,
                Err(error) => return failure("MINT_RPC_FAILED", &error),
            };
            let mint = match parse_mint_account(&mint_response) {
                Ok(value) => value,
                Err(error) => return failure("MINT_PARSE_FAILED", &error),
            };

            let (holders, holders_error) = gather_holders(&cfg, &parsed.mint);
            let (market, market_error) = if cfg.require_market_data {
                gather_market(&cfg, &parsed.mint)
            } else {
                (None, None)
            };
            let evidence = RiskEvidence {
                mint,
                holders,
                holders_error,
                market,
                market_error,
            };
            let report = assess(&parsed.mint, &evidence, &cfg);
            let output = match render_report(&report) {
                Ok(value) => value,
                Err(error) => return failure("RENDER_FAILED", &error),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "risk check complete",
                Some(json!({
                    "rating": report.rating,
                    "score": report.score,
                    "complete": report.complete
                })),
            );
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn gather_holders(
        cfg: &RiskConfig,
        mint: &str,
    ) -> (Option<crate::risk::HolderEvidence>, Option<String>) {
        let result = (|| {
            let largest = rpc(
                &cfg.rpc_url,
                "getTokenLargestAccounts",
                json!([mint, {"commitment":"confirmed"}]),
            )?;
            let addresses = parse_largest_token_accounts(&largest)?;
            let accounts = rpc(
                &cfg.rpc_url,
                "getMultipleAccounts",
                json!([addresses, {"encoding":"jsonParsed","commitment":"confirmed"}]),
            )?;
            parse_holder_accounts(&accounts)
        })();
        match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        }
    }

    fn gather_market(
        cfg: &RiskConfig,
        mint: &str,
    ) -> (Option<crate::risk::MarketEvidence>, Option<String>) {
        let result = (|| {
            let url = format!("{}/{}", cfg.market_base_url, mint);
            let response = waki::Client::new()
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .map_err(|error| format!("market request failed: {error}"))?;
            let status = response.status_code();
            if !(200..300).contains(&status) {
                return Err(format!("market endpoint returned HTTP {status}"));
            }
            let body = response
                .json::<Value>()
                .map_err(|error| format!("market JSON failed: {error}"))?;
            parse_market_pairs(&body)
        })();
        match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        }
    }

    fn rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let response = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|error| format!("{method} request failed: {error}"))?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("{method} returned HTTP {status}"));
        }
        response
            .json::<Value>()
            .map_err(|error| format!("{method} JSON failed: {error}"))
    }

    fn failure(code: &str, detail: &str) -> Result<ToolResult, String> {
        emit(PluginAction::Fail, PluginOutcome::Failure, code, None);
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(format!("{code}: {detail}")),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<Value>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: attrs.map(|value| value.to_string()),
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
