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

    use std::{collections::HashMap, time::Duration};

    use serde::Deserialize;
    use serde_json::{json, Value};

    use crate::risk::{
        append_bounded_body, assess, parse_holder_accounts, parse_largest_token_accounts,
        parse_lp_security, parse_market_pairs, parse_mint_account, render_report, validate_mint,
        RiskConfig, RiskEvidence, MAX_HTTP_BODY_BYTES,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token-risk-check";
    const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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

            let mint_response = match rpc_with_fallback(
                &cfg,
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
            let (lp_security, lp_security_error) = if cfg.require_lp_status {
                gather_lp_security(&cfg, &parsed.mint)
            } else {
                (None, None)
            };
            let evidence = RiskEvidence {
                mint,
                holders,
                holders_error,
                market,
                market_error,
                lp_security,
                lp_security_error,
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
            let largest = rpc_with_fallback(
                cfg,
                "getTokenLargestAccounts",
                json!([mint, {"commitment":"confirmed"}]),
            )?;
            let addresses = parse_largest_token_accounts(&largest)?;
            let expected_accounts = addresses.len();
            let accounts = rpc_with_fallback(
                cfg,
                "getMultipleAccounts",
                json!([addresses, {"encoding":"jsonParsed","commitment":"confirmed"}]),
            )?;
            parse_holder_accounts(&accounts, expected_accounts, mint)
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
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .send()
                .map_err(|_| "market request failed".to_string())?;
            let status = response.status_code();
            if !(200..300).contains(&status) {
                return Err(format!("market endpoint returned HTTP {status}"));
            }
            let body = bounded_json(&response, "market")?;
            parse_market_pairs(&body, mint)
        })();
        match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        }
    }

    fn gather_lp_security(
        cfg: &RiskConfig,
        mint: &str,
    ) -> (Option<crate::risk::LpEvidence>, Option<String>) {
        let result = (|| {
            let separator = if cfg.security_base_url.contains('?') {
                '&'
            } else {
                '?'
            };
            let url = format!(
                "{}{separator}contract_addresses={mint}",
                cfg.security_base_url
            );
            let response = waki::Client::new()
                .get(&url)
                .header("Accept", "application/json")
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .send()
                .map_err(|_| "LP-security request failed".to_string())?;
            let status = response.status_code();
            if !(200..300).contains(&status) {
                return Err(format!("LP-security endpoint returned HTTP {status}"));
            }
            let body = bounded_json(&response, "LP-security")?;
            parse_lp_security(&body, mint)
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
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .send()
            .map_err(|_| format!("{method} request failed"))?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("{method} returned HTTP {status}"));
        }
        let value = bounded_json(&response, method)?;
        if let Some(error) = value.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            return Err(format!("{method} RPC error {code}"));
        }
        Ok(value)
    }

    fn bounded_json(response: &waki::Response, label: &str) -> Result<Value, String> {
        let mut body = Vec::new();
        loop {
            let chunk = response
                .chunk(64 * 1024)
                .map_err(|_| format!("{label} body read failed"))?;
            let Some(chunk) = chunk else {
                break;
            };
            if chunk.is_empty() {
                break;
            }
            append_bounded_body(&mut body, &chunk, MAX_HTTP_BODY_BYTES)
                .map_err(|_| format!("{label} response exceeded the 1 MiB limit"))?;
        }
        serde_json::from_slice(&body).map_err(|_| format!("{label} returned invalid JSON"))
    }

    fn rpc_with_fallback(cfg: &RiskConfig, method: &str, params: Value) -> Result<Value, String> {
        match rpc(&cfg.rpc_url, method, params.clone()) {
            Ok(value) => Ok(value),
            Err(primary_error) => {
                let Some(fallback_url) = &cfg.rpc_fallback_url else {
                    return Err(primary_error);
                };
                rpc(fallback_url, method, params).map_err(|fallback_error| {
                    format!("{primary_error}; fallback failed: {fallback_error}")
                })
            }
        }
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
