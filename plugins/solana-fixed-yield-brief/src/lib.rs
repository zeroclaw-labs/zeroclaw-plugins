//! ZeroClaw T0 tool plugin: `solana-fixed-yield-brief`.
//!
//! The pure, host-testable market selection and scoring core lives in
//! [`brief`]. This file contains only the wasm component shim and fixed HTTPS
//! transport. The plugin has no wallet permission, accepts no endpoint URL,
//! and cannot construct, sign, or submit a transaction.

pub mod brief;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::Value;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::brief::{generate_brief, BriefArgs, MarketDataSource};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-fixed-yield-brief";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const VAULTS_URL: &str = "https://app.exponent.finance/api/vaults?is_active=true";
    const SY_TOKENS_URL: &str = "https://app.exponent.finance/api/sy-tokens";
    const QUOTE_URL: &str = "https://quote.exponent.finance/quote";
    const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const HTTP_CHUNK_BYTES: u64 = 64 * 1024;
    const VAULTS_MAX_BYTES: usize = 2 * 1024 * 1024;
    const SY_TOKENS_MAX_BYTES: usize = 1024 * 1024;
    const QUOTE_MAX_BYTES: usize = 256 * 1024;

    struct ExponentSource;

    impl MarketDataSource for ExponentSource {
        fn now_unix_seconds(&self) -> Result<u64, String> {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .map_err(|_| "system time predates Unix epoch".to_string())
        }

        fn vaults(&self) -> Result<Value, String> {
            get_json(VAULTS_URL, VAULTS_MAX_BYTES)
        }

        fn sy_tokens(&self) -> Result<Value, String> {
            get_json(SY_TOKENS_URL, SY_TOKENS_MAX_BYTES)
        }

        fn quote(&self, request: &Value) -> Result<Value, String> {
            post_json(QUOTE_URL, request, QUOTE_MAX_BYTES)
        }
    }

    fn get_json(url: &str, max_bytes: usize) -> Result<Value, String> {
        let response = waki::Client::new()
            .get(url)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;
        response_json_limited(response, max_bytes)
    }

    fn post_json(url: &str, body: &Value, max_bytes: usize) -> Result<Value, String> {
        let response = waki::Client::new()
            .post(url)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .json(body)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;
        response_json_limited(response, max_bytes)
    }

    fn response_json_limited(response: waki::Response, max_bytes: usize) -> Result<Value, String> {
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(format!("HTTP status {status}"));
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk(HTTP_CHUNK_BYTES)
            .map_err(|e| format!("response read failed: {e}"))?
        {
            let new_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| "response size overflow".to_string())?;
            if new_len > max_bytes {
                return Err(format!("response exceeds {max_bytes}-byte safety limit"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| format!("invalid JSON response: {e}"))
    }

    struct SolanaFixedYieldBrief;

    impl PluginInfo for SolanaFixedYieldBrief {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaFixedYieldBrief {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Read-only Solana fixed-yield scout. Fetches live Exponent PT router quotes for a \
             normalized SOL notional, subtracts estimated non-market costs, compares maturity \
             return with a staking hurdle, and returns a compact risk-labelled brief. It cannot \
             acquire the underlying base token, sign, or trade."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "sol_notional_lamports": {
                        "type": "integer",
                        "minimum": 1_000_000,
                        "maximum": 10_000_000_000_000_u64,
                        "description": "SOL-denominated normalized quote notional in lamports; not proof that the underlying base-token leg is funded."
                    },
                    "hurdle_apy_bps": {
                        "type": "integer",
                        "minimum": 100,
                        "maximum": 100_000,
                        "default": 550,
                        "description": "Alternative annual yield in basis points; for example 550 means 5.50%."
                    },
                    "execution_cost_lamports": {
                        "type": "integer",
                        "minimum": 100_000,
                        "default": 1_000_000,
                        "description": "Estimated total of base-token acquisition/redemption, entry, priority, tip, and other non-market costs."
                    },
                    "minimum_excess_lamports": {
                        "type": "integer",
                        "minimum": 1_000_000,
                        "default": 1_000_000,
                        "description": "Minimum projected normalized term advantage required for the floor-met label."
                    },
                    "minimum_tvl_multiple": {
                        "type": "integer",
                        "minimum": 20,
                        "maximum": 1_000,
                        "default": 20,
                        "description": "Require reported SOL-denominated TVL to be at least this multiple of quote notional."
                    },
                    "max_results": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 3,
                        "default": 3
                    }
                },
                "required": ["sol_notional_lamports"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: BriefArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(_) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                        None,
                    );
                    return Ok(failure(
                        "invalid arguments: expected the published JSON schema",
                    ));
                }
            };

            match generate_brief(&ExponentSource, &parsed) {
                Ok(report) => {
                    emit(
                        PluginAction::Query,
                        PluginOutcome::Success,
                        "fixed-yield brief generated",
                        Some(report.quotes_succeeded),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report.output,
                        error: None,
                    })
                }
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "fixed-yield brief failed",
                        None,
                    );
                    Ok(failure(&error))
                }
            }
        }
    }

    fn failure(message: &str) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message.to_string()),
        }
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        quotes_succeeded: Option<usize>,
    ) {
        let attrs = quotes_succeeded.map(|n| format!("{{\"quotes_succeeded\":{n}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_fixed_yield_brief::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaFixedYieldBrief);
}
