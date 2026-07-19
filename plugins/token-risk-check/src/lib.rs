//! ZeroClaw T0 tool plugin: `token-risk-check`.
//!
//! Reads a Solana mint, its largest token accounts, and optional public DEX
//! liquidity evidence. It never signs, submits, builds, or simulates a transaction.
//! The pure scoring core lives in [`risk`] and is host-tested without WASM.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::{json, Value};

    use crate::risk::{
        assess, compact_json, validate_mint_address, ExtensionObservation, LiquiditySnapshot,
        RiskInput, TokenProgram, Verdict,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
    const DEFAULT_DEX_URL: &str = "https://api.dexscreener.com/token-pairs/v1/solana";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(default = "default_true")]
        include_liquidity: bool,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn default_true() -> bool {
        true
    }

    #[derive(Clone)]
    struct Config {
        rpc_url: String,
        dex_url: String,
    }

    impl Config {
        fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
            let rpc_url = section
                .get("rpc_url")
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
            let dex_url = section
                .get("dex_url")
                .cloned()
                .unwrap_or_else(|| DEFAULT_DEX_URL.to_string());
            validate_endpoint(&rpc_url, "rpc_url")?;
            validate_endpoint(&dex_url, "dex_url")?;
            Ok(Self {
                rpc_url: rpc_url.trim_end_matches('/').to_string(),
                dex_url: dex_url.trim_end_matches('/').to_string(),
            })
        }
    }

    /// HTTPS is mandatory except for an explicitly configured loopback RPC.
    /// The LLM cannot set these URLs; only the jailed operator config can.
    fn validate_endpoint(url: &str, field: &str) -> Result<(), String> {
        let allowed = url.starts_with("https://")
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost")
            || url.starts_with("http://[::1]");
        if !allowed || url.contains('@') || url.contains('#') {
            return Err(format!(
                "{field} must be HTTPS or an explicit loopback HTTP endpoint"
            ));
        }
        Ok(())
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
            PLUGIN_NAME.to_string()
        }

        fn description() -> String {
            "Read-only Solana token risk check. Reports live mint/freeze authority, holder \
             concentration, dangerous Token-2022 extensions, and public DEX liquidity. \
             Never signs or moves funds; incomplete evidence cannot return green."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "One base58 Solana mint public key. Never a URL, prompt, or private key."
                    },
                    "include_liquidity": {
                        "type": "boolean",
                        "default": true,
                        "description": "Query public DEX pair liquidity evidence."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(error) => return Ok(failure(format!("invalid arguments: {error}"))),
            };

            if let Err(error) = validate_mint_address(&parsed.mint) {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "rejected invalid mint input",
                    None,
                );
                return Ok(failure(error));
            }

            let config = match Config::from_section(&parsed.config) {
                Ok(config) => config,
                Err(error) => return Ok(failure(error)),
            };

            let mut input = match fetch_mint(&config.rpc_url, &parsed.mint) {
                Ok(input) => input,
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "mint RPC check failed",
                        None,
                    );
                    return Ok(failure(error));
                }
            };

            input.largest_accounts = fetch_largest_accounts(&config.rpc_url, &parsed.mint).ok();
            input.liquidity = if parsed.include_liquidity {
                fetch_liquidity(&config.dex_url, &parsed.mint).ok()
            } else {
                None
            };

            let report = assess(&input);
            let output = compact_json(&report)
                .map_err(|error| format!("could not serialize risk report: {error}"))?;
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "completed read-only token risk check",
                Some(format!(
                    "{{\"verdict\":\"{:?}\",\"score\":{}}}",
                    report.verdict, report.score
                )),
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn failure(error: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    fn rpc_call(url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response: Value = waki::Client::new()
            .post(url)
            .json(&body)
            .send()
            .map_err(|error| format!("{method} request failed: {error}"))?
            .json()
            .map_err(|error| format!("{method} returned invalid JSON: {error}"))?;

        if let Some(error) = response.get("error") {
            return Err(format!("{method} RPC error: {error}"));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method} response has no result"))
    }

    fn fetch_mint(rpc_url: &str, mint: &str) -> Result<RiskInput, String> {
        let result = rpc_call(
            rpc_url,
            "getAccountInfo",
            json!([mint, {"encoding": "jsonParsed", "commitment": "confirmed"}]),
        )?;
        let account = result
            .get("value")
            .filter(|value| !value.is_null())
            .ok_or_else(|| "mint account does not exist".to_string())?;
        let owner = account
            .get("owner")
            .and_then(Value::as_str)
            .ok_or_else(|| "mint account has no owner".to_string())?;
        let program = match owner {
            TOKEN_PROGRAM => TokenProgram::Legacy,
            TOKEN_2022_PROGRAM => TokenProgram::Token2022,
            _ => return Err("account is not owned by an SPL Token program".to_string()),
        };

        let parsed = account
            .pointer("/data/parsed")
            .ok_or_else(|| "RPC did not return jsonParsed mint data".to_string())?;
        if parsed.get("type").and_then(Value::as_str) != Some("mint") {
            return Err("address is not a parsed mint account".to_string());
        }
        let info = parsed
            .get("info")
            .and_then(Value::as_object)
            .ok_or_else(|| "parsed mint has no info object".to_string())?;

        let supply = info
            .get("supply")
            .and_then(Value::as_str)
            .ok_or_else(|| "parsed mint has no supply".to_string())?
            .parse::<u64>()
            .map_err(|_| "parsed mint supply is out of range".to_string())?;
        let decimals = info
            .get("decimals")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| "parsed mint has invalid decimals".to_string())?;
        let initialized = info
            .get("isInitialized")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let extensions = info
            .get("extensions")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(parse_extension).collect())
            .unwrap_or_default();

        Ok(RiskInput {
            mint: mint.to_string(),
            program,
            initialized,
            supply,
            decimals,
            mint_authority: optional_string(info.get("mintAuthority")),
            freeze_authority: optional_string(info.get("freezeAuthority")),
            extensions,
            largest_accounts: None,
            liquidity: None,
        })
    }

    fn optional_string(value: Option<&Value>) -> Option<String> {
        value
            .filter(|value| !value.is_null())
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    fn parse_extension(value: &Value) -> Option<ExtensionObservation> {
        let kind = value
            .get("extension")
            .or_else(|| value.get("type"))
            .and_then(Value::as_str)?
            .to_string();
        Some(ExtensionObservation {
            kind,
            authority: find_authority(value),
        })
    }

    fn find_authority(value: &Value) -> Option<String> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if key.to_ascii_lowercase().contains("authority") {
                        if let Some(authority) = child.as_str().filter(|value| !value.is_empty()) {
                            return Some(authority.to_string());
                        }
                    }
                }
                map.values().find_map(find_authority)
            }
            Value::Array(items) => items.iter().find_map(find_authority),
            _ => None,
        }
    }

    fn fetch_largest_accounts(rpc_url: &str, mint: &str) -> Result<Vec<u64>, String> {
        let result = rpc_call(
            rpc_url,
            "getTokenLargestAccounts",
            json!([mint, {"commitment": "confirmed"}]),
        )?;
        let values = result
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| "largest-account response has no value array".to_string())?;
        let mut accounts = Vec::with_capacity(values.len().min(20));
        for value in values.iter().take(20) {
            let amount = value
                .get("amount")
                .and_then(Value::as_str)
                .and_then(|amount| amount.parse::<u64>().ok())
                .ok_or_else(|| "largest-account response has invalid amount".to_string())?;
            accounts.push(amount);
        }
        Ok(accounts)
    }

    fn fetch_liquidity(dex_url: &str, mint: &str) -> Result<LiquiditySnapshot, String> {
        let url = format!("{dex_url}/{mint}");
        let response: Value = waki::Client::new()
            .get(&url)
            .send()
            .map_err(|error| format!("liquidity request failed: {error}"))?
            .json()
            .map_err(|error| format!("liquidity endpoint returned invalid JSON: {error}"))?;
        let pairs = response
            .as_array()
            .ok_or_else(|| "liquidity endpoint did not return a pair array".to_string())?;

        let mut max_usd = None::<f64>;
        let mut top_pair = None::<String>;
        for pair in pairs.iter().take(50) {
            let usd = pair.pointer("/liquidity/usd").and_then(Value::as_f64);
            if let Some(usd) = usd {
                if max_usd.map(|current| usd > current).unwrap_or(true) {
                    max_usd = Some(usd);
                    top_pair = pair
                        .get("pairAddress")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                }
            }
        }

        Ok(LiquiditySnapshot {
            pair_count: pairs.len(),
            max_usd,
            top_pair,
            source: "dexscreener".to_string(),
        })
    }

    fn emit(
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        attrs: Option<String>,
    ) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
