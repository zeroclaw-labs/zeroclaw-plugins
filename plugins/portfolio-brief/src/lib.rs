//! A ZeroClaw WIT tool plugin: `portfolio_brief`.
//!
//! Given a wallet address, it returns a compact, model-sized brief of that
//! wallet's holdings: native SOL and SPL / Token-2022 balances, each valued in
//! USD with a 24h price delta, sorted by value, with dust summarized rather than
//! listed. It is built to feed a daily-briefing SOP without nuking the agent's
//! context window (trap #3).
//!
//! ## Custody tier: T0 (read-only)
//!
//! The tool holds no key and signs nothing. Its capabilities are `http_client`
//! (read-only JSON-RPC to the operator's Solana endpoint + a price API) and
//! `config_read` (to learn those endpoints). No code path builds, signs, or
//! submits a transaction. The only model-controlled input is the `owner`
//! address, strictly validated before any I/O.
//!
//! The pure shaping lives in [`brief`] (no wasm/http deps) and is covered by host
//! `cargo test`; this shim only does the RPC/HTTP I/O.

pub mod brief;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::{json, Value};
    use solana_core::shape::{abbrev_addr, ui_amount};
    use solana_core::token_account::parse_token_account;
    use solana_core::{base58, mint, programs, rpc};

    use crate::brief::{self, Holding};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PortfolioBrief;

    const PLUGIN_NAME: &str = "portfolio-brief";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "portfolio_brief";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
    const DEFAULT_PRICE_API: &str = "https://lite-api.jup.ag/price/v3";
    const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
    const SOL_DECIMALS: u8 = 9;
    const MAX_LINES: usize = 10;
    /// getMultipleAccounts and the price API both cap around 100 ids per call.
    const MAX_MINTS: usize = 100;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        /// The wallet to summarize. The only model-controlled input.
        owner: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// Price + 24h change for one mint.
    #[derive(Clone, Copy)]
    struct Price {
        usd: f64,
        change_24h: Option<f64>,
    }

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
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Summarize a Solana wallet's holdings by its address: native SOL and \
             SPL / Token-2022 token balances, each valued in USD with a 24h change, \
             sorted by value with dust summarized. Compact output for a daily \
             briefing. Read-only; never moves funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "owner": {
                        "type": "string",
                        "description": "The wallet address to summarize (base58)."
                    }
                },
                "required": ["owner"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };

            let owner = parsed.owner.trim();
            if let Err(e) = base58::decode(owner) {
                emit(
                    PluginAction::Reject,
                    PluginOutcome::Failure,
                    "rejected non-address input",
                );
                return Ok(fail(format!(
                    "`{owner}` is not a valid wallet address: {e}"
                )));
            }

            let rpc_url = cfg_or(&parsed.config, "rpc_url", DEFAULT_RPC_URL);
            let price_api = cfg_or(&parsed.config, "price_api_url", DEFAULT_PRICE_API);

            match build_brief(&rpc_url, &price_api, owner) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "built portfolio brief",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "brief failed");
                    Ok(fail(e))
                }
            }
        }
    }

    fn build_brief(rpc_url: &str, price_api: &str, owner: &str) -> Result<String, String> {
        // 1. Token balances from both token programs.
        let mut balances: Vec<(String, u64)> = Vec::new();
        for program in [programs::SPL_TOKEN, programs::SPL_TOKEN_2022] {
            balances.extend(fetch_token_balances(rpc_url, owner, program)?);
        }

        // 2. Native SOL.
        let lamports = fetch_sol_lamports(rpc_url, owner).unwrap_or(0);

        // 3. Unique mints (capped), then decimals + prices for them (+ wSOL).
        let mut mints: Vec<String> = balances.iter().map(|(m, _)| m.clone()).collect();
        mints.sort();
        mints.dedup();
        let truncated = mints.len() > MAX_MINTS;
        mints.truncate(MAX_MINTS);

        let decimals = fetch_decimals(rpc_url, &mints).unwrap_or_default();

        let mut price_ids = mints.clone();
        price_ids.push(WSOL_MINT.to_string());
        let prices = fetch_prices(price_api, &price_ids).unwrap_or_default();

        // 4. Assemble holdings.
        let mut holdings: Vec<Holding> = Vec::new();

        if lamports > 0 {
            let amount = ui_amount(lamports, SOL_DECIMALS);
            let price = prices.get(WSOL_MINT).copied();
            holdings.push(Holding {
                label: "SOL".to_string(),
                ui_amount: amount,
                usd_value: price.map(|p| amount * p.usd),
                change_24h_pct: price.and_then(|p| p.change_24h),
            });
        }

        for (mint_addr, raw) in &balances {
            // Decimals are required to value or display a balance correctly; a
            // mint we could not decode is counted as unpriced, never shown wrong.
            let Some(&dec) = decimals.get(mint_addr) else {
                holdings.push(unpriced(mint_addr));
                continue;
            };
            let amount = ui_amount(*raw, dec);
            let price = prices.get(mint_addr).copied();
            holdings.push(Holding {
                label: symbol_of(mint_addr).unwrap_or_else(|| abbrev_addr(mint_addr)),
                ui_amount: amount,
                usd_value: price.map(|p| amount * p.usd),
                change_24h_pct: price.and_then(|p| p.change_24h),
            });
        }

        let built = brief::build(holdings, MAX_LINES);
        let mut out = brief::render(owner, &built);
        if truncated {
            out.push_str(&format!(
                "\n(note: wallet holds more than {MAX_MINTS} token mints; showing the first {MAX_MINTS})"
            ));
        }
        Ok(out)
    }

    /// getTokenAccountsByOwner for one program; returns (mint, raw_amount) for
    /// non-zero balances only.
    fn fetch_token_balances(
        rpc_url: &str,
        owner: &str,
        program: &str,
    ) -> Result<Vec<(String, u64)>, String> {
        let result = rpc_call(
            rpc_url,
            "getTokenAccountsByOwner",
            rpc::get_token_accounts_by_owner_params(owner, program),
        )?;
        let value = rpc::value_field(&result)?;
        let arr = value
            .as_array()
            .ok_or("token accounts value is not an array")?;

        let mut out = Vec::new();
        for entry in arr {
            let data_field = match entry.get("account").and_then(|a| a.get("data")) {
                Some(d) => d,
                None => continue,
            };
            let bytes = match rpc::decode_account_data(data_field) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(acct) = parse_token_account(&bytes) {
                if acct.amount > 0 {
                    out.push((acct.mint_str(), acct.amount));
                }
            }
        }
        Ok(out)
    }

    /// getBalance -> native SOL lamports.
    fn fetch_sol_lamports(rpc_url: &str, owner: &str) -> Option<u64> {
        let result = rpc_call(
            rpc_url,
            "getBalance",
            json!([owner, { "commitment": "confirmed" }]),
        )
        .ok()?;
        rpc::value_field(&result).ok()?.as_u64()
    }

    /// getMultipleAccounts -> mint decimals for each decodable mint.
    fn fetch_decimals(rpc_url: &str, mints: &[String]) -> Option<HashMap<String, u8>> {
        if mints.is_empty() {
            return Some(HashMap::new());
        }
        let result = rpc_call(
            rpc_url,
            "getMultipleAccounts",
            json!([mints, { "encoding": "base64", "commitment": "confirmed" }]),
        )
        .ok()?;
        let arr = rpc::value_field(&result).ok()?.as_array()?.clone();

        let mut out = HashMap::new();
        for (i, acct) in arr.iter().enumerate() {
            let Some(mint_addr) = mints.get(i) else {
                break;
            };
            let Ok(bytes) = decode_account_value(acct) else {
                continue;
            };
            if let Ok(m) = mint::parse_mint(&bytes) {
                out.insert(mint_addr.clone(), m.decimals);
            }
        }
        Some(out)
    }

    /// Jupiter price v3: GET ?ids=comma,separated -> { mint: { usdPrice, priceChange24h } }.
    fn fetch_prices(price_api: &str, mints: &[String]) -> Option<HashMap<String, Price>> {
        if mints.is_empty() {
            return Some(HashMap::new());
        }
        let url = format!("{price_api}?ids={}", mints.join(","));
        let body: Value = waki::Client::new().get(&url).send().ok()?.json().ok()?;
        let obj = body.as_object()?;

        let mut out = HashMap::new();
        for (mint_addr, v) in obj {
            if let Some(usd) = v.get("usdPrice").and_then(Value::as_f64) {
                out.insert(
                    mint_addr.clone(),
                    Price {
                        usd,
                        change_24h: v.get("priceChange24h").and_then(Value::as_f64),
                    },
                );
            }
        }
        Some(out)
    }

    /// Decode the base64 `data` of an account object (or null) from
    /// getMultipleAccounts.
    fn decode_account_value(acct: &Value) -> Result<Vec<u8>, String> {
        if acct.is_null() {
            return Err("null account".to_string());
        }
        let data_field = acct.get("data").ok_or("account missing data")?;
        rpc::decode_account_data(data_field)
    }

    fn unpriced(mint_addr: &str) -> Holding {
        Holding {
            label: symbol_of(mint_addr).unwrap_or_else(|| abbrev_addr(mint_addr)),
            ui_amount: 0.0,
            usd_value: None,
            change_24h_pct: None,
        }
    }

    /// One JSON-RPC POST over wasi:http (TLS host-side).
    fn rpc_call(rpc_url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = rpc::request(method, params);
        let response: Value = waki::Client::new()
            .post(rpc_url)
            .json(&body)
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?
            .json()
            .map_err(|e| format!("RPC response was not JSON: {e}"))?;
        rpc::result(&response).cloned()
    }

    fn cfg_or(config: &HashMap<String, String>, key: &str, default: &str) -> String {
        config
            .get(key)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    }

    /// A tiny well-known-mint table so common tokens render with a symbol
    /// instead of an abbreviated address. Everything else falls back to `abcd…wxyz`.
    fn symbol_of(mint_addr: &str) -> Option<String> {
        let sym = match mint_addr {
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => "USDC",
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => "USDT",
            "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" => "BONK",
            "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" => "JUP",
            "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So" => "mSOL",
            "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs" => "ETH",
            _ => return None,
        };
        Some(sym.to_string())
    }

    fn fail(message: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "portfolio_brief::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(PortfolioBrief);
}
