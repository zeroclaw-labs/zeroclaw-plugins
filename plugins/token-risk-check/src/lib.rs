//! ZeroClaw WIT tool plugin: `token-risk-check`.
//!
//! Analyzes any Solana SPL / Token-2022 mint and returns a structured
//! risk verdict (green / amber / red) with human-readable findings.
//! T0 custody tier — read-only RPC calls, zero secrets.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-bindgen-v0"],
    });

    use std::collections::HashMap;

    use crate::risk::{self, HolderInfo};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String { PLUGIN_NAME.to_string() }
        fn plugin_version() -> String { PLUGIN_VERSION.to_string() }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String { TOOL_NAME.to_string() }

        fn description() -> String {
            "Scan any Solana SPL/Token-2022 mint for risks: mint authority, freeze \
             authority, permanent delegate, transfer hooks, transfer fees, holder \
             concentration, and more. Returns green/amber/red verdict with reasons.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {"type": "string", "description": "The SPL token mint address (base58 Pubkey)."}
                },
                "required": ["mint"]
            }).to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    log_record(LogLevel::Error, &PluginEvent {
                        function_name: "token_risk_check::execute".into(),
                        action: PluginAction::Fail, outcome: Some(PluginOutcome::Failure),
                        duration_ms: None, attrs: None, message: format!("invalid arguments: {e}"),
                    });
                    return Ok(ToolResult { success: false, output: String::new(), error: Some(format!("invalid args: {e}")) });
                }
            };

            let rpc_url = parsed.config.get("rpc_url").cloned()
                .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".into());
            let api_key = parsed.config.get("rpc_api_key").cloned();

            // Fetch mint account
            let mint_acct = match fetch_account(&rpc_url, api_key.as_deref(), &parsed.mint) {
                Ok(Some(a)) => a,
                Ok(None) => return Ok(ToolResult { success: false, output: String::new(),
                    error: Some(format!("mint not found: {}", parsed.mint)) }),
                Err(e) => return Ok(ToolResult { success: false, output: String::new(),
                    error: Some(format!("RPC error: {e}")) }),
            };

            let data = match base64_decode(&mint_acct.data) {
                Ok(d) => d,
                Err(e) => return Ok(ToolResult { success: false, output: String::new(),
                    error: Some(format!("base64: {e}")) }),
            };

            let mint_data = match risk::parse_mint(&data, &mint_acct.owner) {
                Ok(m) => m,
                Err(e) => return Ok(ToolResult { success: false, output: String::new(),
                    error: Some(format!("parse: {e}")) }),
            };

            let extensions = risk::scan_extensions(&data);

            let holders = fetch_largest_holders(&rpc_url, api_key.as_deref(), &parsed.mint).unwrap_or_default();

            let report = risk::analyze(&parsed.mint, &mint_data, &extensions, &holders);

            log_record(LogLevel::Info, &PluginEvent {
                function_name: "token_risk_check::execute".into(),
                action: PluginAction::Complete, outcome: Some(PluginOutcome::Success),
                duration_ms: None,
                attrs: Some(serde_json::json!({"score": report.risk_score}).to_string()),
                message: format!("Scanned {} — {:?}", parsed.mint, report.risk_level),
            });

            Ok(ToolResult { success: true, output: serde_json::to_string(&report).unwrap_or_default(), error: None })
        }
    }

    // -- HTTP helpers -------------------------------------------------------

    struct RawAccount { owner: String, data: String }

    fn fetch_account(rpc_url: &str, api_key: Option<&str>, pubkey: &str) -> Result<Option<RawAccount>, String> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":[pubkey,{"encoding":"base64"}]});
        let resp: serde_json::Value = rpc_post(rpc_url, api_key, &body)?;
        let val = resp.get("result").and_then(|r| r.get("value"));
        if val.is_none() || val.and_then(|v| v.as_object()).map(|o| o.is_empty()).unwrap_or(true) {
            return Ok(None);
        }
        let v = val.unwrap();
        let owner = v.get("owner").and_then(|o| o.as_str()).unwrap_or("").to_string();
        let data = v.get("data").and_then(|d| d.as_array())
            .and_then(|a| a.first()).and_then(|s| s.as_str()).unwrap_or("").to_string();
        Ok(Some(RawAccount { owner, data }))
    }

    fn fetch_largest_holders(rpc_url: &str, api_key: Option<&str>, mint: &str) -> Result<Vec<HolderInfo>, String> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getTokenLargestAccounts","params":[mint]});
        let resp: serde_json::Value = rpc_post(rpc_url, api_key, &body)?;
        let arr = resp.get("result").and_then(|r| r.get("value")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let total: f64 = arr.iter().filter_map(|v| v.get("amount").and_then(|a| a.as_str()).and_then(|a| a.parse::<f64>().ok())).sum();
        Ok(arr.iter().map(|v| {
            let amount: u64 = v.get("amount").and_then(|a| a.as_str()).and_then(|a| a.parse().ok()).unwrap_or(0);
            let address = v.get("address").and_then(|a| a.as_str()).unwrap_or("").to_string();
            let pct = if total > 0.0 { (amount as f64 / total) * 100.0 } else { 0.0 };
            HolderInfo { address, amount, percentage: pct }
        }).collect())
    }

    fn rpc_post(url: &str, api_key: Option<&str>, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut headers: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        let auth_val;
        if let Some(key) = api_key { auth_val = format!("Bearer {key}"); headers.push(("Authorization", &auth_val)); }
        waki::Client::new().post(url).headers(headers).json(body).send()
            .map_err(|e| e.to_string())?.json().map_err(|e| e.to_string())
    }

    fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| e.to_string())
    }

    export!(TokenRiskCheck);
}
