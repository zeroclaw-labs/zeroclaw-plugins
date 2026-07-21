//! A ZeroClaw WIT tool component that turns two Solana JSON-RPC read calls into
//! a bounded token-mint safety summary. It decodes canonical mint account data
//! so Token-2022 extension flags are never guessed from a display-oriented RPC
//! response. It is deliberately a T0 plugin: it has no signing code, no wallet
//! connection, and never constructs a transaction.
//!
//! Build: `rustup target add wasm32-wasip2`
//!        `cargo build --target wasm32-wasip2 --release`

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    use std::collections::HashMap;

    use serde::Deserialize;
    use serde_json::{json, Value};

    use crate::risk::{parse_largest_accounts, parse_mint_account, render_summary, validate_mint};

    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-token-risk";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_token_risk";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

    struct SolanaTokenRisk;

    #[derive(Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaTokenRisk {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaTokenRisk {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read a Solana token mint through JSON-RPC and return a bounded, read-only summary of mint/freeze authorities and top token-account concentration. Never signs, sends, or constructs a transaction."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Solana SPL or Token-2022 mint address to inspect."
                    }
                },
                "required": ["mint"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(_) => return Ok(failure("invalid arguments")),
            };
            let mint = match validate_mint(&parsed.mint) {
                Ok(value) => value,
                Err(error) => return Ok(failure(&error)),
            };
            let rpc_url = match configured_rpc_url(&parsed.config) {
                Ok(value) => value,
                Err(error) => return Ok(failure(&error)),
            };

            let account_result = match rpc_call(
                &rpc_url,
                "getAccountInfo",
                json!([mint, {"encoding": "base64", "commitment": "confirmed"}]),
            ) {
                Ok(value) => value,
                Err(error) => return Ok(failure(&error)),
            };
            let mint_info = match parse_mint_account(&account_result) {
                Ok(value) => value,
                Err(error) => return Ok(failure(&error)),
            };

            let largest_result = match rpc_call(&rpc_url, "getTokenLargestAccounts", json!([mint]))
            {
                Ok(value) => value,
                Err(error) => return Ok(failure(&error)),
            };
            let concentration = match parse_largest_accounts(&largest_result, mint_info.supply) {
                Ok(value) => value,
                Err(error) => return Ok(failure(&error)),
            };

            emit(
                PluginAction::Read,
                PluginOutcome::Success,
                "read mint metadata and largest token accounts",
                Some(concentration.returned_accounts),
            );
            Ok(ToolResult {
                success: true,
                output: render_summary(&mint, &mint_info, &concentration),
                error: None,
            })
        }
    }

    fn configured_rpc_url(config: &HashMap<String, String>) -> Result<String, String> {
        let candidate = config
            .get("rpc_url")
            .map(String::as_str)
            .unwrap_or(DEFAULT_RPC_URL)
            .trim();
        if candidate.is_empty() || candidate.len() > 200 {
            return Err(
                "rpc_url must be a non-empty HTTPS URL of at most 200 characters".to_string(),
            );
        }
        if !candidate.starts_with("https://") {
            return Err("rpc_url must use HTTPS".to_string());
        }
        let authority = candidate["https://".len()..]
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.is_empty()
            || authority.contains('@')
            || authority.chars().any(char::is_whitespace)
        {
            return Err(
                "rpc_url must contain a valid HTTPS authority without user credentials".to_string(),
            );
        }
        Ok(candidate.to_string())
    }

    fn rpc_call(rpc_url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = waki::Client::new()
            .post(rpc_url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|_| "Solana RPC request failed".to_string())?;
        let status = response.status_code();
        let payload = response
            .json::<Value>()
            .map_err(|_| "Solana RPC returned invalid JSON".to_string())?;
        if !(200..300).contains(&status) {
            return Err(format!("Solana RPC returned HTTP {status}"));
        }
        if let Some(error) = payload.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            return Err(format!("Solana RPC returned error code {code}"));
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| "Solana RPC response had no result".to_string())
    }

    fn failure(message: &str) -> ToolResult {
        emit(
            PluginAction::Fail,
            PluginOutcome::Failure,
            "token-risk inspection failed",
            None,
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message.to_string()),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, accounts: Option<usize>) {
        let attrs = accounts.map(|count| format!("{{\"returned_token_accounts\":{count}}}"));
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_token_risk::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaTokenRisk);
}
