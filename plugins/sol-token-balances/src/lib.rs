//! A ZeroClaw WIT tool plugin: `sol_token_balances`.
//!
//! Lists the SPL Token balances held by a Solana account by calling the JSON-RPC
//! `getTokenAccountsByOwner` method (SPL Token program, `jsonParsed` encoding),
//! skipping zero balances. When `include_usd` is set it enriches each balance
//! with a USD price from Jupiter's key-free price API (`lite-api.jup.ag`).
//! Read-only: it holds no keys, signs nothing, and moves no funds. The RPC
//! endpoint and Jupiter base URL default to public hosts and are overridable
//! through the plugin's own jailed config section (`rpc_url`,
//! `jupiter_base_url`, gated by the `config_read` permission).
//!
//! The pure request/response logic lives in [`tokens`] with no wasm dependency,
//! so it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this thin shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod tokens;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::tokens::{
        build_price_url, build_request_body, distinct_mints, format_output, mint_batches,
        parse_price_response, parse_token_accounts, validate_pubkey, TokenConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolTokenBalances;

    const PLUGIN_NAME: &str = "sol-token-balances";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sol_token_balances";

    /// Outbound connect timeout. Kept modest so a slow endpoint fails the call
    /// cleanly rather than burning the host's per-call fuel budget.
    const CONNECT_TIMEOUT_SECS: u64 = 10;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        address: String,
        #[serde(default)]
        include_usd: bool,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolTokenBalances {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolTokenBalances {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "List the SPL Token balances held by a Solana account (by its base58 \
             address). Calls the Solana JSON-RPC `getTokenAccountsByOwner` method \
             for the SPL Token program and returns each non-zero holding as its \
             mint, ui amount, decimals, and exact raw base-unit amount. Set \
             `include_usd` to also attach a USD price and value per token from \
             Jupiter's price API, plus a portfolio total. Read-only: requires no \
             keys and moves no funds. Defaults to Solana mainnet-beta."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "The owner account's base58-encoded Solana public key (decodes to 32 bytes), e.g. \"5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9\"."
                    },
                    "include_usd": {
                        "type": "boolean",
                        "description": "If true, enrich each token with a USD price and value from Jupiter's price API and include a portfolio total_usd. Defaults to false.",
                        "default": false
                    }
                },
                "required": ["address"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // Bad input is reported via `success: false`, never `Err`: an `Err`
            // crosses the boundary as a plugin fault and fails the call, while a
            // `success: false` result flows back to the model as a normal tool
            // response it can react to.
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(failure(
                        "invalid arguments",
                        format!("invalid arguments: {e}"),
                    ));
                }
            };

            let address = match validate_pubkey(&parsed.address) {
                Ok(a) => a,
                Err(e) => return Ok(failure("invalid address", e)),
            };

            let cfg = TokenConfig::from_section(&parsed.config);
            let body = build_request_body(&address);

            let text = match post_json(&cfg.rpc_url, body) {
                Ok(t) => t,
                Err(e) => return Ok(failure("rpc request failed", e)),
            };

            let tokens = match parse_token_accounts(&text) {
                Ok(t) => t,
                Err(e) => return Ok(failure("rpc parse failed", e)),
            };

            // USD enrichment is best-effort: a Jupiter failure must not sink an
            // otherwise-good balance lookup. Any prices we do fetch are merged;
            // mints Jupiter can't price simply get no usd fields.
            let prices = if parsed.include_usd {
                let mints = distinct_mints(&tokens);
                let mut map = HashMap::new();
                for batch in mint_batches(&mints) {
                    let url = build_price_url(&cfg.jupiter_base_url, &batch);
                    match get_url(&url).and_then(|b| parse_price_response(&b)) {
                        Ok(m) => map.extend(m),
                        Err(e) => emit(
                            PluginAction::Query,
                            PluginOutcome::Failure,
                            &format!("jupiter price batch failed: {e}"),
                        ),
                    }
                }
                Some(map)
            } else {
                None
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "fetched token balances",
            );
            Ok(ToolResult {
                success: true,
                output: format_output(&address, &cfg.rpc_url, &tokens, prices.as_ref()),
                error: None,
            })
        }
    }

    /// POST a JSON-RPC body and return the response text, mapping any transport
    /// or non-2xx result to a human-readable error string.
    fn post_json(url: &str, body: String) -> Result<String, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.into_bytes())
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?;
        let status = resp.status_code();
        let raw = resp
            .body()
            .map_err(|e| format!("reading RPC response failed: {e}"))?;
        let text = String::from_utf8_lossy(&raw).to_string();
        if !(200..300).contains(&status) {
            return Err(format!("RPC returned HTTP {status}: {text}"));
        }
        Ok(text)
    }

    /// GET a URL and return the response text, mapping any transport or non-2xx
    /// result to a human-readable error string.
    fn get_url(url: &str) -> Result<String, String> {
        let resp = waki::Client::new()
            .get(url)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?;
        let status = resp.status_code();
        let raw = resp
            .body()
            .map_err(|e| format!("reading HTTP response failed: {e}"))?;
        let text = String::from_utf8_lossy(&raw).to_string();
        if !(200..300).contains(&status) {
            return Err(format!("HTTP {status}: {text}"));
        }
        Ok(text)
    }

    /// Build a `success: false` result and log the failure. Used for every
    /// recoverable error so the model sees a normal tool response.
    fn failure(log_message: &str, error: String) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, log_message);
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    /// Emit a structured log record through the host's `logging` interface
    /// (never `wasi:logging`). Fire-and-forget: the host absorbs all errors.
    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "sol_token_balances::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolTokenBalances);
}
