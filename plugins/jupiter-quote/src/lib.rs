//! A ZeroClaw WIT tool plugin: `jupiter_quote`.
//!
//! Fetches a read-only swap quote from the Jupiter Quote API
//! (`{base}/swap/v1/quote`, default host `lite-api.jup.ag`, no API key) for a
//! given input mint, output mint, and input amount in base units. Returns the
//! expected output amount, price impact, and a route/hop summary for the model.
//! Read-only: this is a *quote only* — it never builds, signs, or sends a swap,
//! holds no keys, and moves no funds. The Jupiter base URL is overridable
//! through the plugin's own jailed config section (`jupiter_base_url`, gated by
//! the `config_read` permission).
//!
//! The pure request/response logic lives in [`quote`] with no wasm dependency,
//! so it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this thin shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod quote;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::quote::{
        amount_from_json, build_quote_url, format_output, parse_quote_response, validate_mint,
        QuoteConfig, QuoteParams,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct JupiterQuote;

    const PLUGIN_NAME: &str = "jupiter-quote";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "jupiter_quote";

    /// Outbound connect timeout. Kept modest so a slow endpoint fails the call
    /// cleanly rather than burning the host's per-call fuel budget.
    const CONNECT_TIMEOUT_SECS: u64 = 10;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        input_mint: String,
        output_mint: String,
        // Accept the amount as either a JSON string or an integer number.
        amount: serde_json::Value,
        #[serde(default)]
        slippage_bps: Option<u32>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for JupiterQuote {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for JupiterQuote {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Get a read-only swap quote from Jupiter (Solana's DEX aggregator) \
             for swapping `amount` base units of `input_mint` into `output_mint`. \
             Returns the expected output amount, price impact %, the route/hops \
             taken across DEXes, and the minimum output after slippage. This is a \
             QUOTE ONLY: it never builds, signs, or sends a transaction and moves \
             no funds. `amount` is in the input token's smallest units (e.g. \
             lamports for SOL, 1e6 per USDC). Uses Jupiter's key-free public API."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "input_mint": {
                        "type": "string",
                        "description": "Base58 mint of the token being sold, e.g. \"So11111111111111111111111111111111111111112\" (wrapped SOL)."
                    },
                    "output_mint": {
                        "type": "string",
                        "description": "Base58 mint of the token being bought, e.g. \"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v\" (USDC)."
                    },
                    "amount": {
                        "type": ["string", "integer"],
                        "description": "Amount of input_mint to swap, in the token's base units (integer, no decimal point). E.g. 1 SOL = 1000000000, 1 USDC = 1000000."
                    },
                    "slippage_bps": {
                        "type": "integer",
                        "description": "Optional slippage tolerance in basis points (100 = 1%). If omitted, Jupiter's default is used.",
                        "minimum": 0
                    }
                },
                "required": ["input_mint", "output_mint", "amount"]
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

            let input_mint = match validate_mint(&parsed.input_mint) {
                Ok(m) => m,
                Err(e) => return Ok(failure("invalid input_mint", format!("input_mint: {e}"))),
            };
            let output_mint = match validate_mint(&parsed.output_mint) {
                Ok(m) => m,
                Err(e) => return Ok(failure("invalid output_mint", format!("output_mint: {e}"))),
            };
            let amount = match amount_from_json(&parsed.amount) {
                Ok(a) => a,
                Err(e) => return Ok(failure("invalid amount", format!("amount: {e}"))),
            };

            let cfg = QuoteConfig::from_section(&parsed.config);
            let params = QuoteParams {
                input_mint,
                output_mint,
                amount,
                slippage_bps: parsed.slippage_bps,
            };
            let url = build_quote_url(&cfg.jupiter_base_url, &params);

            let text = match get_url(&url) {
                Ok(t) => t,
                Err(e) => return Ok(failure("quote request failed", e)),
            };

            match parse_quote_response(&text) {
                Ok(q) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "fetched quote",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: format_output(&q, &cfg.jupiter_base_url),
                        error: None,
                    })
                }
                Err(e) => Ok(failure("quote parse failed", e)),
            }
        }
    }

    /// GET a URL and return the response text, mapping any transport or non-2xx
    /// result to a human-readable error string.
    fn get_url(url: &str) -> Result<String, String> {
        let resp = waki::Client::new()
            .get(url)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .send()
            .map_err(|e| format!("Jupiter request failed: {e}"))?;
        let status = resp.status_code();
        let raw = resp
            .body()
            .map_err(|e| format!("reading Jupiter response failed: {e}"))?;
        let text = String::from_utf8_lossy(&raw).to_string();
        if !(200..300).contains(&status) {
            return Err(format!("Jupiter returned HTTP {status}: {text}"));
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
                function_name: "jupiter_quote::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(JupiterQuote);
}
