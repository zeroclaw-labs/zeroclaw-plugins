//! A ZeroClaw WIT **tool** plugin: `token_risk_check`.
//!
//! Given a Solana mint address, returns a red/amber/green risk verdict with
//! plain-English reasons: is the mint/freeze authority still live, does the
//! mint carry a dangerous Token-2022 extension (permanent delegate, transfer
//! hook, non-transferable, frozen-by-default), is supply concentrated in a
//! handful of wallets, and is there an active liquidity route.
//!
//! This is a **T0 (read-only)** plugin. It never builds, signs, or submits a
//! transaction, and holds no secret beyond an optional operator-supplied RPC
//! URL. See README.md for the full threat model.
//!
//! The pure risk-scoring core lives in [`risk`] with no wasm/http dependency,
//! so it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim, feeding it real
//! RPC responses fetched over `wasi:http`.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

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
        assess, compute_holder_concentration, format_report, parse_mint_info, HolderConcentration,
    };

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
    const JUPITER_QUOTE_URL: &str = "https://quote-api.jup.ag/v6/quote";
    // Wrapped SOL mint, used as the quote side to probe for a liquidity route.
    const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

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
            "Given a Solana token mint address, return a red/amber/green risk verdict: whether \
             the mint or freeze authority is still active, whether the mint carries a dangerous \
             Token-2022 extension (permanent delegate, transfer hook, non-transferable, \
             frozen-by-default accounts, transfer fee), whether supply is concentrated in a \
             handful of wallets, and whether an active liquidity route exists. Read-only \
             (T0) — never builds or signs a transaction."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The base58 SPL token or Token-2022 mint address to check."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, "invalid arguments", Some(&e.to_string()));
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let mint = parsed.mint.trim();
            if mint.is_empty() || mint.len() > 64 || !mint.chars().all(|c| c.is_ascii_alphanumeric()) {
                emit(PluginAction::Fail, "rejected malformed mint address", None);
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("mint must be a base58 address".to_string()),
                });
            }

            let rpc_url = parsed
                .config
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());

            let account_info = match rpc_call(
                &rpc_url,
                "getAccountInfo",
                json!([mint, { "encoding": "jsonParsed" }]),
            ) {
                Ok(v) => v,
                Err(e) => {
                    emit(PluginAction::Fail, "RPC getAccountInfo failed", Some(&e));
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("RPC request failed: {e}")),
                    });
                }
            };

            let mint_info = match parse_mint_info(&account_info) {
                Ok(m) => m,
                Err(e) => {
                    emit(PluginAction::Fail, "not a parsed mint account", Some(&e));
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            };

            // Holder concentration and LP liquidity are best-effort: a failure
            // here should never sink the whole report, since the authority and
            // extension checks above are already the highest-signal findings.
            let holders: Option<HolderConcentration> = rpc_call(
                &rpc_url,
                "getTokenLargestAccounts",
                json!([mint]),
            )
            .ok()
            .and_then(|resp| compute_holder_concentration(&resp, mint_info.supply).ok());

            let lp_active = check_lp_route(mint);

            let report = assess(&mint_info, holders, lp_active);
            let output = format_report(mint, &report);

            emit(
                PluginAction::Complete,
                "risk check complete",
                Some(&format!("verdict={}", report.verdict.label())),
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    /// POST a Solana JSON-RPC 2.0 request and return the parsed body.
    fn rpc_call(rpc_url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });
        waki::Client::new()
            .post(rpc_url)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .map_err(|e| e.to_string())
    }

    /// Best-effort: does Jupiter's aggregator find any route swapping a small
    /// notional of this mint against wrapped SOL? `None` on any network/parse
    /// error so a Jupiter outage never fails the whole risk check, only omits
    /// that one finding.
    fn check_lp_route(mint: &str) -> Option<bool> {
        let url = format!(
            "{JUPITER_QUOTE_URL}?inputMint={WSOL_MINT}&outputMint={mint}&amount=10000000&slippageBps=500"
        );
        let resp = waki::Client::new().get(&url).send().ok()?;
        let v: Value = resp.json().ok()?;
        Some(v.get("routePlan").and_then(Value::as_array).map(|r| !r.is_empty()).unwrap_or(false))
    }

    fn emit(action: PluginAction, message: &str, detail: Option<&str>) {
        let attrs = detail.map(|d| json!({ "detail": d }).to_string());
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(match action {
                    PluginAction::Fail => PluginOutcome::Failure,
                    _ => PluginOutcome::Success,
                }),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
