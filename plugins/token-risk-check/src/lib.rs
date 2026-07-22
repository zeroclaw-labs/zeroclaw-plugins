//! A ZeroClaw WIT tool plugin: `token-risk-check`.
//!
//! Answers one question before an agent spends money: is this Solana mint safe
//! to touch? It reads the mint account and its largest holders over JSON-RPC and
//! returns red/amber/green with the specific reasons — mint and freeze
//! authority, the Token-2022 extensions that let an issuer confiscate or tax
//! (permanent delegate, transfer hook, transfer fee), and holder concentration.
//!
//! Custody tier: **T0 (read)**. It holds no key, builds no transaction and signs
//! nothing. The worst a prompt injection can do is make it read the wrong mint.
//!
//! The pure scoring core lives in [`risk_check`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod risk_check;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::risk_check::{RiskChecker, RiskLevel};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "check-solana-token-risk";
    const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint_address: String,
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
            "Check whether a Solana token is safe before buying, swapping or accepting it. \
             Reports mint and freeze authority, Token-2022 permanent delegate, transfer hook \
             and transfer fee, and how much of the supply the top holders control. \
             Returns red, amber or green with the reasons. Read-only: holds no key and signs nothing."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint_address": {
                        "type": "string",
                        "description": "The mint address (base58 public key) of the Solana token to scan."
                    }
                },
                "required": ["mint_address"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments", None);
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };

            // Validate before touching the network: a malformed or injected
            // address never becomes an outbound request.
            if let Err(e) = RiskChecker::validate_mint_address(&parsed.mint_address) {
                emit(PluginAction::Validate, PluginOutcome::Failure, &e, None);
                return Ok(fail(e));
            }

            // The RPC URL usually carries an API key, so it comes from the
            // operator's own jailed config section, never from the LLM's args.
            let rpc_url = parsed
                .config
                .get("solana_rpc_url")
                .map(String::as_str)
                .unwrap_or(DEFAULT_RPC);

            emit(PluginAction::Query, PluginOutcome::Success, "scanning mint", None);

            let account_info = match call_rpc(
                rpc_url,
                "getAccountInfo",
                serde_json::json!([parsed.mint_address, { "encoding": "jsonParsed" }]),
            ) {
                Ok(v) => v,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "getAccountInfo failed", None);
                    return Ok(fail(format!("could not read the mint account: {e}")));
                }
            };

            // The holder list is the optional half of the check. Authority and
            // Token-2022 findings come from getAccountInfo above and are the ones
            // that actually block a trade, so a throttled or failed holder lookup
            // degrades to "concentration unknown" instead of sinking the report.
            let holders_raw = call_rpc(
                rpc_url,
                "getTokenLargestAccounts",
                serde_json::json!([parsed.mint_address]),
            );

            let mint_info = match RiskChecker::parse_account_info(&account_info) {
                Ok(v) => v,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "unparseable mint account", None);
                    return Ok(fail(e));
                }
            };
            let (holders, holders_checked) = match holders_raw
                .as_deref()
                .map_err(|e| e.clone())
                .and_then(RiskChecker::parse_largest_holders)
            {
                Ok(v) => (v, true),
                Err(e) => {
                    emit(PluginAction::Note, PluginOutcome::Failure,
                         &format!("holder lookup unavailable: {e}"), None);
                    (Vec::new(), false)
                }
            };

            let report = match RiskChecker::evaluate_risk_full(
                &parsed.mint_address, &mint_info, &holders, holders_checked,
            ) {
                Ok(r) => r,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &e, None);
                    return Ok(fail(e));
                }
            };

            // Hand the model a few hundred tokens of prose, not the raw RPC
            // payload — a getAccountInfo dump would swamp the context window.
            let output = report.to_agent_summary();
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                match report.risk_level {
                    RiskLevel::Red => "scored RED",
                    RiskLevel::Amber => "scored AMBER",
                    RiskLevel::Green => "scored GREEN",
                },
                Some(report.risk_score),
            );

            Ok(ToolResult { success: true, output, error: None })
        }
    }

    fn fail(error: String) -> ToolResult {
        ToolResult { success: false, output: String::new(), error: Some(error) }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, score: Option<u8>) {
        let attrs = score.map(|s| format!("{{\"risk_score\":{s}}}"));
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

    /// One Solana JSON-RPC round trip. Returns the raw response body so the pure
    /// core owns all parsing.
    fn call_rpc(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<String, String> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let body = waki::Client::new()
            .post(rpc_url)
            .json(&payload)
            .send()
            .map_err(|e| e.to_string())?
            .json::<serde_json::Value>()
            .map_err(|e| e.to_string())?;

        Ok(body.to_string())
    }

    export!(TokenRiskCheck);
}
