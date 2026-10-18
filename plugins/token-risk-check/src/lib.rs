//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Given a mint address, it returns a red/amber/green safety verdict for an SPL
//! or Token-2022 token: mint/freeze authority status, dangerous Token-2022
//! extensions (permanent delegate, transfer hook, transfer fee, default-frozen,
//! non-transferable, mint-close), and top-holder concentration. It is the
//! plugin that makes every other plugin safer.
//!
//! ## Custody tier: T0 (read-only)
//!
//! The tool holds no key and signs nothing. Its only capabilities are
//! `http_client` (a read-only JSON-RPC POST to the operator-configured endpoint)
//! and `config_read` (to learn that endpoint). There is no code path anywhere in
//! this plugin that builds, signs, or submits a transaction. A prompt-injected
//! model can, at worst, ask for the risk of some other mint — a read.
//!
//! ## Injection surface
//!
//! The single argument the model controls is `mint`, which is strictly validated
//! as a 32-byte base58 address before any use; anything else is rejected and the
//! tool returns an error without touching the network. The verdict is derived
//! only from structural on-chain state, never from creator-controlled metadata
//! (name/symbol/description), so a token cannot talk its way to a GREEN.
//!
//! The pure verdict logic lives in [`risk`] (no wasm/http deps) and is covered by
//! host `cargo test`; this shim only does the RPC I/O.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::Value;
    use solana_core::rpc;
    use solana_core::{base58, programs};

    use crate::risk::{self, RiskInput, TokenProgram};
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

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        /// The token mint address to assess. The only model-controlled input.
        mint: String,
        /// Operator config section, injected by the host under `config_read`.
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
            "Assess the safety of a Solana token by its mint address. Returns a \
             red/amber/green verdict with reasons: mint and freeze authority status, \
             dangerous Token-2022 extensions (permanent delegate, transfer hook, \
             transfer fee, default-frozen, non-transferable), and top-holder \
             concentration. Read-only; never moves funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The token's mint address (base58)."
                    }
                },
                "required": ["mint"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };

            // Fail closed on anything that is not a real address, before any I/O.
            let mint = parsed.mint.trim();
            if let Err(e) = base58::decode(mint) {
                emit(
                    PluginAction::Reject,
                    PluginOutcome::Failure,
                    "rejected non-address input",
                );
                return Ok(fail(format!("`{mint}` is not a valid mint address: {e}")));
            }

            let rpc_url = parsed
                .config
                .get("rpc_url")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_RPC_URL)
                .to_string();

            match assess_mint(&rpc_url, mint) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "assessed mint",
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "assessment failed",
                    );
                    Ok(fail(e))
                }
            }
        }
    }

    /// The full read path: fetch the mint account, decode it, fetch holder
    /// concentration (best-effort), assess, and render.
    fn assess_mint(rpc_url: &str, mint: &str) -> Result<String, String> {
        let acct_result = rpc_call(
            rpc_url,
            "getAccountInfo",
            rpc::get_account_info_params(mint),
        )?;
        let value = rpc::value_field(&acct_result)?;
        let account = rpc::parse_account(value)?
            .ok_or_else(|| format!("no account exists at {mint} (not a token mint)"))?;

        let program = match account.owner.as_str() {
            programs::SPL_TOKEN => TokenProgram::SplToken,
            programs::SPL_TOKEN_2022 => TokenProgram::SplToken2022,
            other => {
                return Err(format!(
                    "{mint} is owned by {other}, not a token program — not a mint"
                ))
            }
        };

        let mint_data = solana_core::mint::parse_mint(&account.data)?;
        let extensions = solana_core::mint::parse_extensions(&account.data);

        // Holder concentration is best-effort: a failure here downgrades to
        // "unknown", it never fails the whole verdict.
        let holders = fetch_holders(rpc_url, mint, mint_data.supply);

        let input = RiskInput {
            program,
            mint: mint_data,
            extensions,
            holders,
        };
        let report = risk::assess(&input);
        Ok(risk::render(mint, &input, &report))
    }

    /// Fetch `getTokenLargestAccounts` and compute concentration. Returns `None`
    /// on any error so the verdict still renders.
    fn fetch_holders(rpc_url: &str, mint: &str, supply: u64) -> Option<risk::HolderStats> {
        let result = rpc_call(
            rpc_url,
            "getTokenLargestAccounts",
            rpc::get_token_largest_accounts_params(mint),
        )
        .ok()?;
        let value = rpc::value_field(&result).ok()?;
        let arr = value.as_array()?;
        let amounts: Vec<u64> = arr
            .iter()
            .filter_map(|e| e.get("amount").and_then(Value::as_str))
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        risk::holder_stats(&amounts, supply)
    }

    /// One JSON-RPC POST over `wasi:http`. TLS is performed host-side.
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
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
