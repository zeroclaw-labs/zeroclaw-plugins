//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Given a Solana mint address, it reads the mint account (and, best-effort, its
//! largest token accounts) over the host's `wasi:http` and returns a
//! Red / Amber / Green safety verdict: whether an authority can inflate supply,
//! freeze or seize tokens, block sells via a transfer hook, punitively tax
//! transfers, pause the token, or has parked most of the supply in a few wallets.
//!
//! This is a **T0 read-only** plugin. It only ever issues read RPCs
//! (`getAccountInfo`, `getTokenLargestAccounts`) and *decodes bytes*; it never
//! executes anything carried in the token's data, so it is immune to prompt
//! injection and fails closed on every malformed or unexpected input.
//!
//! The pure scoring core lives in [`risk`] with no wasm dependency, so it
//! compiles and tests on the host with a plain `cargo test`; the wasm component
//! reuses the exact same logic through this shim.
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

    use zeroclaw_solana_core::extensions::{analyze_extensions, ExtensionRisks};
    use zeroclaw_solana_core::holders::{
        largest_accounts_params, parse_largest_accounts, top_n_concentration,
    };
    use zeroclaw_solana_core::mint::decode_mint;
    use zeroclaw_solana_core::pubkey::{Pubkey, SPL_TOKEN, SPL_TOKEN_2022};
    use zeroclaw_solana_core::rpc::RpcClient;

    use crate::risk::{assess, Verdict};

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
            "Analyze a Solana token mint for rug and footgun risk and return a compact \
             Red/Amber/Green verdict. Checks mint and freeze authorities, Token-2022 \
             extensions (permanent delegate, active vs. disabled transfer hook, transfer \
             fees, pausable, non-transferable, default-frozen, confidential), and top-holder \
             concentration. Read-only: it never signs or sends a transaction. Input is a \
             base58 mint address."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 SPL Token or Token-2022 mint address to analyze."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail("invalid arguments", format!("invalid arguments: {e}"))),
            };

            let rpc_url = parsed
                .config
                .get("rpc_url")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());

            let mint_pk = match Pubkey::from_base58(parsed.mint.trim()) {
                Ok(pk) => pk,
                Err(e) => {
                    return Ok(fail(
                        "invalid mint address",
                        format!("invalid mint address: {e}"),
                    ))
                }
            };

            let client = RpcClient::new(rpc_url);

            let account = match client.get_account(&mint_pk) {
                Ok(Some(acc)) => acc,
                Ok(None) => {
                    return Ok(fail(
                        "account not found",
                        "account not found / not a token".to_string(),
                    ))
                }
                Err(e) => return Ok(fail("rpc error", format!("rpc error: {e}"))),
            };

            // Classify strictly by owning program (never by account contents).
            let owner = account.owner.to_string();
            if owner != SPL_TOKEN && owner != SPL_TOKEN_2022 {
                return Ok(fail(
                    "not an SPL token mint",
                    format!("not an SPL token mint (owner {owner})"),
                ));
            }

            let mint = match decode_mint(&account.data, &account.owner) {
                Ok(m) => m,
                Err(e) => {
                    return Ok(fail(
                        "mint decode failed",
                        format!("mint decode failed: {e}"),
                    ))
                }
            };

            let ext = if mint.is_token_2022 && mint.has_extensions {
                analyze_extensions(&account.data)
            } else {
                ExtensionRisks::default()
            };

            // Holder concentration is best-effort: some RPC endpoints rate-limit
            // or disable getTokenLargestAccounts. On any failure we proceed with
            // no data; the core reports that as a neutral note, never as safety.
            let (top1, top5) =
                match client.call("getTokenLargestAccounts", largest_accounts_params(&mint_pk)) {
                    Ok(resp) => match parse_largest_accounts(&resp) {
                        Ok(holders) => (
                            Some(top_n_concentration(&holders, mint.supply, 1)),
                            Some(top_n_concentration(&holders, mint.supply, 5)),
                        ),
                        Err(_) => (None, None),
                    },
                    Err(_) => (None, None),
                };

            let verdict = assess(&mint, &ext, top1, top5);
            let summary = verdict.summary();

            emit(
                LogLevel::Info,
                PluginAction::Complete,
                PluginOutcome::Success,
                &format!("assessed {mint_pk}: {}", verdict.level.label()),
                Some(verdict_attrs(
                    &mint_pk,
                    &verdict,
                    mint.is_token_2022,
                    top1.is_some(),
                )),
            );

            Ok(ToolResult {
                success: true,
                output: summary,
                error: None,
            })
        }
    }

    /// Build a fail-closed `ToolResult` and emit a structured failure log.
    fn fail(log_message: &str, error: String) -> ToolResult {
        emit(
            LogLevel::Warn,
            PluginAction::Fail,
            PluginOutcome::Failure,
            log_message,
            None,
        );
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        }
    }

    /// JSON attrs for a completed assessment (never includes token data bytes).
    fn verdict_attrs(mint: &Pubkey, verdict: &Verdict, token_2022: bool, holders: bool) -> String {
        serde_json::json!({
            "mint": mint.to_string(),
            "level": verdict.level.label(),
            "reasons": verdict.reasons.len(),
            "token_2022": token_2022,
            "holder_data": holders,
        })
        .to_string()
    }

    fn emit(
        level: LogLevel,
        action: PluginAction,
        outcome: PluginOutcome,
        message: &str,
        attrs: Option<String>,
    ) {
        log_record(
            level,
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
