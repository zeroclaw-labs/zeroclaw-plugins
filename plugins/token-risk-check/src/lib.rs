//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Given a Solana mint address, answers one question an agent should ask
//! before it touches ANY token: "is this thing safe to hold and move?" —
//! mint/freeze authorities, Token-2022 extension traps (permanent delegate,
//! transfer hooks, transfer fees, default-frozen, non-transferable), and
//! holder concentration, reduced to a red/amber/green verdict with reasons.
//!
//! Custody tier: **T0 (read-only)**. The plugin holds no keys, signs nothing,
//! and mutates nothing. Its only secret exposure is the operator's RPC URL,
//! read from the plugin's own jailed config section.
//!
//! The pure logic lives in [`spl`], [`rpc`], and [`risk`] with no wasm
//! dependency, so it compiles and tests on the host with a plain `cargo test`;
//! the wasm component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod risk;
pub mod rpc;
pub mod spl;

/// Shared arg/config plumbing (host-testable, no wasm dependency).
pub mod args {
    use std::collections::HashMap;

    /// Public, keyless default. Operators are expected to set `rpc_url` in
    /// this plugin's config section; never put an endpoint with an API key in
    /// code or in the mint argument.
    pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

    #[derive(serde::Deserialize)]
    pub struct ExecuteArgs {
        pub mint: String,
        #[serde(rename = "__config", default)]
        pub config: HashMap<String, String>,
    }

    impl ExecuteArgs {
        pub fn rpc_url(&self) -> &str {
            self.config
                .get("rpc_url")
                .map(String::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_RPC_URL)
        }
    }

    /// Validate a mint address shape before it goes anywhere near a URL or an
    /// RPC body: base58, decodes to exactly 32 bytes. Fail closed on anything
    /// else — including prompt-injected "addresses" carrying URLs or params.
    pub fn validate_mint(mint: &str) -> Result<(), String> {
        if mint.len() < 32 || mint.len() > 44 {
            return Err(format!(
                "'{}' is not a Solana mint address (bad length)",
                sanitize(mint)
            ));
        }
        let decoded = bs58::decode(mint)
            .into_vec()
            .map_err(|_| format!("'{}' is not valid base58", sanitize(mint)))?;
        if decoded.len() != 32 {
            return Err(format!(
                "'{}' does not decode to a 32-byte key",
                sanitize(mint)
            ));
        }
        Ok(())
    }

    /// Echo untrusted input safely: strip to a short printable prefix.
    fn sanitize(s: &str) -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(16)
            .collect()
    }
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde_json::Value;

    use crate::args::ExecuteArgs;
    use crate::{args, risk, rpc, spl};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";

    fn post_json(url: &str, body: &Value) -> Result<String, String> {
        let resp = waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?;
        let bytes = resp.body().map_err(|e| format!("RPC body read failed: {e}"))?;
        String::from_utf8(bytes).map_err(|e| format!("RPC body is not UTF-8: {e}"))
    }

    fn log(level: LogLevel, action: PluginAction, outcome: PluginOutcome, msg: &str) {
        log_record(
            level,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: msg.to_string(),
            },
        );
    }

    /// The full pipeline; every failure path returns an error string and the
    /// tool reports it explicitly — no partial verdicts, no guesses.
    fn run(args: &ExecuteArgs) -> Result<String, String> {
        args::validate_mint(&args.mint)?;
        let url = args.rpc_url();

        let acc_resp = post_json(url, &rpc::build_get_account_info(&args.mint))?;
        let (owner, data) = rpc::parse_account_info(&acc_resp)?
            .ok_or_else(|| format!("mint {} does not exist on this cluster", args.mint))?;
        let mint = spl::parse_mint(&data)?;

        let supply_resp = post_json(url, &rpc::build_get_token_supply(&args.mint))?;
        let (supply, _decimals) = rpc::parse_token_supply(&supply_resp)?;

        let largest_resp = post_json(url, &rpc::build_get_token_largest_accounts(&args.mint))?;
        let largest = rpc::parse_largest_amounts(&largest_resp)?;

        let report = risk::analyze(&mint, &owner, supply, &largest)?;
        Ok(risk::render(&args.mint, &report))
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
            "Check a Solana token mint for safety risks BEFORE holding, swapping, or \
             building a transaction with it. Reports a RED/AMBER/GREEN verdict with \
             reasons: live mint/freeze authorities, Token-2022 traps (permanent \
             delegate, transfer hooks, transfer fees, frozen-by-default, \
             non-transferable), and holder concentration. Read-only; costs one RPC \
             round-trip and returns a few short lines."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "The token's mint address (base58, 32 bytes)"
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args_json: String) -> Result<ToolResult, String> {
            log(
                LogLevel::Info,
                PluginAction::Start,
                PluginOutcome::Success,
                "token_risk_check invoked",
            );
            let args: ExecuteArgs = match serde_json::from_str(&args_json) {
                Ok(a) => a,
                Err(e) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "bad arguments",
                    );
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };
            match run(&args) {
                Ok(report) => {
                    log(
                        LogLevel::Info,
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "verdict delivered",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: report,
                        error: None,
                    })
                }
                Err(e) => {
                    log(
                        LogLevel::Warn,
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        &e,
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    export!(TokenRiskCheck);
}
