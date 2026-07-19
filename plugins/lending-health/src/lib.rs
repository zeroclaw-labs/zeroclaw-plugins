//! A ZeroClaw WIT tool plugin: `lending_health`.
//!
//! A Solana DeFi liquidation-risk sentinel for **Kamino Lend**. Given a wallet
//! address it discovers that wallet's Kamino obligations over the host's
//! `wasi:http`, decodes each account's cached health fields, and returns a
//! compact health-factor verdict (🟢 Healthy / 🟡 At-risk / 🔴 Liquidatable),
//! so a ZeroClaw cron SOP can run it on a schedule and push a Telegram alert the
//! moment a position drifts toward liquidation.
//!
//! This is a **T0 read-only** plugin. It only ever issues read RPCs
//! (`getProgramAccounts`, `getAccountInfo`) and *decodes bytes*; it never
//! signs, sends, or executes anything carried in on-chain data, so it is immune
//! to prompt injection and fails closed on every malformed or unexpected input.
//!
//! The pure decode + scoring core lives in [`kamino`] and [`fraction`] with no
//! wasm dependency, so it compiles and tests on the host with a plain
//! `cargo test` (against an embedded real mainnet obligation); the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod fraction;
pub mod kamino;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::{json, Value};

    use zeroclaw_solana_core::base58;
    use zeroclaw_solana_core::base64;
    use zeroclaw_solana_core::pubkey::Pubkey;
    use zeroclaw_solana_core::rpc::{result_of, RpcClient};

    use crate::kamino::{
        decode_obligation, Obligation, Status, KLEND_PROGRAM_ID, OBLIGATION_DISCRIMINATOR,
    };

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct LendingHealth;

    const PLUGIN_NAME: &str = "lending-health";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "lending_health";
    const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        wallet: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for LendingHealth {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for LendingHealth {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Check a Solana wallet's Kamino Lend liquidation risk. Discovers the \
             wallet's obligations and returns a compact health-factor verdict \
             (Healthy / At-risk / Liquidatable) with collateral, debt, and \
             loan-to-value. Read-only: it only reads and decodes on-chain \
             accounts, never signs or sends a transaction. Designed to be run on \
             a schedule by a cron SOP that alerts a channel when a position is at \
             risk. Input is a base58 wallet address."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "properties": {
                    "wallet": {
                        "type": "string",
                        "description": "Base58 Solana wallet address to check for Kamino Lend positions."
                    }
                },
                "required": ["wallet"]
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

            let wallet = match Pubkey::from_base58(parsed.wallet.trim()) {
                Ok(pk) => pk,
                Err(e) => {
                    return Ok(fail(
                        "invalid wallet address",
                        format!("invalid wallet address: {e}"),
                    ))
                }
            };

            let client = RpcClient::new(rpc_url);

            // Discover the wallet's obligations: getProgramAccounts on the Kamino
            // Lend program, filtered by the Obligation discriminator (@0) and the
            // owner field (@64). Both memcmp bytes are base58 (the RPC default).
            let disc_b58 = base58::encode(&OBLIGATION_DISCRIMINATOR);
            let params = json!([
                KLEND_PROGRAM_ID,
                {
                    "encoding": "base64",
                    "filters": [
                        { "memcmp": { "offset": 0, "bytes": disc_b58 } },
                        { "memcmp": { "offset": 64, "bytes": wallet.to_string() } }
                    ]
                }
            ]);

            let resp = match client.call("getProgramAccounts", params) {
                Ok(v) => v,
                Err(e) => return Ok(fail("rpc error", format!("rpc error: {e}"))),
            };
            let accounts = match result_of(&resp).and_then(|r| {
                r.as_array()
                    .cloned()
                    .ok_or_else(|| "getProgramAccounts: result not an array".to_string())
            }) {
                Ok(a) => a,
                Err(e) => return Ok(fail("rpc error", format!("rpc error: {e}"))),
            };

            // Honest, non-error result: this wallet simply has no Kamino position.
            if accounts.is_empty() {
                emit(
                    LogLevel::Info,
                    PluginAction::Complete,
                    PluginOutcome::Success,
                    &format!("no Kamino position for {wallet}"),
                    Some(no_position_attrs(&wallet)),
                );
                return Ok(ToolResult {
                    success: true,
                    output: "No Kamino position found for this wallet.".to_string(),
                    error: None,
                });
            }

            let mut obligations: Vec<Obligation> = Vec::new();
            for item in &accounts {
                let Some(b64) = item
                    .get("account")
                    .and_then(|a| a.get("data"))
                    .and_then(Value::as_array)
                    .and_then(|d| d.first())
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                let Ok(bytes) = base64::decode(b64) else {
                    continue;
                };
                if let Ok(ob) = decode_obligation(&bytes) {
                    obligations.push(ob);
                }
            }

            if obligations.is_empty() {
                return Ok(fail(
                    "decode failed",
                    "found obligation account(s) but could not decode them".to_string(),
                ));
            }

            let worst = worst_status(&obligations);
            let output = render(&wallet, &obligations);

            emit(
                LogLevel::Info,
                PluginAction::Complete,
                PluginOutcome::Success,
                &format!(
                    "checked {wallet}: {} position(s), worst {}",
                    obligations.len(),
                    worst.label()
                ),
                Some(result_attrs(&wallet, &obligations, worst)),
            );

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    /// Render one or more obligations into the final compact output. A single
    /// position is just its summary; multiple positions get a one-line header.
    fn render(wallet: &Pubkey, obligations: &[Obligation]) -> String {
        if obligations.len() == 1 {
            return obligations[0].summary();
        }
        let mut out = format!("{} Kamino positions for {wallet}:\n", obligations.len());
        for ob in obligations {
            out.push('\n');
            out.push_str(&ob.summary());
            out.push('\n');
        }
        out
    }

    /// The most severe status across a wallet's obligations (drives alerting).
    fn worst_status(obligations: &[Obligation]) -> Status {
        let rank = |s: Status| match s {
            Status::Liquidatable => 3,
            Status::AtRisk => 2,
            Status::Healthy => 1,
            Status::NoDebt => 0,
        };
        obligations
            .iter()
            .map(|o| o.status())
            .max_by_key(|s| rank(*s))
            .unwrap_or(Status::NoDebt)
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

    fn no_position_attrs(wallet: &Pubkey) -> String {
        json!({ "wallet": wallet.to_string(), "positions": 0 }).to_string()
    }

    /// JSON attrs for a completed check. Carries the alert signal a cron SOP
    /// branches on; never includes raw account bytes.
    fn result_attrs(wallet: &Pubkey, obligations: &[Obligation], worst: Status) -> String {
        json!({
            "wallet": wallet.to_string(),
            "positions": obligations.len(),
            "worst_status": worst.label(),
            "alert": worst.should_alert(),
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
                function_name: "lending_health::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(LendingHealth);
}
