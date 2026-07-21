//! A ZeroClaw WIT tool plugin: `solana_account`.
//!
//! Read any Solana address's on-chain state — SOL balance, SPL token holdings,
//! account type, and recent activity — and shape it into a ~200-token summary.
//! Custody tier T0: pure reads, no keys, no state. This is the tool the agent
//! reaches for when someone asks "what's in wallet X?" or "is this address
//! active?", so it never has to dump a raw `getAccountInfo`/`getTokenAccounts`
//! response into its context window.
//!
//! The pure core lives in [`account`] with no wasm dependency and is host-tested
//! against a mock RPC with plain `cargo test`; this file is the thin component
//! shim wiring it to the `tool-plugin` WIT world with the blocking `waki`
//! client (TLS is performed host-side).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod account;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::account::{account_brief, AccountArgs, AccountConfig};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };
    use zeroclaw_solana_core::rpc::HttpTransport;

    struct WakiTransport;

    impl HttpTransport for WakiTransport {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let response = waki::Client::new()
                .post(url)
                .header("content-type", "application/json")
                .connect_timeout(std::time::Duration::from_secs(8))
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?;
            let bytes = response
                .body()
                .map_err(|e| format!("rpc response read failed: {e}"))?;
            String::from_utf8(bytes).map_err(|_| "rpc response is not UTF-8".to_string())
        }
    }

    struct SolanaAccount;

    const PLUGIN_NAME: &str = "solana-account";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_account";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        address: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolanaAccount {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaAccount {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Look up a Solana address on-chain and report its SOL balance, SPL token \
             holdings, account type (wallet vs program-owned), and recent transaction \
             activity — shaped to a short summary. Use when asked what an address holds, \
             whether a wallet is funded or active, or to inspect an account before paying \
             it. Takes a base58 address (resolve a .sol name with sns_resolve first). \
             Read-only; touches no funds and no keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "The Solana address to inspect (base58)."
                    }
                },
                "required": ["address"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments");
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };
            let cfg = AccountConfig::from_section(&parsed.config);
            let account_args = AccountArgs {
                address: parsed.address,
            };

            match account_brief(&WakiTransport, &account_args, &cfg) {
                Ok(brief) => {
                    emit(PluginAction::Complete, PluginOutcome::Success, "account read");
                    Ok(clamp(ToolResult {
                        success: true,
                        output: brief.text,
                        error: None,
                    }))
                }
                Err(e) => {
                    emit(PluginAction::Reject, PluginOutcome::Failure, "account read refused");
                    Ok(fail(e))
                }
            }
        }
    }

    /// Final backstop: no ToolResult exceeds this, whatever the inputs. A brief
    /// is a handful of short lines; the core already bounds every field, and
    /// this guarantees it at the WIT edge.
    const MAX_RESULT_CHARS: usize = 1024;

    fn clamp(mut r: ToolResult) -> ToolResult {
        if r.output.len() > MAX_RESULT_CHARS {
            r.output = r.output.chars().take(MAX_RESULT_CHARS).collect::<String>() + "…";
        }
        if let Some(e) = r.error.take() {
            r.error = Some(if e.len() > MAX_RESULT_CHARS {
                e.chars().take(MAX_RESULT_CHARS).collect::<String>() + "…"
            } else {
                e
            });
        }
        r
    }

    fn fail(error: String) -> ToolResult {
        clamp(ToolResult {
            success: false,
            output: String::new(),
            error: Some(error),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        // Refusals/failures log at WARN so operators can grep them; successes
        // and notes stay at INFO.
        let level = if matches!(outcome, PluginOutcome::Failure) {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };
        log_record(
            level,
            &PluginEvent {
                function_name: "solana_account::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaAccount);
}
