//! A ZeroClaw WIT tool plugin: `token_risk_check`.
//!
//! Red/amber/green risk verdict for any Solana SPL / Token-2022 mint:
//! mint & freeze authorities, Token-2022 extension traps (permanent delegate,
//! transfer hooks, confiscatory fees, frozen-by-default, pausable transfers),
//! and holder concentration — shaped into a few sentences, not kilobytes.
//!
//! Custody tier T0: read-only. The plugin holds no keys, builds no
//! transactions, and the model cannot influence *where* requests go — the RPC
//! endpoint comes exclusively from the operator's config section.
//!
//! The pure analysis core lives in [`check`], [`rpc`], [`mint`], [`holders`],
//! [`risk`] and [`report`] with no wasm dependency, so the entire pipeline
//! compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod check;
pub mod holders;
pub mod mint;
pub mod report;
pub mod risk;
pub mod rpc;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Instant;

    use crate::check::{run_check, CheckConfig};
    use crate::rpc::Transport;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// `waki`-backed transport: one blocking JSON-RPC POST per call.
    struct WakiTransport {
        url: String,
    }

    impl Transport for WakiTransport {
        fn send(&self, body: &serde_json::Value) -> Result<serde_json::Value, String> {
            waki::Client::new()
                .post(&self.url)
                .json(body)
                .connect_timeout(std::time::Duration::from_secs(10))
                .send()
                .map_err(|e| format!("RPC request failed: {e}"))?
                .json::<serde_json::Value>()
                .map_err(|e| format!("RPC returned non-JSON: {e}"))
        }
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
            "Assess the on-chain risk of a Solana token BEFORE interacting with it. \
             Give it a token mint address; it returns a red/amber/green verdict with \
             reasons: mint/freeze authority status, Token-2022 extension traps \
             (permanent delegate, transfer hooks, transfer fees, frozen-by-default, \
             pausable), and holder concentration. Read-only and safe to call \
             liberally — use it whenever a user mentions buying, receiving, or \
             evaluating an SPL token. May require operator approval."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 address of the token MINT (the token itself, not a wallet)."
                    }
                },
                "required": ["mint"],
                "additionalProperties": false
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let started = Instant::now();
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                        None,
                    );
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };

            let cfg = CheckConfig::from_section(&parsed.config);
            let transport = WakiTransport {
                url: cfg.rpc_url.clone(),
            };

            match run_check(&transport, &parsed.mint, &cfg.commitment) {
                Ok(output) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "risk check complete",
                        Some(started.elapsed().as_millis() as u64),
                    );
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(msg) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "risk check failed",
                        Some(started.elapsed().as_millis() as u64),
                    );
                    Ok(fail(msg))
                }
            }
        }
    }

    /// Bad input and unreachable RPCs are model-visible outcomes it can react
    /// to; `Err` is reserved for genuinely broken plugin states.
    fn fail(message: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, duration_ms: Option<u64>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
