//! A ZeroClaw WIT tool plugin: `sol_get_balance`.
//!
//! Reads a Solana account's native balance from a JSON-RPC endpoint
//! (`getBalance`) and returns it as both lamports and SOL. Read-only: it holds
//! no keys, signs nothing, and moves no funds. The RPC endpoint defaults to
//! Solana mainnet-beta and is overridable through the plugin's own jailed config
//! section (`rpc_url`, gated by the `config_read` permission).
//!
//! The pure request/response logic lives in [`balance`] with no wasm
//! dependency, so it compiles and tests on the host with a plain `cargo test`;
//! the wasm component reuses the exact same logic through this thin shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod balance;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::balance::{
        build_request_body, format_output, parse_balance_response, validate_pubkey, BalanceConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolGetBalance;

    const PLUGIN_NAME: &str = "sol-get-balance";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sol_get_balance";

    /// Outbound RPC connect timeout. Kept modest so a slow endpoint fails the
    /// call cleanly rather than burning the host's per-call fuel budget.
    const CONNECT_TIMEOUT_SECS: u64 = 10;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        address: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolGetBalance {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolGetBalance {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Look up the native SOL balance of a Solana account by its base58 \
             address. Returns the balance in both lamports and SOL by calling \
             the Solana JSON-RPC `getBalance` method. Read-only: requires no \
             keys and moves no funds. Defaults to Solana mainnet-beta and can be \
             pointed at a custom RPC endpoint by the operator."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "The account's base58-encoded Solana public key (decodes to 32 bytes), e.g. \"So11111111111111111111111111111111111111112\"."
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

            let cfg = BalanceConfig::from_section(&parsed.config);
            let body = build_request_body(&address);

            let resp = match waki::Client::new()
                .post(&cfg.rpc_url)
                .header("Content-Type", "application/json")
                .body(body.into_bytes())
                .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
                .send()
            {
                Ok(r) => r,
                Err(e) => {
                    return Ok(failure(
                        "rpc request failed",
                        format!("RPC request failed: {e}"),
                    ));
                }
            };

            let status = resp.status_code();
            let raw = match resp.body() {
                Ok(b) => b,
                Err(e) => {
                    return Ok(failure(
                        "rpc read failed",
                        format!("reading RPC response failed: {e}"),
                    ));
                }
            };
            let text = String::from_utf8_lossy(&raw);

            if !(200..300).contains(&status) {
                return Ok(failure(
                    "rpc http error",
                    format!("RPC returned HTTP {status}: {text}"),
                ));
            }

            match parse_balance_response(&text) {
                Ok(lamports) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "fetched balance",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: format_output(&address, lamports, &cfg.rpc_url),
                        error: None,
                    })
                }
                Err(e) => Ok(failure("rpc parse failed", e)),
            }
        }
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
                function_name: "sol_get_balance::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolGetBalance);
}
