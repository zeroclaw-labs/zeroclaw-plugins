//! A ZeroClaw WIT tool plugin: `sol_tx`.
//!
//! Looks up a Solana transaction by its base58 signature via the JSON-RPC
//! `getTransaction` method (`jsonParsed` encoding, `maxSupportedTransactionVersion:
//! 0`) and returns its status (success/failed), slot, block time, fee (lamports
//! and SOL), and the involved account keys. A signature that is valid but not
//! found or not yet finalized comes back cleanly as `found: false`. Read-only:
//! it holds no keys, signs nothing, and moves no funds. The RPC endpoint
//! defaults to Solana mainnet-beta and is overridable through the plugin's own
//! jailed config section (`rpc_url`, gated by the `config_read` permission).
//!
//! The pure request/response logic lives in [`tx`] with no wasm dependency, so
//! it compiles and tests on the host with a plain `cargo test`; the wasm
//! component reuses the exact same logic through this thin shim.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod tx;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use crate::tx::{
        build_request_body, format_output, parse_tx_response, validate_signature, TxConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolTx;

    const PLUGIN_NAME: &str = "sol-tx";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sol_tx";

    /// Outbound RPC connect timeout. Kept modest so a slow endpoint fails the
    /// call cleanly rather than burning the host's per-call fuel budget.
    const CONNECT_TIMEOUT_SECS: u64 = 10;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        signature: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SolTx {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolTx {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Look up a Solana transaction by its base58 signature. Returns whether \
             it succeeded or failed (with the on-chain error if any), the slot and \
             block time, the fee paid in lamports and SOL, and the account keys \
             involved, by calling the Solana JSON-RPC `getTransaction` method. A \
             signature that is valid but not found or not yet finalized comes back \
             as `found: false`. Read-only: requires no keys and moves no funds. \
             Defaults to Solana mainnet-beta."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "The transaction's base58-encoded signature (decodes to 64 bytes), e.g. \"5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW\"."
                    }
                },
                "required": ["signature"]
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

            let signature = match validate_signature(&parsed.signature) {
                Ok(s) => s,
                Err(e) => return Ok(failure("invalid signature", e)),
            };

            let cfg = TxConfig::from_section(&parsed.config);
            let body = build_request_body(&signature);

            let text = match post_json(&cfg.rpc_url, body) {
                Ok(t) => t,
                Err(e) => return Ok(failure("rpc request failed", e)),
            };

            match parse_tx_response(&signature, &text) {
                Ok(lookup) => {
                    // A not-found signature is a legitimate answer, not a fault,
                    // so it flows back as a successful tool result.
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "fetched transaction",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: format_output(&lookup, &signature, &cfg.rpc_url),
                        error: None,
                    })
                }
                Err(e) => Ok(failure("rpc parse failed", e)),
            }
        }
    }

    /// POST a JSON-RPC body and return the response text, mapping any transport
    /// or non-2xx result to a human-readable error string.
    fn post_json(url: &str, body: String) -> Result<String, String> {
        let resp = waki::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.into_bytes())
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .send()
            .map_err(|e| format!("RPC request failed: {e}"))?;
        let status = resp.status_code();
        let raw = resp
            .body()
            .map_err(|e| format!("reading RPC response failed: {e}"))?;
        let text = String::from_utf8_lossy(&raw).to_string();
        if !(200..300).contains(&status) {
            return Err(format!("RPC returned HTTP {status}: {text}"));
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
                function_name: "sol_tx::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolTx);
}
