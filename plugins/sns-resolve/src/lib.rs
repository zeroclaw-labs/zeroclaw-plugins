//! A ZeroClaw WIT tool plugin: `sns_resolve`.
//!
//! Resolves a Solana Name Service (`.sol`) domain to the wallet address that
//! owns it — custody tier T0: pure reads, no keys, no state. Its whole purpose
//! is to stop an agent hallucinating an address: a user says "pay lucas.sol"
//! and the agent derives and verifies the real one on-chain first.
//!
//! The pure core lives in [`resolve`] with no wasm dependency and is
//! host-tested against a mock RPC with plain `cargo test`; this file is the
//! thin component shim wiring it to the `tool-plugin` WIT world with the
//! blocking `waki` client (TLS is performed host-side).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod resolve;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::resolve::{resolve_domain, ResolveConfig};
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
                .body(body.as_bytes().to_vec())
                .send()
                .map_err(|e| format!("rpc request failed: {e}"))?;
            let bytes = response
                .body()
                .map_err(|e| format!("rpc response read failed: {e}"))?;
            String::from_utf8(bytes).map_err(|_| "rpc response is not UTF-8".to_string())
        }
    }

    struct SnsResolve;

    const PLUGIN_NAME: &str = "sns-resolve";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sns_resolve";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        domain: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    impl PluginInfo for SnsResolve {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SnsResolve {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Resolve a Solana Name Service (.sol) domain to its on-chain wallet address. \
             Use this BEFORE sending funds to a human-readable name like \"lucas.sol\" so \
             the address is derived and verified on-chain, never guessed. Read-only; \
             touches no funds and no keys."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The .sol domain to resolve, e.g. \"lucas.sol\" or \"lucas\"."
                    }
                },
                "required": ["domain"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    return Ok(fail(format!("invalid arguments: {e}")));
                }
            };
            // Bound the domain before it can be echoed into an error;
            // normalization enforces a tighter label bound afterward.
            if parsed.domain.len() > 64 {
                emit(
                    PluginAction::Fail,
                    PluginOutcome::Failure,
                    "domain too long",
                );
                return Ok(fail("refused: domain is too long".to_string()));
            }
            let cfg = ResolveConfig::from_section(&parsed.config);

            match resolve_domain(&WakiTransport, &parsed.domain, &cfg) {
                Ok(res) => {
                    emit(
                        PluginAction::Resolve,
                        PluginOutcome::Success,
                        "domain resolved",
                    );
                    Ok(clamp(ToolResult {
                        success: true,
                        output: res.text,
                        error: None,
                    }))
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "resolution failed",
                    );
                    Ok(fail(e))
                }
            }
        }
    }

    /// Final backstop: a resolution is two addresses; nothing here should ever
    /// be large, but bound the WIT-edge output regardless.
    const MAX_RESULT_CHARS: usize = 512;

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
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "sns_resolve::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SnsResolve);
}
