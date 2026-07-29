//! A ZeroClaw WIT tool plugin: `token-risk-check`.
//!
//! Assesses the on-chain risk of a Solana token mint before the agent trades
//! or displays it: `execute` fetches the mint account over Solana JSON-RPC
//! (`getAccountInfo`, jsonParsed), then classifies the authorities and
//! Token-2022 extensions into a red/amber/green verdict with per-signal
//! reasons. Every fetch/parse failure is fail-closed: an error result with no
//! verdict, never green.
//!
//! The pure core lives in [`assess`] (no wasm/http deps) behind the
//! `MintFetcher` seam, so it is host-tested with mocked RPC via a plain
//! `cargo test`; this file is the thin component shim that injects the real
//! blocking `waki` client (wasi:http, TLS host-side).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

pub mod assess;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use serde_json::Value;

    use crate::assess::{
        attach_untrusted_metadata, build_account_info_request, build_account_info_request_base64,
        classify, fetch_and_parse, fetch_metadata, resolve_rpc_url, MetadataFetcher, MintFetcher,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token-risk-check";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint: String,
        // Injected by the host under the config_read permission (rpc_url).
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    /// Real transport for the `MintFetcher` seam: blocking waki POST of the
    /// JSON-RPC body, same call pattern as the telegram plugin. The URL may
    /// embed a private API key and is never logged.
    struct WakiFetcher {
        rpc_url: String,
    }

    impl WakiFetcher {
        fn post(&self, body: &Value) -> Result<Value, String> {
            waki::Client::new()
                .post(&self.rpc_url)
                .json(body)
                .send()
                .map_err(|e| e.to_string())?
                .json::<Value>()
                .map_err(|e| e.to_string())
        }
    }

    impl MintFetcher for WakiFetcher {
        fn fetch(&self, mint: &str) -> Result<Value, String> {
            self.post(&build_account_info_request(mint))
        }
    }

    impl MetadataFetcher for WakiFetcher {
        fn fetch_base64(&self, address: &str) -> Result<Value, String> {
            self.post(&build_account_info_request_base64(address))
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
            "Assess the on-chain risk of a Solana token before trading or displaying it: \
             pass the token's base58 mint address to get a green/yellow/red verdict with \
             the reasons and the list of checks performed."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58-encoded Solana token mint address to assess."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "invalid arguments");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            let fetcher = WakiFetcher {
                rpc_url: resolve_rpc_url(&parsed.config),
            };

            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "calling getAccountInfo for mint",
            );

            // Fail-closed: any transport, RPC, not-found, or parse failure is
            // an error result — never a green (or any) verdict.
            let account = match fetch_and_parse(&parsed.mint, &fetcher) {
                Ok(a) => a,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "mint fetch failed");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("token-risk-check failed (fail-closed): {e}")),
                    });
                }
            };

            // Classification is pure and only ever runs on a successfully
            // parsed account — every failure above returned with no verdict.
            let mut result = classify(&parsed.mint, &account);

            // Metadata is fetched AFTER the verdict is fixed and attached as
            // labeled untrusted data — it is structurally not a classify
            // input, and its absence or failure never changes the verdict.
            let metadata = fetch_metadata(&parsed.mint, &account, &fetcher);
            emit(
                PluginAction::Note,
                PluginOutcome::Success,
                if metadata.is_some() {
                    "attached untrusted token metadata"
                } else {
                    "no token metadata available (verdict unaffected)"
                },
            );
            attach_untrusted_metadata(&mut result, metadata);

            let output = match serde_json::to_string(&result) {
                Ok(s) => s,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "serialization failed");
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("serialization failed: {e}")),
                    });
                }
            };

            emit(PluginAction::Complete, PluginOutcome::Success, "mint assessed");

            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
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
