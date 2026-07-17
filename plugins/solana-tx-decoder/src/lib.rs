//! ZeroClaw WIT tool plugin: `solana-tx-decoder`.
//!
//! Fetches a Solana transaction by signature and returns a human-readable
//! summary — program names, SOL transfers, status, fee, accounts.
//! WASM HTTP transport uses `waki`; host tests use a mock client.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

// ── 1. Host-testable core (no wasm dependency) ──
mod tx_decoder;

// ── 2. WASM component shim ──
#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::tx_decoder;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SolanaTxDecoder;

    const PLUGIN_NAME: &str = "solana-tx-decoder";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana-tx-decoder";

    impl PluginInfo for SolanaTxDecoder {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaTxDecoder {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Decode a Solana transaction signature into a human-readable summary: program names, SOL transfers, status, and fee."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "The base58 transaction signature to decode"
                    },
                    "rpc": {
                        "type": "string",
                        "description": "Optional Solana RPC URL (defaults to mainnet-beta)"
                    }
                },
                "required": ["signature"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let v: serde_json::Value = match serde_json::from_str(&args) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("invalid JSON arguments: {e}");
                    emit(PluginAction::Fail, PluginOutcome::Failure, &msg);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(msg),
                    });
                }
            };

            let signature = match v["signature"].as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => {
                    let msg = "missing field: 'signature'".to_string();
                    emit(PluginAction::Fail, PluginOutcome::Failure, &msg);
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(msg),
                    });
                }
            };

            let rpc_url = v["rpc"]
                .as_str()
                .unwrap_or("https://api.mainnet-beta.solana.com")
                .to_string();

            let client = WasmHttpClient;

            match tx_decoder::decode_transaction(&client, &rpc_url, &signature) {
                Ok(report) => {
                    let json = serde_json::to_string_pretty(&report)
                        .unwrap_or_else(|_| "serialization error".to_string());
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        &format!("success={}", report.success),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: json,
                        error: None,
                    })
                }
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, &e);
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    })
                }
            }
        }
    }

    use tx_decoder::HttpClient;

    struct WasmHttpClient;

    impl HttpClient for WasmHttpClient {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(url)
                .header("Content-Type", "application/json")
                .body(body.as_bytes())
                .send()
                .map_err(|e| format!("HTTP request failed: {e}"))?;
            let bytes = resp
                .body()
                .map_err(|e| format!("Response read error: {e}"))?;
            String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in response: {e}"))
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_tx_decoder::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaTxDecoder);
}
