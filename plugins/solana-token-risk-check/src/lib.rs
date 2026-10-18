//! ZeroClaw T0 tool plugin for read-only Solana token risk checks.
//!
//! The host-testable parser and policy live in [`risk`]. This thin component
//! shim performs four unsigned JSON-RPC reads through `wasi:http`, then passes
//! their untrusted JSON to the pure core.

pub mod risk;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use wstd::future::FutureExt;
    use wstd::http::{Body, BodyExt, Client, Request};
    use wstd::time::Duration;

    use crate::risk::{
        append_bounded_chunk, check_with_transport, parse_bounded_json, validate_http_status,
        validate_mint, Config, RpcTransport, MAX_RPC_RESPONSE_BYTES,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_token_risk_check";
    const RPC_PHASE_TIMEOUT_SECS: u64 = 10;
    const RPC_TOTAL_TIMEOUT_SECS: u64 = 30;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct SolanaTokenRiskCheck;

    impl PluginInfo for SolanaTokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaTokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read-only Solana token risk check. Inspects mint/freeze authority, dangerous Token-2022 extensions, and concentration among the RPC's largest token accounts. Never accepts a private key, signs, simulates, or submits transactions. Results are bounded heuristics, not financial advice."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "mint": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "description": "Base58 Solana mint address. Never provide a private key or seed phrase."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            if args.len() > 8192 {
                return Ok(failure("arguments exceed 8192 bytes"));
            }
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(_) => return Ok(failure("invalid arguments")),
            };
            if let Err(error) = validate_mint(&parsed.mint) {
                return Ok(failure(error));
            }
            let config = match Config::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return Ok(failure(error)),
            };

            let mut transport = WasiRpc {
                url: &config.rpc_url,
            };
            match check_with_transport(&parsed.mint, &mut transport) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        report.findings.len(),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&report)
                            .map_err(|_| "could not encode bounded report".to_string())?,
                        error: None,
                    })
                }
                Err(error) => Ok(failure(error)),
            }
        }
    }

    struct WasiRpc<'a> {
        url: &'a str,
    }

    impl RpcTransport for WasiRpc<'_> {
        fn send(&mut self, body: &Value) -> Result<Value, &'static str> {
            let request = Request::post(self.url)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(body).map_err(|_| "RPC request encode failed")?,
                ))
                .map_err(|_| "RPC request build failed")?;

            let mut client = Client::new();
            client.set_connect_timeout(Duration::from_secs(RPC_PHASE_TIMEOUT_SECS));
            client.set_first_byte_timeout(Duration::from_secs(RPC_PHASE_TIMEOUT_SECS));
            client.set_between_bytes_timeout(Duration::from_secs(RPC_PHASE_TIMEOUT_SECS));

            let bytes = wstd::runtime::block_on(async move {
                async move {
                    let response = client
                        .send(request)
                        .await
                        .map_err(|_| "RPC request failed")?;
                    validate_http_status(response.status().as_u16())?;
                    let mut response_body = response.into_body().into_boxed_body();
                    let mut bytes = Vec::new();
                    while let Some(frame) = response_body.frame().await {
                        let frame = frame.map_err(|_| "RPC response read failed")?;
                        if let Ok(chunk) = frame.into_data() {
                            append_bounded_chunk(&mut bytes, &chunk, MAX_RPC_RESPONSE_BYTES)?;
                        }
                    }
                    Ok::<_, &'static str>(bytes)
                }
                .timeout(Duration::from_secs(RPC_TOTAL_TIMEOUT_SECS))
                .await
            })
            .map_err(|_| "RPC request timed out")??;
            parse_bounded_json(&bytes)
        }
    }

    fn failure(message: &'static str) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, 0);
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message.to_string()),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, findings: usize) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(format!("{{\"findings\":{findings}}}")),
                message: "completed read-only token risk check".to_string(),
            },
        );
    }

    export!(SolanaTokenRiskCheck);
}
