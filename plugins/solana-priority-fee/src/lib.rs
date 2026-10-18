//! A ZeroClaw WIT tool plugin for bounded Solana priority-fee estimates.
//!
//! The pure request validation and fee analysis live in [`priority_fee`]. The
//! wasm-only shim performs one HTTPS JSON-RPC call through `wasi:http`; it never
//! accepts a private key, signs a transaction, or submits one.

pub mod priority_fee;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::priority_fee::{
        analyze_rpc_response, append_bounded_rpc_chunk, prepare_query, ToolArgs,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use waki::bindings::wasi::clocks::monotonic_clock;
    use waki::bindings::wasi::http::{
        outgoing_handler,
        types::{Fields, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme},
    };
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "solana-priority-fee";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_priority_fee";
    const RPC_READ_CHUNK_BYTES: u64 = 32 * 1024;
    const CONNECT_TIMEOUT_NS: u64 = 5_000_000_000;
    const FIRST_BYTE_TIMEOUT_NS: u64 = 10_000_000_000;
    const BETWEEN_BYTES_TIMEOUT_NS: u64 = 2_000_000_000;
    const TOTAL_RPC_TIMEOUT_NS: u64 = 20_000_000_000;

    struct SolanaPriorityFee;

    impl PluginInfo for SolanaPriorityFee {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaPriorityFee {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Estimate recent Solana priority fees for an optional writable-account set. Returns compact p50/p75/p90/p95 micro-lamports-per-compute-unit statistics and a recommendation capped by operator policy. Read-only: never signs or submits a transaction."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "writable_accounts": {
                        "type": "array",
                        "description": "Optional complete set of Solana accounts expected to be writable in the transaction.",
                        "items": {
                            "type": "string",
                            "minLength": 32,
                            "maxLength": 44
                        },
                        "maxItems": 128,
                        "uniqueItems": true
                    },
                    "percentile": {
                        "type": "integer",
                        "description": "Percentile used for the recommendation (1-99). Defaults to operator config, then 75.",
                        "minimum": 1,
                        "maximum": 99
                    }
                }
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ToolArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(_) => {
                    return failure(
                        "invalid arguments",
                        "arguments must match the published schema",
                    )
                }
            };

            let prepared = match prepare_query(&parsed) {
                Ok(value) => value,
                Err(error) => return failure("policy rejected request", &error),
            };

            let deadline = monotonic_clock::now().saturating_add(TOTAL_RPC_TIMEOUT_NS);
            let response = match send_rpc(&prepared.config.rpc_url, &prepared.request) {
                Ok(value) => value,
                Err(_) => return failure("rpc request failed", "Solana RPC request failed"),
            };

            if deadline_expired(deadline) {
                return failure(
                    "rpc total deadline exceeded",
                    "Solana RPC request timed out",
                );
            }

            if !(200..300).contains(&response.status_code()) {
                return failure(
                    "rpc returned non-success HTTP status",
                    "Solana RPC returned a non-success HTTP status",
                );
            }

            let body = match read_bounded_body(&response, deadline) {
                Ok(value) => value,
                Err(error) => return failure("rpc response rejected", &error),
            };

            let rpc_json = match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(value) => value,
                Err(_) => {
                    return failure("rpc response invalid", "Solana RPC returned invalid JSON")
                }
            };

            let summary = match analyze_rpc_response(
                &rpc_json,
                prepared.percentile,
                prepared.config.max_micro_lamports_per_cu,
                parsed.writable_accounts.len(),
            ) {
                Ok(value) => value,
                Err(error) => return failure("rpc response rejected", &error),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "priority fee estimate completed",
                Some(format!(
                    "{{\"samples\":{},\"percentile\":{}}}",
                    summary.sample_count, summary.selected_percentile
                )),
            );

            Ok(ToolResult {
                success: true,
                output: serde_json::to_string(&summary)
                    .map_err(|_| "failed to serialize summary".to_string())?,
                error: None,
            })
        }
    }

    fn send_rpc(url: &str, request: &serde_json::Value) -> Result<waki::Response, String> {
        let uri = url
            .parse::<http::Uri>()
            .map_err(|_| "invalid RPC URL".to_string())?;
        let authority = uri
            .authority()
            .ok_or_else(|| "RPC URL is missing an authority".to_string())?;
        let path_with_query = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        let headers =
            Fields::from_list(&[("content-type".to_string(), b"application/json".to_vec())])
                .map_err(|_| "failed to construct RPC headers".to_string())?;
        let outgoing = OutgoingRequest::new(headers);
        outgoing
            .set_method(&Method::Post)
            .map_err(|_| "failed to set RPC method".to_string())?;
        outgoing
            .set_scheme(Some(&Scheme::Https))
            .map_err(|_| "failed to set RPC scheme".to_string())?;
        outgoing
            .set_authority(Some(authority.as_str()))
            .map_err(|_| "failed to set RPC authority".to_string())?;
        outgoing
            .set_path_with_query(Some(path_with_query))
            .map_err(|_| "failed to set RPC path".to_string())?;

        let body = outgoing
            .body()
            .map_err(|_| "failed to open RPC request body".to_string())?;
        let options = RequestOptions::new();
        options
            .set_connect_timeout(Some(CONNECT_TIMEOUT_NS))
            .map_err(|_| "failed to set RPC connect timeout".to_string())?;
        options
            .set_first_byte_timeout(Some(FIRST_BYTE_TIMEOUT_NS))
            .map_err(|_| "failed to set RPC first-byte timeout".to_string())?;
        options
            .set_between_bytes_timeout(Some(BETWEEN_BYTES_TIMEOUT_NS))
            .map_err(|_| "failed to set RPC between-bytes timeout".to_string())?;

        let future = outgoing_handler::handle(outgoing, Some(options))
            .map_err(|_| "failed to start RPC request".to_string())?;
        let bytes = serde_json::to_vec(request)
            .map_err(|_| "failed to serialize RPC request".to_string())?;
        let output = body
            .write()
            .map_err(|_| "failed to write RPC request".to_string())?;
        for chunk in bytes.chunks(4096) {
            output
                .blocking_write_and_flush(chunk)
                .map_err(|_| "failed to write RPC request".to_string())?;
        }
        drop(output);
        OutgoingBody::finish(body, None).map_err(|_| "failed to finish RPC request".to_string())?;

        let incoming = match future.get() {
            Some(result) => result.map_err(|_| "RPC response already consumed".to_string())?,
            None => {
                let pollable = future.subscribe();
                pollable.block();
                future
                    .get()
                    .ok_or_else(|| "RPC response unavailable".to_string())?
                    .map_err(|_| "RPC response already consumed".to_string())?
            }
        }
        .map_err(|_| "RPC transport failed or timed out".to_string())?;
        drop(future);

        incoming
            .try_into()
            .map_err(|_| "failed to decode RPC response".to_string())
    }

    fn read_bounded_body(response: &waki::Response, deadline: u64) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        loop {
            if deadline_expired(deadline) {
                return Err("Solana RPC response exceeded the total time limit".to_string());
            }
            let chunk = response
                .chunk(RPC_READ_CHUNK_BYTES)
                .map_err(|_| "Solana RPC response could not be read".to_string())?;
            if deadline_expired(deadline) {
                return Err("Solana RPC response exceeded the total time limit".to_string());
            }
            let Some(chunk) = chunk else {
                break;
            };
            append_bounded_rpc_chunk(&mut body, &chunk)?;
        }
        Ok(body)
    }

    fn deadline_expired(deadline: u64) -> bool {
        monotonic_clock::now() >= deadline
    }

    fn failure(message: &str, public_error: &str) -> Result<ToolResult, String> {
        emit(PluginAction::Fail, PluginOutcome::Failure, message, None);
        Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(public_error.to_string()),
        })
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, attrs: Option<String>) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_priority_fee::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaPriorityFee);
}
