//! ZeroClaw `token-risk-check` tool plugin.

pub mod liquidity;
pub mod model;
pub mod risk;
pub mod solana;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::risk::{
        classify_transport_error, execute_json_with, tool_description, tool_name,
        tool_parameters_schema, Config, ReadTransport, Request, Response, TransportError,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use serde::Deserialize;
    use url::{Position, Url};
    use waki::bindings::wasi::{
        clocks::monotonic_clock,
        http::{
            outgoing_handler,
            types::{Headers, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme},
        },
        io::streams::StreamError,
    };
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const BODY_CHUNK_BYTES: u64 = 16 * 1024;
    const CONNECT_TIMEOUT_NANOS: u64 = 10_000_000_000;
    const FIRST_BYTE_TIMEOUT_NANOS: u64 = 10_000_000_000;
    const BETWEEN_BYTES_TIMEOUT_NANOS: u64 = 10_000_000_000;
    const REQUEST_TOTAL_TIMEOUT_NANOS: u64 = 20_000_000_000;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        mint: String,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct WasiTransport;

    impl ReadTransport for WasiTransport {
        fn send(&mut self, request: Request) -> Result<Response, TransportError> {
            send_bounded(request)
        }
    }

    fn send_bounded(request: Request) -> Result<Response, TransportError> {
        let url = Url::parse(&request.url).map_err(|_| TransportError::Unavailable)?;
        if url.scheme() != "https" {
            return Err(TransportError::Denied);
        }
        let method = match request.method {
            "GET" => Method::Get,
            "POST" => Method::Post,
            _ => return Err(TransportError::Unavailable),
        };
        let header_entries: Vec<(String, Vec<u8>)> = if request.method == "POST" {
            vec![("content-type".to_string(), b"application/json".to_vec())]
        } else {
            Vec::new()
        };
        let headers =
            Headers::from_list(&header_entries).map_err(|_| TransportError::Unavailable)?;
        let outgoing = OutgoingRequest::new(headers);
        outgoing
            .set_method(&method)
            .map_err(|_| TransportError::Unavailable)?;
        outgoing
            .set_scheme(Some(&Scheme::Https))
            .map_err(|_| TransportError::Unavailable)?;
        let authority = &url[Position::BeforeHost..Position::AfterPort];
        outgoing
            .set_authority(Some(authority))
            .map_err(|_| TransportError::Unavailable)?;
        let path_with_query = &url[Position::BeforePath..Position::AfterQuery];
        outgoing
            .set_path_with_query(Some(path_with_query))
            .map_err(|_| TransportError::Unavailable)?;

        let outgoing_body = outgoing.body().map_err(|_| TransportError::Unavailable)?;
        let options = RequestOptions::new();
        options
            .set_connect_timeout(Some(CONNECT_TIMEOUT_NANOS))
            .map_err(|_| TransportError::Unavailable)?;
        options
            .set_first_byte_timeout(Some(FIRST_BYTE_TIMEOUT_NANOS))
            .map_err(|_| TransportError::Unavailable)?;
        options
            .set_between_bytes_timeout(Some(BETWEEN_BYTES_TIMEOUT_NANOS))
            .map_err(|_| TransportError::Unavailable)?;

        let started = monotonic_clock::now();
        let future_response = outgoing_handler::handle(outgoing, Some(options))
            .map_err(|error| classify_transport_error(&format!("{error:?}")))?;
        write_outgoing_body(
            &outgoing_body,
            request.body.unwrap_or_default().as_bytes(),
            started,
        )?;
        OutgoingBody::finish(outgoing_body, None).map_err(|_| TransportError::Unavailable)?;

        let incoming = match future_response.get() {
            Some(result) => result.map_err(|_| TransportError::Unavailable)?,
            None => {
                if request_timed_out(started) {
                    return Err(TransportError::Timeout);
                }
                let pollable = future_response.subscribe();
                pollable.block();
                future_response
                    .get()
                    .ok_or(TransportError::Unavailable)?
                    .map_err(|_| TransportError::Unavailable)?
            }
        }
        .map_err(|error| classify_transport_error(&format!("{error:?}")))?;
        drop(future_response);

        let status = incoming.status();
        if (300..400).contains(&status) {
            return Err(TransportError::Redirect);
        }
        let incoming_body = incoming
            .consume()
            .map_err(|_| TransportError::Unavailable)?;
        drop(incoming);
        let input = incoming_body
            .stream()
            .map_err(|_| TransportError::Unavailable)?;
        let mut body = Vec::new();
        loop {
            if request_timed_out(started) {
                return Err(TransportError::Timeout);
            }
            match input.blocking_read(BODY_CHUNK_BYTES) {
                Ok(chunk) => {
                    if body.len().saturating_add(chunk.len()) > request.max_response_bytes {
                        return Err(TransportError::TooLarge);
                    }
                    body.extend_from_slice(&chunk);
                }
                Err(StreamError::Closed) => break,
                Err(_) => return Err(TransportError::Unavailable),
            }
        }
        drop(input);
        drop(incoming_body);
        Ok(Response {
            status,
            final_url: request.url,
            body,
        })
    }

    fn write_outgoing_body(
        outgoing_body: &OutgoingBody,
        mut body: &[u8],
        started: u64,
    ) -> Result<(), TransportError> {
        if body.is_empty() {
            return Ok(());
        }
        let output = outgoing_body
            .write()
            .map_err(|_| TransportError::Unavailable)?;
        let pollable = output.subscribe();
        while !body.is_empty() {
            if request_timed_out(started) {
                return Err(TransportError::Timeout);
            }
            pollable.block();
            let permit = output
                .check_write()
                .map_err(|_| TransportError::Unavailable)?;
            let len = body.len().min(permit as usize);
            let (chunk, remaining) = body.split_at(len);
            output
                .write(chunk)
                .map_err(|_| TransportError::Unavailable)?;
            body = remaining;
        }
        output.flush().map_err(|_| TransportError::Unavailable)?;
        pollable.block();
        output
            .check_write()
            .map_err(|_| TransportError::Unavailable)?;
        Ok(())
    }

    fn request_timed_out(started: u64) -> bool {
        monotonic_clock::now().saturating_sub(started) >= REQUEST_TOTAL_TIMEOUT_NANOS
    }

    struct TokenRiskCheck;

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            tool_name().to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            tool_name().to_string()
        }

        fn description() -> String {
            tool_description().to_string()
        }

        fn parameters_schema() -> String {
            tool_parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(value) => value,
                Err(_) => {
                    emit(
                        PluginAction::Validate,
                        PluginOutcome::Failure,
                        "invalid arguments",
                    );
                    let output =
                        crate::model::serialize_bounded(&crate::model::Assessment::unknown(
                            "",
                            "INVALID_EXECUTE_ARGS",
                            "arguments must contain only one canonical mint field",
                        ));
                    return Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    });
                }
            };
            let rpc_url = parsed.config.get("rpc_url").cloned().unwrap_or_default();
            let model_args = serde_json::json!({"mint": parsed.mint}).to_string();
            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "starting bounded read-only assessment",
            );
            let output = execute_json_with(&model_args, &Config::new(rpc_url), &mut WasiTransport);
            let complete = serde_json::from_str::<serde_json::Value>(&output)
                .ok()
                .and_then(|value| value.get("complete").and_then(serde_json::Value::as_bool))
                .unwrap_or(false);
            let (outcome, message) = if complete {
                (PluginOutcome::Success, "assessment complete")
            } else {
                (PluginOutcome::Failure, "assessment incomplete")
            };
            emit(PluginAction::Complete, outcome, message);
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
