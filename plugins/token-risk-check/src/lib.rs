//! ZeroClaw `token-risk-check` tool plugin.

pub mod liquidity;
pub mod model;
pub mod risk;
pub mod solana;

#[cfg(any(target_family = "wasm", test))]
mod deadline;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;

    use crate::{
        deadline::{read_all_bounded, wait_ready_until, DeadlineRead, DeadlineWait, ReadChunk},
        risk::{
            classify_transport_error, execute_json_with, tool_description, tool_name,
            tool_parameters_schema, Config, ReadTransport, Request, Response, TransportError,
        },
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
        io::{
            poll,
            streams::{InputStream, StreamError},
        },
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

    struct WasiWait<'a> {
        pollable: &'a poll::Pollable,
    }

    impl DeadlineWait for WasiWait<'_> {
        fn wait_until(&mut self, deadline_ns: u64) -> Result<bool, ()> {
            let timer = monotonic_clock::subscribe_instant(deadline_ns);
            let ready = poll::poll(&[self.pollable, &timer]);
            if ready.contains(&1) {
                Ok(false)
            } else if ready.contains(&0) {
                Ok(true)
            } else {
                Err(())
            }
        }
    }

    struct WasiInput<'a> {
        input: &'a InputStream,
        pollable: poll::Pollable,
    }

    impl DeadlineWait for WasiInput<'_> {
        fn wait_until(&mut self, deadline_ns: u64) -> Result<bool, ()> {
            WasiWait {
                pollable: &self.pollable,
            }
            .wait_until(deadline_ns)
        }
    }

    impl DeadlineRead for WasiInput<'_> {
        fn read_chunk(&mut self, max_bytes: u64) -> Result<ReadChunk, ()> {
            match self.input.read(max_bytes) {
                Ok(bytes) => Ok(ReadChunk::Data(bytes)),
                Err(StreamError::Closed) => Ok(ReadChunk::Closed),
                Err(_) => Err(()),
            }
        }
    }

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

        let deadline = monotonic_clock::now().saturating_add(REQUEST_TOTAL_TIMEOUT_NANOS);
        let future_response = outgoing_handler::handle(outgoing, Some(options))
            .map_err(|error| classify_transport_error(&format!("{error:?}")))?;
        write_outgoing_body(
            &outgoing_body,
            request.body.unwrap_or_default().as_bytes(),
            deadline,
        )?;
        OutgoingBody::finish(outgoing_body, None).map_err(|_| TransportError::Unavailable)?;

        let response_pollable = future_response.subscribe();
        wait_ready_until(
            &mut WasiWait {
                pollable: &response_pollable,
            },
            deadline,
        )
        .map_err(TransportError::from)?;
        let incoming = future_response
            .get()
            .ok_or(TransportError::Unavailable)?
            .map_err(|_| TransportError::Unavailable)?
            .map_err(|error| classify_transport_error(&format!("{error:?}")))?;
        drop(response_pollable);
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
        let input_pollable = input.subscribe();
        let mut reader = WasiInput {
            input: &input,
            pollable: input_pollable,
        };
        let body = read_all_bounded(
            &mut reader,
            deadline,
            BODY_CHUNK_BYTES,
            request.max_response_bytes,
        )
        .map_err(TransportError::from)?;
        drop(reader);
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
        deadline: u64,
    ) -> Result<(), TransportError> {
        if body.is_empty() {
            return Ok(());
        }
        let output = outgoing_body
            .write()
            .map_err(|_| TransportError::Unavailable)?;
        let pollable = output.subscribe();
        while !body.is_empty() {
            wait_ready_until(
                &mut WasiWait {
                    pollable: &pollable,
                },
                deadline,
            )
            .map_err(TransportError::from)?;
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
        wait_ready_until(
            &mut WasiWait {
                pollable: &pollable,
            },
            deadline,
        )
        .map_err(TransportError::from)?;
        output
            .check_write()
            .map_err(|_| TransportError::Unavailable)?;
        Ok(())
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
            let liquidity_url = parsed.config.get("liquidity_url").cloned();
            let model_args = serde_json::json!({"mint": parsed.mint}).to_string();
            emit(
                PluginAction::Query,
                PluginOutcome::Success,
                "starting bounded read-only assessment",
            );
            let output = execute_json_with(
                &model_args,
                &Config::with_liquidity_url(rpc_url, liquidity_url),
                &mut WasiTransport,
            );
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
