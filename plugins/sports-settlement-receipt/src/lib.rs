//! ZeroClaw `sports_settlement_receipt` tool plugin.
//!
//! The pure implementation lives in [`core`]. The wasm-only module below is a
//! thin WIT/WASI HTTP shim: one fixed TxLINE stat-validation GET followed by
//! fixed finalized status/transaction reads from two or three RPC providers.
//! It never signs or submits.

pub mod core;
pub mod quorum;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use url::{Position, Url};

    use crate::core::{
        build_attestation_plan, compile_market, parameters_schema, parse_execute_args,
        parse_stat_validation_response, stat_validation_url, unknown_report, verified_report,
        PluginConfig, VerifiedAttestation, MAX_RESPONSE_BODY_BYTES,
    };
    use crate::quorum::{
        classify_quorum, inspect_provider, quorum_request_bodies, verify_attestation_response,
        AttestationBinding, ProviderState, QuorumVerdict,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use waki::bindings::wasi::clocks::monotonic_clock;
    use waki::bindings::wasi::http::{
        outgoing_handler,
        types::{
            ErrorCode, FutureIncomingResponse, Headers, IncomingResponse, Method, OutgoingBody,
            OutgoingRequest, RequestOptions, Scheme,
        },
    };
    use waki::bindings::wasi::io::{
        poll::{self, Pollable},
        streams::{InputStream, StreamError},
    };
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    const PLUGIN_NAME: &str = "sports-settlement-receipt";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "sports_settlement_receipt";
    const MAX_RESPONSE_CHUNK_BYTES: usize = 64 * 1024;

    struct SportsSettlementReceipt;

    impl PluginInfo for SportsSettlementReceipt {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SportsSettlementReceipt {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Bind an authenticated final TxLINE soccer proof to an existing finalized Solana \
             SettleTrace attestation using a fail-closed 2-of-3 RPC quorum. Returns a compact \
             receipt or UNKNOWN. It cannot hold keys, sign, submit, bet, trade, or pay funds."
                .to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed = match parse_execute_args(&args) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), None, None)),
            };
            let fixture_id = Some(parsed.fixture_id);
            let sequence = Some(parsed.sequence);
            let config = match PluginConfig::from_section(&parsed.config) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };
            let market = match compile_market(&parsed.market) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };

            let proof_url = match stat_validation_url(
                &config.txline_base_url,
                parsed.fixture_id,
                parsed.sequence,
            ) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };
            let proof_target = match request_target(HttpMethod::Get, &proof_url) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };
            let proof_headers = [
                ("Accept".to_string(), b"application/json".to_vec()),
                (
                    "Authorization".to_string(),
                    format!("Bearer {}", config.txline_session_jwt).into_bytes(),
                ),
                (
                    "X-Api-Token".to_string(),
                    config.txline_api_token.as_bytes().to_vec(),
                ),
            ];
            let proof_body = match send_request(&proof_target, &proof_headers, None) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };
            let proof = match parse_stat_validation_response(&proof_body, parsed.fixture_id) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };
            let plan = match build_attestation_plan(&proof, &market) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };
            let request_bodies = match quorum_request_bodies(&parsed.attestation_signature) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };

            let mut providers = Vec::with_capacity(config.rpc_urls.len());
            let mut bindings: Vec<AttestationBinding> = Vec::new();
            for (index, rpc_url) in config.rpc_urls.iter().enumerate() {
                let provider = (index + 1) as u8;
                let status_response = post_rpc(rpc_url, &request_bodies[0]);
                let transaction_response = post_rpc(rpc_url, &request_bodies[1]);
                let status_view = match &status_response {
                    Ok(body) => Ok(body.as_str()),
                    Err(code) => Err(*code),
                };
                let transaction_view = match &transaction_response {
                    Ok(body) => Ok(body.as_str()),
                    Err(code) => Err(*code),
                };
                let mut evidence = inspect_provider(
                    provider,
                    &parsed.attestation_signature,
                    status_view,
                    transaction_view,
                );
                if evidence.state == ProviderState::Complete {
                    match &transaction_response {
                        Ok(body) => match verify_attestation_response(
                            body,
                            &parsed.attestation_signature,
                            parsed.fixture_id,
                            parsed.sequence,
                            &plan,
                        ) {
                            Ok(binding) => bindings.push(binding),
                            Err(error) => {
                                evidence = evidence.binding_diverged(error.code());
                            }
                        },
                        Err(code) => evidence = evidence.binding_diverged(code),
                    }
                }
                providers.push(evidence);
            }

            let decision = classify_quorum(providers);
            if decision.verdict != QuorumVerdict::Consistent {
                return Ok(unknown_result(&decision.code, fixture_id, sequence));
            }
            let Some(binding) = bindings.first() else {
                return Ok(unknown_result(
                    "ATTESTATION_BINDING_QUORUM_MISSING",
                    fixture_id,
                    sequence,
                ));
            };
            if bindings.len() < 2 || bindings.iter().any(|candidate| candidate != binding) {
                return Ok(unknown_result(
                    "ATTESTATION_BINDING_DIVERGED",
                    fixture_id,
                    sequence,
                ));
            }
            let quorum = match serde_json::to_value(&decision) {
                Ok(value) => value,
                Err(_) => {
                    return Ok(unknown_result(
                        "OUTPUT_SERIALIZATION_ERROR",
                        fixture_id,
                        sequence,
                    ));
                }
            };
            let attestation = VerifiedAttestation {
                signature: &parsed.attestation_signature,
                finalized_slot: binding.finalized_slot,
                transaction_sha256: &binding.transaction_sha256,
                memo_receipt_sha256: &binding.memo_receipt_sha256,
                quorum: &quorum,
            };
            let output = match verified_report(
                parsed.fixture_id,
                parsed.sequence,
                &proof,
                &market,
                &plan,
                &attestation,
            ) {
                Ok(value) => value,
                Err(error) => return Ok(unknown_result(error.code(), fixture_id, sequence)),
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                "FINALIZED_RECEIPT_VERIFIED",
            );
            Ok(ToolResult {
                success: true,
                output,
                error: None,
            })
        }
    }

    fn post_rpc(endpoint: &str, body: &str) -> Result<String, &'static str> {
        let target = request_target(HttpMethod::Post, endpoint).map_err(ShimError::code)?;
        let headers = [
            ("Accept".to_string(), b"application/json".to_vec()),
            ("Content-Type".to_string(), b"application/json".to_vec()),
        ];
        send_request(&target, &headers, Some(body.as_bytes())).map_err(ShimError::code)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HttpMethod {
        Get,
        Post,
    }

    struct HttpRequestTarget {
        method: HttpMethod,
        authority: String,
        path_with_query: String,
    }

    fn request_target(method: HttpMethod, endpoint: &str) -> Result<HttpRequestTarget, ShimError> {
        let url = Url::parse(endpoint).map_err(|_| ShimError::HttpTransport)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ShimError::HttpTransport);
        }
        Ok(HttpRequestTarget {
            method,
            authority: url[Position::BeforeHost..Position::AfterPort].to_string(),
            path_with_query: url[Position::BeforePath..Position::AfterQuery].to_string(),
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ShimError {
        HttpTransport,
        Timeout,
        HttpStatus,
        BodyRead,
        ResponseTooLarge,
        ResponseBufferFailure,
        ResponseNotUtf8,
    }

    impl ShimError {
        fn code(self) -> &'static str {
            match self {
                Self::HttpTransport => "HTTP_TRANSPORT_ERROR",
                Self::Timeout => "TIMEOUT",
                Self::HttpStatus => "HTTP_STATUS_ERROR",
                Self::BodyRead => "HTTP_BODY_READ_ERROR",
                Self::ResponseTooLarge => "RESPONSE_TOO_LARGE",
                Self::ResponseBufferFailure => "RESPONSE_BUFFER_ERROR",
                Self::ResponseNotUtf8 => "RESPONSE_NOT_UTF8",
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct Deadline {
        expires_at_ns: u64,
    }

    impl Deadline {
        fn new(start_ns: u64, duration_ns: u64) -> Result<Self, ShimError> {
            Ok(Self {
                expires_at_ns: start_ns
                    .checked_add(duration_ns)
                    .ok_or(ShimError::Timeout)?,
            })
        }

        fn remaining_ns(self, now_ns: u64) -> Result<u64, ShimError> {
            self.expires_at_ns
                .checked_sub(now_ns)
                .filter(|remaining| *remaining > 0)
                .ok_or(ShimError::Timeout)
        }
    }

    struct ResponseAccumulator {
        bytes: Vec<u8>,
    }

    impl ResponseAccumulator {
        fn new() -> Self {
            Self { bytes: Vec::new() }
        }

        fn next_chunk_len(&self) -> u64 {
            let remaining = MAX_RESPONSE_BODY_BYTES - self.bytes.len();
            remaining.saturating_add(1).min(MAX_RESPONSE_CHUNK_BYTES) as u64
        }

        fn push(&mut self, chunk: &[u8]) -> Result<(), ShimError> {
            let new_len = self
                .bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(ShimError::ResponseTooLarge)?;
            if new_len > MAX_RESPONSE_BODY_BYTES {
                return Err(ShimError::ResponseTooLarge);
            }
            self.bytes
                .try_reserve(chunk.len())
                .map_err(|_| ShimError::ResponseBufferFailure)?;
            self.bytes.extend_from_slice(chunk);
            Ok(())
        }

        fn finish(self) -> Result<String, ShimError> {
            String::from_utf8(self.bytes).map_err(|_| ShimError::ResponseNotUtf8)
        }
    }

    fn send_request(
        target: &HttpRequestTarget,
        headers: &[(String, Vec<u8>)],
        request_body: Option<&[u8]>,
    ) -> Result<String, ShimError> {
        if !matches!(
            (target.method, request_body),
            (HttpMethod::Get, None) | (HttpMethod::Post, Some(_))
        ) {
            return Err(ShimError::HttpTransport);
        }
        let headers = Headers::from_list(headers).map_err(|_| ShimError::HttpTransport)?;
        let request = OutgoingRequest::new(headers);
        request
            .set_method(&match target.method {
                HttpMethod::Get => Method::Get,
                HttpMethod::Post => Method::Post,
            })
            .map_err(|_| ShimError::HttpTransport)?;
        request
            .set_scheme(Some(&Scheme::Https))
            .map_err(|_| ShimError::HttpTransport)?;
        request
            .set_authority(Some(&target.authority))
            .map_err(|_| ShimError::HttpTransport)?;
        request
            .set_path_with_query(Some(&target.path_with_query))
            .map_err(|_| ShimError::HttpTransport)?;

        let outgoing_body = request.body().map_err(|_| ShimError::HttpTransport)?;
        let options = RequestOptions::new();
        options
            .set_connect_timeout(Some(5_000_000_000))
            .map_err(|_| ShimError::HttpTransport)?;
        options
            .set_first_byte_timeout(Some(10_000_000_000))
            .map_err(|_| ShimError::HttpTransport)?;
        options
            .set_between_bytes_timeout(Some(5_000_000_000))
            .map_err(|_| ShimError::HttpTransport)?;

        let header_deadline = Deadline::new(monotonic_clock::now(), 15_000_000_000)?;
        let future =
            outgoing_handler::handle(request, Some(options)).map_err(classify_http_error)?;
        if let Some(bytes) = request_body {
            write_request_body(&outgoing_body, bytes, header_deadline)?;
        }
        OutgoingBody::finish(outgoing_body, None).map_err(|_| ShimError::HttpTransport)?;
        let response = await_response(&future, header_deadline)?;
        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(ShimError::HttpStatus);
        }
        read_response(response)
    }

    fn write_request_body(
        outgoing_body: &OutgoingBody,
        mut bytes: &[u8],
        deadline: Deadline,
    ) -> Result<(), ShimError> {
        let stream = outgoing_body
            .write()
            .map_err(|_| ShimError::HttpTransport)?;
        while !bytes.is_empty() {
            wait_for_pollable(&stream.subscribe(), deadline)?;
            let permit = stream
                .check_write()
                .map_err(|error| classify_stream_error(&error, ShimError::HttpTransport))?;
            if permit == 0 {
                continue;
            }
            let len = bytes.len().min(permit as usize);
            let (chunk, remaining) = bytes.split_at(len);
            stream
                .write(chunk)
                .map_err(|error| classify_stream_error(&error, ShimError::HttpTransport))?;
            bytes = remaining;
        }
        stream
            .flush()
            .map_err(|error| classify_stream_error(&error, ShimError::HttpTransport))?;
        wait_for_pollable(&stream.subscribe(), deadline)?;
        stream
            .check_write()
            .map_err(|error| classify_stream_error(&error, ShimError::HttpTransport))?;
        drop(stream);
        Ok(())
    }

    fn await_response(
        future: &FutureIncomingResponse,
        deadline: Deadline,
    ) -> Result<IncomingResponse, ShimError> {
        let response = match future.get() {
            Some(response) => response,
            None => {
                wait_for_pollable(&future.subscribe(), deadline)?;
                future.get().ok_or(ShimError::HttpTransport)?
            }
        };
        response
            .map_err(|_| ShimError::HttpTransport)?
            .map_err(classify_http_error)
    }

    fn read_response(response: IncomingResponse) -> Result<String, ShimError> {
        let body = response.consume().map_err(|_| ShimError::BodyRead)?;
        drop(response);
        let stream = body.stream().map_err(|_| ShimError::BodyRead)?;
        let total_deadline = Deadline::new(monotonic_clock::now(), 15_000_000_000)?;
        let mut accumulator = ResponseAccumulator::new();
        loop {
            let idle_deadline = Deadline::new(monotonic_clock::now(), 5_000_000_000)?;
            wait_for_stream(&stream, total_deadline, idle_deadline)?;
            match stream.read(accumulator.next_chunk_len()) {
                Ok(chunk) if chunk.is_empty() => return Err(ShimError::BodyRead),
                Ok(chunk) => accumulator.push(&chunk)?,
                Err(StreamError::Closed) => break,
                Err(error) => return Err(classify_stream_error(&error, ShimError::BodyRead)),
            }
        }
        drop(stream);
        drop(body);
        accumulator.finish()
    }

    fn wait_for_stream(
        stream: &InputStream,
        total_deadline: Deadline,
        idle_deadline: Deadline,
    ) -> Result<(), ShimError> {
        let now = monotonic_clock::now();
        let duration = total_deadline
            .remaining_ns(now)?
            .min(idle_deadline.remaining_ns(now)?);
        wait_for_duration(&stream.subscribe(), duration)
    }

    fn wait_for_pollable(pollable: &Pollable, deadline: Deadline) -> Result<(), ShimError> {
        wait_for_duration(pollable, deadline.remaining_ns(monotonic_clock::now())?)
    }

    fn wait_for_duration(pollable: &Pollable, duration_ns: u64) -> Result<(), ShimError> {
        let timer = monotonic_clock::subscribe_duration(duration_ns);
        let ready = poll::poll(&[pollable, &timer]);
        if ready.contains(&1) {
            return Err(ShimError::Timeout);
        }
        if ready.contains(&0) {
            Ok(())
        } else {
            Err(ShimError::HttpTransport)
        }
    }

    fn classify_http_error(error: ErrorCode) -> ShimError {
        match error {
            ErrorCode::DnsTimeout
            | ErrorCode::ConnectionTimeout
            | ErrorCode::ConnectionReadTimeout
            | ErrorCode::ConnectionWriteTimeout
            | ErrorCode::HttpResponseTimeout => ShimError::Timeout,
            _ => ShimError::HttpTransport,
        }
    }

    fn classify_stream_error(error: &StreamError, fallback: ShimError) -> ShimError {
        match error {
            StreamError::LastOperationFailed(error)
                if error
                    .to_debug_string()
                    .to_ascii_lowercase()
                    .contains("timeout") =>
            {
                ShimError::Timeout
            }
            StreamError::LastOperationFailed(_) | StreamError::Closed => fallback,
        }
    }

    fn unknown_result(code: &str, fixture_id: Option<u64>, sequence: Option<u64>) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, code);
        ToolResult {
            success: false,
            output: unknown_report(code, fixture_id, sequence),
            error: Some(code.to_string()),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, code: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "sports_settlement_receipt::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(format!(r#"{{"code":"{code}"}}"#)),
                message: code.to_string(),
            },
        );
    }

    export!(SportsSettlementReceipt);
}
