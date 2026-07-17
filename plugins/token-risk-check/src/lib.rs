pub mod liquidity;
pub mod risk;

pub use risk::{owner_accounts_request_body, OWNER_ACCOUNTS_REQUEST_ID};

use url::{Position, Url};

use risk::{validate_mint, ACCOUNT_REQUEST_ID, LARGEST_ACCOUNTS_REQUEST_ID};

const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestTarget {
    pub method: HttpMethod,
    pub scheme: String,
    pub authority: String,
    pub path_with_query: String,
}

pub fn http_request_target(
    method: HttpMethod,
    endpoint: &str,
) -> Result<HttpRequestTarget, ShimError> {
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
        scheme: url.scheme().to_owned(),
        authority: url[Position::BeforeHost..Position::AfterPort].to_owned(),
        path_with_query: url[Position::BeforePath..Position::AfterQuery].to_owned(),
    })
}

pub fn liquidity_get_request(mint: &str) -> Result<HttpRequestTarget, ShimError> {
    let endpoint = liquidity::liquidity_url(mint).map_err(|_| ShimError::InvalidMint)?;
    http_request_target(HttpMethod::Get, &endpoint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeouts {
    pub connect_ns: u64,
    pub first_byte_ns: u64,
    pub between_bytes_ns: u64,
    pub full_response_ns: u64,
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            connect_ns: 5_000_000_000,
            first_byte_ns: 10_000_000_000,
            between_bytes_ns: 5_000_000_000,
            full_response_ns: 15_000_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    expires_at_ns: u64,
}

impl Deadline {
    pub fn new(start_ns: u64, duration_ns: u64) -> Result<Self, ShimError> {
        let expires_at_ns = start_ns
            .checked_add(duration_ns)
            .ok_or(ShimError::Timeout)?;
        Ok(Self { expires_at_ns })
    }

    pub fn remaining_ns(self, now_ns: u64) -> Result<u64, ShimError> {
        self.expires_at_ns
            .checked_sub(now_ns)
            .filter(|remaining| *remaining > 0)
            .ok_or(ShimError::Timeout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimError {
    InvalidMint,
    RequestSerialization,
    HttpTransport,
    Timeout,
    HttpStatus,
    BodyRead,
    ResponseTooLarge,
    ResponseBufferFailure,
    ResponseNotUtf8,
}

impl ShimError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidMint => "INVALID_MINT",
            Self::RequestSerialization => "REQUEST_SERIALIZATION_ERROR",
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

#[derive(Debug, Default)]
pub struct ResponseBodyAccumulator {
    bytes: Vec<u8>,
}

impl ResponseBodyAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Result<(), ShimError> {
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

    pub fn next_chunk_len(&self) -> u64 {
        let remaining = MAX_RESPONSE_BODY_BYTES - self.bytes.len();
        remaining.saturating_add(1).min(MAX_RESPONSE_CHUNK_BYTES) as u64
    }

    pub fn finish(self) -> Result<String, ShimError> {
        String::from_utf8(self.bytes).map_err(|_| ShimError::ResponseNotUtf8)
    }
}

pub fn rpc_request_bodies(mint: &str) -> Result<[String; 2], ShimError> {
    validate_mint(mint).map_err(|_| ShimError::InvalidMint)?;
    let account = serde_json::json!({
        "jsonrpc": "2.0",
        "id": ACCOUNT_REQUEST_ID,
        "method": "getAccountInfo",
        "params": [mint, {"encoding": "jsonParsed"}],
    });
    let largest = serde_json::json!({
        "jsonrpc": "2.0",
        "id": LARGEST_ACCOUNTS_REQUEST_ID,
        "method": "getTokenLargestAccounts",
        "params": [mint],
    });
    Ok([
        serde_json::to_string(&account).map_err(|_| ShimError::RequestSerialization)?,
        serde_json::to_string(&largest).map_err(|_| ShimError::RequestSerialization)?,
    ])
}

pub fn bounded_response_body(status: u16, body: Vec<u8>) -> Result<String, ShimError> {
    if !(200..300).contains(&status) {
        return Err(ShimError::HttpStatus);
    }
    let mut accumulator = ResponseBodyAccumulator::new();
    accumulator.push_chunk(&body)?;
    accumulator.finish()
}

pub fn parameters_schema() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {"mint": {"type": "string"}},
        "required": ["mint"],
        "additionalProperties": false,
    })
    .to_string()
}

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::risk::{
        assess, owner_accounts_request_body, parse_execute_args, serialize_report, unknown_report,
        Verdict,
    };
    use crate::{
        http_request_target, liquidity_get_request, parameters_schema, rpc_request_bodies,
        Deadline, HttpMethod, HttpRequestTarget, HttpTimeouts, ResponseBodyAccumulator, ShimError,
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

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = "0.1.0";
    const TOOL_NAME: &str = "token_risk_check";

    struct TokenRiskCheck;

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
            "Assess Solana mint risk from fixed JSON-RPC evidence.".to_string()
        }

        fn parameters_schema() -> String {
            parameters_schema()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed = match parse_execute_args(&args) {
                Ok(parsed) => parsed,
                Err(error) => return Ok(unknown_result(error.code())),
            };
            let [account_request, largest_request] = match rpc_request_bodies(&parsed.mint) {
                Ok(requests) => requests,
                Err(error) => return Ok(unknown_result(error.code())),
            };
            let account_body = match post_json(&parsed.config.rpc_url, &account_request) {
                Ok(body) => body,
                Err(error) => return Ok(unknown_result(error.code())),
            };
            let largest_body = match post_json(&parsed.config.rpc_url, &largest_request) {
                Ok(body) => body,
                Err(error) => return Ok(unknown_result(error.code())),
            };
            let owner_accounts_request = match owner_accounts_request_body(&largest_body) {
                Ok(request) => request,
                Err(error) => return Ok(unknown_result(error.code())),
            };
            let owner_accounts_body =
                match post_json(&parsed.config.rpc_url, &owner_accounts_request) {
                    Ok(body) => body,
                    Err(error) => return Ok(unknown_result(error.code())),
                };
            let liquidity_body = match get_liquidity(&parsed.mint) {
                Ok(body) => body,
                Err(error) => return Ok(unknown_result(error.code())),
            };

            match assess(
                &parsed.mint,
                &account_body,
                &largest_body,
                &owner_accounts_body,
                &liquidity_body,
            ) {
                Ok(report) => {
                    let verdict = verdict_code(report.verdict);
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        verdict,
                        "ASSESSMENT_COMPLETE",
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serialize_report(&report),
                        error: None,
                    })
                }
                Err(error) => Ok(unknown_result(error.code())),
            }
        }
    }

    fn post_json(endpoint: &str, request: &str) -> Result<String, ShimError> {
        let target = http_request_target(HttpMethod::Post, endpoint)?;
        send_request(&target, Some(request.as_bytes()))
    }

    fn get_liquidity(mint: &str) -> Result<String, ShimError> {
        let target = liquidity_get_request(mint)?;
        send_request(&target, None)
    }

    fn send_request(
        target: &HttpRequestTarget,
        request_body: Option<&[u8]>,
    ) -> Result<String, ShimError> {
        if !matches!(
            (target.method, request_body),
            (HttpMethod::Post, Some(_)) | (HttpMethod::Get, None)
        ) {
            return Err(ShimError::HttpTransport);
        }

        let timeouts = HttpTimeouts::default();
        let headers = match request_body {
            Some(_) => {
                Headers::from_list(&[("Content-Type".to_string(), b"application/json".to_vec())])
                    .map_err(|_| ShimError::HttpTransport)?
            }
            None => Headers::from_list(&[]).map_err(|_| ShimError::HttpTransport)?,
        };
        let request = OutgoingRequest::new(headers);
        let method = match target.method {
            HttpMethod::Get => Method::Get,
            HttpMethod::Post => Method::Post,
        };
        request
            .set_method(&method)
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
            .set_connect_timeout(Some(timeouts.connect_ns))
            .map_err(|_| ShimError::HttpTransport)?;
        options
            .set_first_byte_timeout(Some(timeouts.first_byte_ns))
            .map_err(|_| ShimError::HttpTransport)?;
        options
            .set_between_bytes_timeout(Some(timeouts.between_bytes_ns))
            .map_err(|_| ShimError::HttpTransport)?;

        let response_deadline = Deadline::new(
            monotonic_clock::now(),
            timeouts
                .connect_ns
                .checked_add(timeouts.first_byte_ns)
                .ok_or(ShimError::Timeout)?,
        )?;
        let future =
            outgoing_handler::handle(request, Some(options)).map_err(classify_http_error)?;
        if let Some(request_body) = request_body {
            write_request_body(&outgoing_body, request_body, response_deadline)?;
        }
        OutgoingBody::finish(outgoing_body, None).map_err(|_| ShimError::HttpTransport)?;
        let response = await_response(&future, response_deadline)?;
        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(ShimError::HttpStatus);
        }

        let body = response.consume().map_err(|_| ShimError::BodyRead)?;
        drop(response);
        let stream = body.stream().map_err(|_| ShimError::BodyRead)?;
        let mut accumulator = ResponseBodyAccumulator::new();
        let read_deadline = Deadline::new(monotonic_clock::now(), timeouts.full_response_ns)?;
        loop {
            let idle_deadline = Deadline::new(monotonic_clock::now(), timeouts.between_bytes_ns)?;
            wait_for_stream(&stream, read_deadline, idle_deadline)?;
            match stream.read(accumulator.next_chunk_len()) {
                Ok(chunk) if chunk.is_empty() => return Err(ShimError::BodyRead),
                Ok(chunk) => accumulator.push_chunk(&chunk)?,
                Err(StreamError::Closed) => break,
                Err(error) => return Err(classify_stream_error(&error, ShimError::BodyRead)),
            }
        }
        drop(stream);
        drop(body);
        accumulator.finish()
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

    fn wait_for_stream(
        stream: &InputStream,
        total_deadline: Deadline,
        idle_deadline: Deadline,
    ) -> Result<(), ShimError> {
        let now = monotonic_clock::now();
        let remaining = total_deadline
            .remaining_ns(now)?
            .min(idle_deadline.remaining_ns(now)?);
        wait_for_duration(&stream.subscribe(), remaining)
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

    fn unknown_result(code: &'static str) -> ToolResult {
        emit(PluginAction::Fail, PluginOutcome::Failure, "UNKNOWN", code);
        ToolResult {
            success: false,
            output: serialize_report(&unknown_report(code, code)),
            error: Some(code.to_string()),
        }
    }

    fn verdict_code(verdict: Verdict) -> &'static str {
        match verdict {
            Verdict::Red => "RED",
            Verdict::Amber => "AMBER",
            Verdict::Green => "GREEN",
            Verdict::Unknown => "UNKNOWN",
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, verdict: &str, code: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "token_risk_check::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: Some(format!(r#"{{"verdict":"{verdict}","code":"{code}"}}"#)),
                message: code.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
