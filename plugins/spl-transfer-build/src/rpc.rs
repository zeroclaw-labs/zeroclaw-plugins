//! The plugin-owned transport boundary.

use std::fmt;

use nanosol::rpc::MAX_RPC_RESPONSE_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Unavailable,
    HttpStatus(u16),
    ResponseTooLarge,
    InvalidUtf8,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("RPC transport is unavailable"),
            Self::HttpStatus(status) => write!(formatter, "RPC returned HTTP status {status}"),
            Self::ResponseTooLarge => write!(
                formatter,
                "RPC response exceeds the {MAX_RPC_RESPONSE_BYTES}-byte limit"
            ),
            Self::InvalidUtf8 => formatter.write_str("RPC response is not valid UTF-8"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Validate one HTTP response and collect its chunks without exceeding the
/// caller-supplied aggregate byte limit. Exactly HTTP 200 is accepted, so a
/// redirect is returned as an error rather than followed.
pub fn collect_http_response<I>(
    status: u16,
    chunks: I,
    maximum_bytes: usize,
) -> Result<String, TransportError>
where
    I: IntoIterator<Item = Result<Vec<u8>, TransportError>>,
{
    if status != 200 {
        return Err(TransportError::HttpStatus(status));
    }

    let mut body = Vec::new();
    for chunk in chunks {
        let chunk = chunk?;
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or(TransportError::ResponseTooLarge)?;
        if next_length > maximum_bytes {
            return Err(TransportError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| TransportError::InvalidUtf8)
}

pub trait RpcTransport {
    /// POST one JSON-RPC request. Implementations must not follow redirects and
    /// must enforce `maximum_bytes` before returning a UTF-8 response.
    fn post(
        &self,
        endpoint: &str,
        request_body: &str,
        maximum_bytes: usize,
    ) -> Result<String, TransportError>;
}

#[cfg(target_family = "wasm")]
pub struct WakiTransport;

#[cfg(target_family = "wasm")]
impl RpcTransport for WakiTransport {
    fn post(
        &self,
        endpoint: &str,
        request_body: &str,
        maximum_bytes: usize,
    ) -> Result<String, TransportError> {
        use std::time::Duration;

        let response = waki::Client::new()
            .post(endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(request_body.as_bytes())
            .connect_timeout(Duration::from_secs(10))
            .send()
            .map_err(|_| TransportError::Unavailable)?;

        // Waki performs one outgoing request and exposes 3xx as responses; it
        // does not implement a redirect-following loop. Accept exactly 200.
        let status = response.status_code();
        let requested = u64::try_from(maximum_bytes.saturating_add(1)).unwrap_or(u64::MAX);
        let mut finished = false;
        let chunks = std::iter::from_fn(|| {
            if finished {
                return None;
            }
            match response.chunk(requested) {
                Ok(Some(chunk)) => Some(Ok(chunk)),
                Ok(None) => {
                    finished = true;
                    None
                }
                Err(_) => {
                    finished = true;
                    Some(Err(TransportError::Unavailable))
                }
            }
        });
        collect_http_response(status, chunks, maximum_bytes)
    }
}
