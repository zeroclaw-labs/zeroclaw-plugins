//! Pure SNS response parsing and output shaping. No WASM or HTTP dependencies.

use serde_json::Value;

pub const MAX_OUTPUT_CHARS: usize = 700;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    InvalidDomain(String),
    NotFound,
    Provider(String),
    MalformedResponse,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDomain(message) | Self::Provider(message) => f.write_str(message),
            Self::NotFound => {
                f.write_str("SNS domain not found or has no resolvable wallet address")
            }
            Self::MalformedResponse => {
                f.write_str("SNS provider returned an unrecognised response")
            }
        }
    }
}

/// Normalize only top-level `.sol` domains. Subdomains have distinct SNS parent
/// semantics and are deliberately rejected until they have a tested resolver.
pub fn normalize_domain(input: &str) -> Result<String, ResolveError> {
    let domain = input.trim().to_ascii_lowercase();
    let label = domain.strip_suffix(".sol").unwrap_or(&domain);
    if label.is_empty() || label.len() > 63 || label.contains('.') {
        return Err(ResolveError::InvalidDomain(
            "expected one top-level .sol domain, e.g. bonk.sol".into(),
        ));
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || label.starts_with('-')
        || label.ends_with('-')
    {
        return Err(ResolveError::InvalidDomain(
            "invalid .sol domain label".into(),
        ));
    }
    Ok(format!("{label}.sol"))
}

fn valid_address(value: &str) -> bool {
    (32..=44).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn parse_proxy_response(value: &Value) -> Result<String, ResolveError> {
    match value.get("s").and_then(Value::as_str) {
        Some("ok") => {
            let address = value
                .get("result")
                .and_then(Value::as_str)
                .ok_or(ResolveError::MalformedResponse)?;
            if valid_address(address) {
                Ok(address.to_string())
            } else {
                Err(ResolveError::MalformedResponse)
            }
        }
        Some("error") => Err(ResolveError::NotFound),
        Some(other) => Err(ResolveError::Provider(format!(
            "SNS provider status: {other}"
        ))),
        None => Err(ResolveError::MalformedResponse),
    }
}

pub fn format(domain: &str, address: &str) -> String {
    format!("SNS resolved\nDomain: {domain}\nWallet: {address}\nRead-only lookup; verify recipient before any separate action.")
        .chars().take(MAX_OUTPUT_CHARS).collect()
}
