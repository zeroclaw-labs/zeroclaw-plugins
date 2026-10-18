//! Pure Solana Pay transfer-request builder.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_URI_BYTES: usize = 2_048;
const MAX_REFERENCES: usize = 5;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestArgs {
    pub recipient: String,
    pub amount: String,
    #[serde(default)]
    pub spl_token: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaymentRequest {
    pub uri: String,
    pub qr_payload: String,
    pub fingerprint: String,
    pub recipient: String,
    pub amount: String,
    pub asset: String,
    pub references: Vec<String>,
    pub custody_tier: &'static str,
    pub summary: String,
}

pub fn parse_request_args(json: &str) -> Result<RequestArgs, String> {
    serde_json::from_str(json).map_err(|error| error.to_string())
}

pub fn build_request(mut args: RequestArgs) -> Result<PaymentRequest, String> {
    validate_pubkey(&args.recipient, "recipient")?;
    args.amount = canonical_decimal(&args.amount)?;
    args.spl_token = normalize_optional(args.spl_token, "spl_token", 64)?;
    if let Some(mint) = &args.spl_token {
        validate_pubkey(mint, "spl_token")?;
    }
    if args.references.len() > MAX_REFERENCES {
        return Err(format!("at most {MAX_REFERENCES} references are allowed"));
    }
    let mut unique = HashSet::new();
    for reference in &args.references {
        validate_pubkey(reference, "reference")?;
        if !unique.insert(reference) {
            return Err("references must be unique".to_string());
        }
        if reference == &args.recipient {
            return Err("reference must not equal recipient".to_string());
        }
    }
    args.label = normalize_text(args.label, "label", 64)?;
    args.message = normalize_text(args.message, "message", 128)?;
    args.memo = normalize_text(args.memo, "memo", 128)?;

    let mut query = vec![("amount", args.amount.as_str())];
    if let Some(mint) = args.spl_token.as_deref() {
        query.push(("spl-token", mint));
    }
    for reference in &args.references {
        query.push(("reference", reference));
    }
    if let Some(label) = args.label.as_deref() {
        query.push(("label", label));
    }
    if let Some(message) = args.message.as_deref() {
        query.push(("message", message));
    }
    if let Some(memo) = args.memo.as_deref() {
        query.push(("memo", memo));
    }

    let query = query
        .into_iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let uri = format!("solana:{}?{query}", args.recipient);
    if uri.len() > MAX_URI_BYTES {
        return Err(format!("encoded URI exceeds {MAX_URI_BYTES} bytes"));
    }

    let asset = args.spl_token.clone().unwrap_or_else(|| "SOL".to_string());
    let fingerprint = fingerprint(&uri);
    let summary = format!(
        "Request {} {} to {} with {} reference(s).",
        args.amount,
        asset,
        shorten(&args.recipient),
        args.references.len()
    );

    Ok(PaymentRequest {
        qr_payload: uri.clone(),
        uri,
        fingerprint,
        recipient: args.recipient,
        amount: args.amount,
        asset,
        references: args.references,
        custody_tier: "T1-build-only",
        summary,
    })
}

fn validate_pubkey(value: &str, field: &str) -> Result<(), String> {
    if value.len() > 64 {
        return Err(format!("{field} is too long"));
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be valid base58"))?;
    if decoded.len() != 32 {
        return Err(format!("{field} must decode to 32 bytes"));
    }
    Ok(())
}

fn canonical_decimal(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 40 {
        return Err("amount must contain between 1 and 40 characters".to_string());
    }
    let mut dots = 0;
    for character in value.chars() {
        match character {
            '0'..='9' => {}
            '.' if dots == 0 => dots += 1,
            _ => return Err("amount must be an unsigned decimal string".to_string()),
        }
    }
    if value.starts_with('.') || value.ends_with('.') {
        return Err("amount must have digits on both sides of a decimal point".to_string());
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let fraction = fraction.trim_end_matches('0');
    let canonical = if fraction.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fraction}")
    };
    if canonical == "0" {
        return Err("amount must be greater than zero".to_string());
    }
    Ok(canonical)
}

fn normalize_optional(
    value: Option<String>,
    field: &str,
    max_len: usize,
) -> Result<Option<String>, String> {
    match value {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) if value.len() > max_len => Err(format!("{field} is too long")),
        other => Ok(other),
    }
}

fn normalize_text(
    value: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > max_chars {
        return Err(format!("{field} exceeds {max_chars} characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    Ok(Some(value))
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(hex((*byte >> 4) & 0x0f));
            encoded.push(hex(*byte & 0x0f));
        }
    }
    encoded
}

fn hex(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'A' + value - 10),
    }
}

fn fingerprint(uri: &str) -> String {
    let digest = Sha256::digest(uri.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn shorten(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    format!("{}...{}", &value[..6], &value[value.len() - 4..])
}
