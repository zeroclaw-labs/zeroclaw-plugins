//! Pure Solana Pay transfer-request core. No WIT, WASI, network, clock, or
//! randomness dependency: the same code runs in host tests and the component.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_INTEGER_DIGITS: usize = 20;
const MAX_FRACTION_DIGITS: usize = 18;
const MAX_INVOICE_ID_BYTES: usize = 128;
const MAX_LABEL_CHARS: usize = 64;
const MAX_MESSAGE_CHARS: usize = 256;
const MAX_MEMO_BYTES: usize = 128;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestInput {
    pub recipient: String,
    pub amount: String,
    #[serde(default)]
    pub spl_token: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub invoice_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RequestOutput {
    pub uri: String,
    pub reference: String,
    pub recipient: String,
    pub amount: String,
    pub asset: String,
    pub custody_tier: &'static str,
    pub summary: String,
}

pub fn create_request(input: RequestInput) -> Result<RequestOutput, String> {
    validate_pubkey("recipient", &input.recipient)?;
    let amount = canonical_amount(&input.amount)?;

    if let Some(mint) = input.spl_token.as_deref() {
        validate_pubkey("spl_token", mint)?;
        if mint == input.recipient {
            return Err("spl_token must not equal recipient".to_string());
        }
    }

    validate_optional_text("label", input.label.as_deref(), MAX_LABEL_CHARS, false)?;
    validate_optional_text(
        "message",
        input.message.as_deref(),
        MAX_MESSAGE_CHARS,
        false,
    )?;
    validate_optional_text("memo", input.memo.as_deref(), MAX_MEMO_BYTES, true)?;

    let reference = resolve_reference(&input, &amount)?;
    let mut query = vec![format!("amount={}", encode_component(&amount))];
    if let Some(mint) = input.spl_token.as_deref() {
        query.push(format!("spl-token={}", encode_component(mint)));
    }
    query.push(format!("reference={}", encode_component(&reference)));
    for (key, value) in [
        ("label", input.label.as_deref()),
        ("message", input.message.as_deref()),
        ("memo", input.memo.as_deref()),
    ] {
        if let Some(value) = value {
            query.push(format!("{key}={}", encode_component(value)));
        }
    }

    let asset = input.spl_token.clone().unwrap_or_else(|| "SOL".to_string());
    let summary = format!(
        "Request {amount} {} to {} (reference {})",
        if input.spl_token.is_some() {
            short_key(&asset)
        } else {
            "SOL".to_string()
        },
        short_key(&input.recipient),
        short_key(&reference),
    );

    Ok(RequestOutput {
        uri: format!("solana:{}?{}", input.recipient, query.join("&")),
        reference,
        recipient: input.recipient,
        amount,
        asset,
        custody_tier: "T1-build-no-signing",
        summary,
    })
}

fn resolve_reference(input: &RequestInput, amount: &str) -> Result<String, String> {
    match (input.reference.as_deref(), input.invoice_id.as_deref()) {
        (Some(_), Some(_)) => Err("provide reference or invoice_id, not both".to_string()),
        (None, None) => Err("reference or invoice_id is required".to_string()),
        (Some(reference), None) => {
            validate_pubkey("reference", reference)?;
            if reference == input.recipient || input.spl_token.as_deref() == Some(reference) {
                return Err("reference must be distinct from recipient and spl_token".to_string());
            }
            Ok(reference.to_string())
        }
        (None, Some(invoice_id)) => {
            if invoice_id.is_empty() || invoice_id.len() > MAX_INVOICE_ID_BYTES {
                return Err(format!(
                    "invoice_id must be 1..={MAX_INVOICE_ID_BYTES} UTF-8 bytes"
                ));
            }
            if invoice_id.chars().any(char::is_control) {
                return Err("invoice_id must not contain control characters".to_string());
            }
            let mut hasher = Sha256::new();
            hasher.update(b"zeroclaw-solana-pay-reference-v1\0");
            hasher.update(input.recipient.as_bytes());
            hasher.update(b"\0");
            hasher.update(input.spl_token.as_deref().unwrap_or("SOL").as_bytes());
            hasher.update(b"\0");
            hasher.update(amount.as_bytes());
            hasher.update(b"\0");
            hasher.update(invoice_id.as_bytes());
            Ok(bs58::encode(hasher.finalize()).into_string())
        }
    }
}

pub fn validate_pubkey(field: &str, value: &str) -> Result<(), String> {
    if value.len() < 32 || value.len() > 44 {
        return Err(format!(
            "{field} must be a base58-encoded 32-byte public key"
        ));
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be valid base58"))?;
    if decoded.len() != 32 {
        return Err(format!("{field} must decode to exactly 32 bytes"));
    }
    Ok(())
}

pub fn canonical_amount(value: &str) -> Result<String, String> {
    if value.is_empty() || value.trim() != value || value.starts_with(['+', '-']) {
        return Err("amount must be an unsigned plain decimal string".to_string());
    }
    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("amount must be an unsigned plain decimal string".to_string());
    }
    let fraction = match fraction {
        Some("") => return Err("amount must not end with a decimal point".to_string()),
        Some(value) if !value.bytes().all(|byte| byte.is_ascii_digit()) => {
            return Err("amount must be an unsigned plain decimal string".to_string());
        }
        value => value.unwrap_or_default(),
    };
    if integer.len() > MAX_INTEGER_DIGITS || fraction.len() > MAX_FRACTION_DIGITS {
        return Err(format!(
            "amount supports at most {MAX_INTEGER_DIGITS} integer and {MAX_FRACTION_DIGITS} fractional digits"
        ));
    }
    let normalized_integer = integer.trim_start_matches('0');
    let normalized_integer = if normalized_integer.is_empty() {
        "0"
    } else {
        normalized_integer
    };
    let normalized_fraction = fraction.trim_end_matches('0');
    if normalized_integer == "0" && normalized_fraction.is_empty() {
        return Err("amount must be greater than zero".to_string());
    }
    if normalized_fraction.is_empty() {
        Ok(normalized_integer.to_string())
    } else {
        Ok(format!("{normalized_integer}.{normalized_fraction}"))
    }
}

fn validate_optional_text(
    field: &str,
    value: Option<&str>,
    limit: usize,
    byte_limit: bool,
) -> Result<(), String> {
    let Some(value) = value else { return Ok(()) };
    if value.is_empty() {
        return Err(format!("{field} must not be empty when provided"));
    }
    if value.chars().any(|character| character == '\0') {
        return Err(format!("{field} must not contain NUL"));
    }
    let length = if byte_limit {
        value.len()
    } else {
        value.chars().count()
    };
    if length > limit {
        return Err(format!("{field} exceeds the {limit}-character limit"));
    }
    Ok(())
}

fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

fn short_key(value: &str) -> String {
    if value.len() <= 12 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..6], &value[value.len() - 4..])
    }
}
