//! Pure Solana Pay URL construction and policy validation.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

const MAX_REFERENCES: usize = 8;
const MAX_LABEL_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 200;
const SOL_SCALE: u32 = 9;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PayRequest {
    #[serde(default)]
    pub recipient: Option<String>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayConfig {
    pub default_recipient: Option<String>,
    pub allowed_recipients: HashSet<String>,
    pub allow_unlisted_recipients: bool,
    max_amount_minor: u128,
    max_amount_display: String,
}

impl Default for PayConfig {
    fn default() -> Self {
        Self {
            default_recipient: None,
            allowed_recipients: HashSet::new(),
            allow_unlisted_recipients: false,
            max_amount_minor: 1_000 * 1_000_000_000,
            max_amount_display: "1000".to_string(),
        }
    }
}

impl PayConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let default_recipient = non_empty(section.get("default_recipient")).map(str::to_owned);
        let mut allowed_recipients = parse_list(section.get("allowed_recipients"));
        if let Some(recipient) = &default_recipient {
            validate_public_key("default_recipient", recipient)?;
            allowed_recipients.insert(recipient.clone());
        }
        for recipient in &allowed_recipients {
            validate_public_key("allowed recipient", recipient)?;
        }

        let max_amount = non_empty(section.get("max_amount")).unwrap_or("1000");
        Ok(Self {
            default_recipient,
            allowed_recipients,
            allow_unlisted_recipients: parse_bool(section, "allow_unlisted_recipients", false)?,
            max_amount_minor: parse_amount("max_amount", max_amount)?,
            max_amount_display: max_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PayResult {
    pub url: String,
    pub summary: String,
    pub requires_wallet_approval: bool,
    pub plugin_signed_transaction: bool,
    pub plugin_broadcast_transaction: bool,
    pub reference_count: usize,
}

pub fn build_request(request: &PayRequest, config: &PayConfig) -> Result<PayResult, String> {
    let recipient = request
        .recipient
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or(config.default_recipient.as_deref())
        .ok_or_else(|| {
            "recipient is required unless default_recipient is configured".to_string()
        })?;

    validate_public_key("recipient", recipient)?;
    if !config.allow_unlisted_recipients && !config.allowed_recipients.contains(recipient) {
        return Err(
            "recipient is not in allowed_recipients; operator policy rejected the request"
                .to_string(),
        );
    }

    let amount_minor = parse_amount("amount", &request.amount)?;
    if amount_minor > config.max_amount_minor {
        return Err(format!(
            "amount exceeds configured max_amount {}",
            config.max_amount_display
        ));
    }

    if request
        .spl_token
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(
            "SPL token requests are not supported in this release; native SOL only".to_string(),
        );
    }

    validate_references(&request.references)?;
    validate_text("label", request.label.as_deref(), MAX_LABEL_BYTES)?;
    validate_text("message", request.message.as_deref(), MAX_TEXT_BYTES)?;
    validate_text("memo", request.memo.as_deref(), MAX_TEXT_BYTES)?;

    let mut query = Vec::new();
    query.push(format!("amount={}", encode_component(&request.amount)));
    for reference in &request.references {
        query.push(format!("reference={}", encode_component(reference)));
    }
    push_optional(&mut query, "label", request.label.as_deref());
    push_optional(&mut query, "message", request.message.as_deref());
    push_optional(&mut query, "memo", request.memo.as_deref());

    Ok(PayResult {
        url: format!("solana:{}?{}", encode_component(recipient), query.join("&")),
        summary: format!(
            "Native-SOL transfer request for {} SOL to {}. This plugin did not sign or broadcast a transaction; verify the recipient and amount in a compatible wallet before approving.",
            request.amount, recipient
        ),
        requires_wallet_approval: true,
        plugin_signed_transaction: false,
        plugin_broadcast_transaction: false,
        reference_count: request.references.len(),
    })
}

fn non_empty(value: Option<&String>) -> Option<&str> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn parse_list(value: Option<&String>) -> HashSet<String> {
    value
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_bool(section: &HashMap<String, String>, key: &str, default: bool) -> Result<bool, String> {
    match non_empty(section.get(key)) {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(format!("{key} must be exactly true or false")),
    }
}

fn validate_public_key(field: &str, value: &str) -> Result<(), String> {
    if value.trim() != value || value.is_empty() {
        return Err(format!("{field} must be a non-empty base58 public key"));
    }
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| format!("{field} must be valid base58"))?;
    if bytes.len() != 32 {
        return Err(format!("{field} must decode to exactly 32 bytes"));
    }
    Ok(())
}

fn parse_amount(field: &str, value: &str) -> Result<u128, String> {
    if value.is_empty()
        || value.trim() != value
        || value.starts_with('+')
        || value.starts_with('-')
        || value.contains(['e', 'E'])
    {
        return Err(format!(
            "{field} must be a canonical non-negative decimal without signs or exponents"
        ));
    }

    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
    {
        return Err(format!("{field} must be a canonical decimal"));
    }

    let fraction = fraction.unwrap_or("");
    if value.contains('.') && fraction.is_empty() {
        return Err(format!("{field} must not end with a decimal point"));
    }
    if fraction.len() > SOL_SCALE as usize || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{field} must have at most {SOL_SCALE} fractional digits"
        ));
    }

    let integer_value = integer
        .parse::<u128>()
        .map_err(|_| format!("{field} is too large"))?;
    let scale = 10_u128.pow(SOL_SCALE);
    let fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u128>()
            .map_err(|_| format!("{field} is not a decimal"))?
            .checked_mul(10_u128.pow(SOL_SCALE - fraction.len() as u32))
            .ok_or_else(|| format!("{field} is too large"))?
    };
    integer_value
        .checked_mul(scale)
        .and_then(|scaled| scaled.checked_add(fraction_value))
        .ok_or_else(|| format!("{field} is too large"))
}

fn validate_references(references: &[String]) -> Result<(), String> {
    if references.len() > MAX_REFERENCES {
        return Err(format!("at most {MAX_REFERENCES} references are allowed"));
    }
    let mut unique = HashSet::new();
    for reference in references {
        validate_public_key("reference", reference)?;
        if !unique.insert(reference) {
            return Err("references must be unique".to_string());
        }
    }
    Ok(())
}

fn validate_text(field: &str, value: Option<&str>, max_bytes: usize) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() > max_bytes {
        return Err(format!("{field} must be at most {max_bytes} UTF-8 bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    Ok(())
}

fn push_optional(query: &mut Vec<String>, key: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        query.push(format!("{key}={}", encode_component(value)));
    }
}

fn encode_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}
