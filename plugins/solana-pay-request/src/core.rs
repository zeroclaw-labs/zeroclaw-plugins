//! Pure, host-testable Solana Pay URL construction.
//!
//! This T1 component never holds a key, signs, submits, or broadcasts a
//! transaction. A `solana:` URL is a request for a separate wallet to build
//! and approve the transfer.

use serde::{Deserialize, Serialize};

pub const PARAMETERS_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "recipient": { "type": "string", "description": "Base58 public key of the payment recipient" },
    "amount": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$", "description": "Exact positive decimal amount, for example \"25.0\"" },
    "mint": { "type": "string", "description": "Base58 SPL token mint, for example the USDC mint" },
    "memo": { "type": "string", "maxLength": 500, "description": "Invoice or reconciliation memo" },
    "reference": { "type": "string", "description": "Base58 public key used by the merchant to locate this payment" }
  },
  "required": ["recipient", "amount", "mint", "reference"]
}"#;

const MAX_MEMO_BYTES: usize = 500;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PayError {
    #[error("{field} must be a base58 public key")]
    InvalidPubkey { field: &'static str },
    #[error("amount must be a positive decimal string")]
    InvalidAmount,
    #[error("memo exceeds {MAX_MEMO_BYTES} bytes")]
    MemoTooLong,
    #[error("amount exceeds configured max_amount {max} — request refused")]
    AmountOverCap { max: u64 },
    #[error("mint not in allowlist")]
    MintNotAllowed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayRequestArgs {
    pub recipient: String,
    /// Kept as a string so a request never crosses binary floating point.
    pub amount: String,
    pub mint: String,
    pub memo: Option<String>,
    pub reference: String,
}

/// Operator-controlled configuration. When caps are set, the tool enforces
/// them before building the URL. When empty/unset, the tool operates
/// zero-config with no caps (fail-open for caps, not for validity).
#[derive(Debug, Clone)]
pub struct PayConfig {
    pub max_amount_base_units: Option<u64>,
    pub allowed_mints: Vec<[u8; 32]>,
    pub decimals: u8,
}

impl PayConfig {
    pub fn from_config(
        max_amount: Option<&str>,
        allowed_mints: Option<&str>,
        decimals: u8,
    ) -> Result<Self, PayError> {
        let max_amount_base_units = match max_amount {
            Some(s) if !s.trim().is_empty() => {
                Some(parse_amount_to_base_units(s, decimals).map_err(|_| {
                    PayError::InvalidAmount
                })?)
            }
            _ => None,
        };
        let allowed_mints = allowed_mints
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(|s| {
                let bytes = bs58::decode(s)
                    .into_vec()
                    .map_err(|_| PayError::InvalidPubkey { field: "mint" })?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| PayError::InvalidPubkey { field: "mint" })?;
                Ok(arr)
            })
            .collect::<Result<Vec<_>, PayError>>()?;
        Ok(Self {
            max_amount_base_units,
            allowed_mints,
            decimals,
        })
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct PayRequestResult {
    pub solana_pay_url: String,
    /// Chat clients can pass this exact value to a QR renderer.
    pub qr_payload: String,
    pub summary: String,
}

pub fn build_solana_pay_request(args: &PayRequestArgs) -> Result<PayRequestResult, PayError> {
    build_solana_pay_request_with_config(args, &PayConfig {
        max_amount_base_units: None,
        allowed_mints: vec![],
        decimals: 6,
    })
}

pub fn build_solana_pay_request_with_config(
    args: &PayRequestArgs,
    config: &PayConfig,
) -> Result<PayRequestResult, PayError> {
    validate_pubkey(&args.recipient, "recipient")?;
    validate_pubkey(&args.mint, "mint")?;
    validate_pubkey(&args.reference, "reference")?;
    validate_amount(&args.amount)?;
    if let Some(memo) = &args.memo {
        if memo.len() > MAX_MEMO_BYTES {
            return Err(PayError::MemoTooLong);
        }
    }

    // Enforce caps only if configured (fail-open on caps, fail-closed on validity)
    if let Some(max) = config.max_amount_base_units {
        let raw = parse_amount_to_base_units(&args.amount, config.decimals)?;
        if raw > max {
            return Err(PayError::AmountOverCap { max });
        }
    }
    let mint_bytes = bs58::decode(&args.mint)
        .into_vec()
        .ok()
        .and_then(|v| {
            let arr: [u8; 32] = v.try_into().ok()?;
            Some(arr)
        });
    if !config.allowed_mints.is_empty() {
        match mint_bytes {
            Some(m) if config.allowed_mints.contains(&m) => {}
            _ => return Err(PayError::MintNotAllowed),
        }
    }

    let mut query = vec![
        format!("amount={}", args.amount),
        format!("spl-token={}", args.mint),
        format!("reference={}", args.reference),
    ];
    if let Some(memo) = &args.memo {
        query.push(format!("memo={}", percent_encode(memo)));
    }
    let solana_pay_url = format!("solana:{}?{}", args.recipient, query.join("&"));
    let summary = format!(
        "Request {} tokens to {}\nMint: {}\nReference: {}\nMemo: {}\nRequires wallet approval; this plugin cannot sign or submit.",
        args.amount,
        args.recipient,
        args.mint,
        args.reference,
        args.memo.as_deref().unwrap_or("(none)"),
    );

    Ok(PayRequestResult {
        qr_payload: solana_pay_url.clone(),
        solana_pay_url,
        summary,
    })
}

fn validate_pubkey(value: &str, field: &'static str) -> Result<(), PayError> {
    let bytes = bs58::decode(value).into_vec().ok();
    if !matches!(bytes, Some(ref value) if value.len() == 32) {
        return Err(PayError::InvalidPubkey { field });
    }
    Ok(())
}

fn validate_amount(value: &str) -> Result<(), PayError> {
    if value.is_empty() || value.trim() != value {
        return Err(PayError::InvalidAmount);
    }
    let mut parts = value.split('.');
    let whole = parts.next().expect("split returns one element");
    let fractional = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fractional
            .is_some_and(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        || fractional.is_some_and(|part| part.len() > 255)
        || !value
            .bytes()
            .any(|byte| byte.is_ascii_digit() && byte != b'0')
    {
        return Err(PayError::InvalidAmount);
    }
    Ok(())
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                vec![byte as char].into_iter().collect::<Vec<_>>()
            } else {
                format!("%{byte:02X}").chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

/// Convert a human-readable decimal amount to base units without using binary
/// floating point.
pub fn parse_amount_to_base_units(amount: &str, decimals: u8) -> Result<u64, PayError> {
    if amount.is_empty() || amount.trim() != amount {
        return Err(PayError::InvalidAmount);
    }
    let mut parts = amount.split('.');
    let whole = parts.next().expect("split returns one element");
    let fractional = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fractional.is_some_and(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(PayError::InvalidAmount);
    }
    let fraction = fractional.unwrap_or("");
    if fraction.len() > decimals as usize {
        return Err(PayError::InvalidAmount);
    }
    let scale = 10u64
        .checked_pow(decimals as u32)
        .ok_or(PayError::InvalidAmount)?;
    let whole_units = whole
        .parse::<u64>()
        .map_err(|_| PayError::InvalidAmount)?
        .checked_mul(scale)
        .ok_or(PayError::InvalidAmount)?;
    let fraction_units = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u64>()
            .map_err(|_| PayError::InvalidAmount)?
            .checked_mul(10u64.pow((decimals as usize - fraction.len()) as u32))
            .ok_or(PayError::InvalidAmount)?
    };
    let units = whole_units
        .checked_add(fraction_units)
        .ok_or(PayError::InvalidAmount)?;
    if units == 0 {
        return Err(PayError::InvalidAmount);
    }
    Ok(units)
}
