//! Pure Solana Pay request construction with explicit trust boundaries.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    str::FromStr,
};

use nanosol::{
    amount::{format_ui_amount, parse_ui_amount, AmountError, MAX_SUPPORTED_DECIMALS},
    pubkey::Pubkey,
    shape::{elide_address, quote_untrusted},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REFERENCE_DOMAIN: &[u8] = b"zeroclaw-solana-pay-v1";
pub const MAX_TOOL_OUTPUT_BYTES: usize = 4_000;
pub const MAX_URL_BYTES: usize = 1_600;

const MAX_AMOUNT_BYTES: usize = 64;
const MAX_INVOICE_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 128;
const MAX_MESSAGE_BYTES: usize = 256;
const MAX_MEMO_BYTES: usize = 256;
const MAX_ALIAS_BYTES: usize = 24;
const MAX_MINT_ALIASES: usize = 32;
const MAX_ALLOWED_RECIPIENTS: usize = 128;
const SUMMARY_INVOICE_CHARS: usize = 80;
const NATIVE_SOL_MINT_SENTINEL: [u8; 32] = [0; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestArgs {
    pub recipient: String,
    pub amount: String,
    pub spl_token: Option<String>,
    pub invoice_id: String,
    pub label: Option<String>,
    pub message: Option<String>,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestOutput {
    pub url: String,
    pub qr_payload: String,
    pub summary: String,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResponse {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl ToolResponse {
    fn success(output: String) -> Self {
        Self {
            success: true,
            output,
            error: None,
        }
    }

    fn refusal(error: impl fmt::Display) -> Self {
        Self {
            success: false,
            output: String::new(),
            error: Some(error.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentArgs {
    recipient: String,
    amount: String,
    #[serde(default)]
    spl_token: Option<String>,
    invoice_id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    memo: Option<String>,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

impl From<ComponentArgs> for RequestArgs {
    fn from(value: ComponentArgs) -> Self {
        Self {
            recipient: value.recipient,
            amount: value.amount,
            spl_token: value.spl_token,
            invoice_id: value.invoice_id,
            label: value.label,
            message: value.message,
            memo: value.memo,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MintAlias {
    mint: Pubkey,
    decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestConfig {
    aliases: BTreeMap<String, MintAlias>,
    default_label: Option<String>,
    allowed_recipients: Option<BTreeSet<Pubkey>>,
}

impl RequestConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, RequestError> {
        for key in section.keys() {
            if !matches!(
                key.as_str(),
                "mint_aliases" | "mint_decimals" | "default_label" | "allowed_recipients"
            ) {
                return Err(RequestError::Config(format!("unknown config key '{key}'")));
            }
        }
        let alias_values = parse_assignments(section.get("mint_aliases"), "mint_aliases")?;
        if alias_values.len() > MAX_MINT_ALIASES {
            return Err(RequestError::ConfigLimit {
                field: "mint_aliases",
                maximum: MAX_MINT_ALIASES,
            });
        }
        let decimal_values = parse_assignments(section.get("mint_decimals"), "mint_decimals")?;

        for alias in decimal_values.keys() {
            if !alias_values.contains_key(alias) {
                return Err(RequestError::Config(format!(
                    "mint_decimals defines unknown alias '{alias}'"
                )));
            }
        }

        let mut aliases = BTreeMap::new();
        for (alias, address) in alias_values {
            validate_alias(&alias)?;
            let mint = Pubkey::from_str(&address).map_err(|_| {
                RequestError::Config(format!("mint alias '{alias}' is not a 32-byte public key"))
            })?;
            let decimals = decimal_values
                .get(&alias)
                .ok_or_else(|| RequestError::MissingAliasDecimals(alias.clone()))?
                .parse::<u8>()
                .map_err(|_| {
                    RequestError::Config(format!(
                        "mint_decimals value for '{alias}' must be an integer"
                    ))
                })?;
            if decimals > MAX_SUPPORTED_DECIMALS {
                return Err(RequestError::Config(format!(
                    "mint_decimals value for '{alias}' exceeds {MAX_SUPPORTED_DECIMALS}"
                )));
            }
            aliases.insert(alias, MintAlias { mint, decimals });
        }

        let default_label = section
            .get("default_label")
            .filter(|value| !value.is_empty())
            .map(|value| validate_text("default_label", value, MAX_LABEL_BYTES))
            .transpose()?
            .map(str::to_owned);

        let allowed_recipients = match section.get("allowed_recipients") {
            None => None,
            Some(value) => {
                let entries = split_list(value, "allowed_recipients")?;
                if entries.len() > MAX_ALLOWED_RECIPIENTS {
                    return Err(RequestError::ConfigLimit {
                        field: "allowed_recipients",
                        maximum: MAX_ALLOWED_RECIPIENTS,
                    });
                }
                let mut recipients = BTreeSet::new();
                for entry in entries {
                    let recipient = Pubkey::from_str(entry).map_err(|_| {
                        RequestError::Config(
                            "allowed_recipients contains an invalid public key".to_string(),
                        )
                    })?;
                    recipients.insert(recipient);
                }
                Some(recipients)
            }
        };

        Ok(Self {
            aliases,
            default_label,
            allowed_recipients,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Asset {
    Sol,
    Alias {
        name: String,
        mint: Pubkey,
        decimals: u8,
    },
    DirectMint(Pubkey),
}

impl Asset {
    fn mint(&self) -> Option<Pubkey> {
        match self {
            Self::Sol => None,
            Self::Alias { mint, .. } | Self::DirectMint(mint) => Some(*mint),
        }
    }

    fn decimals(&self) -> Option<u8> {
        match self {
            Self::Sol => Some(9),
            Self::Alias { decimals, .. } => Some(*decimals),
            Self::DirectMint(_) => None,
        }
    }

    fn summary_name(&self) -> String {
        match self {
            Self::Sol => "SOL".to_string(),
            Self::Alias { name, .. } => name.clone(),
            Self::DirectMint(mint) => format!("token {}", elide_address(mint)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    InvalidArguments(String),
    InvalidRecipient,
    RecipientNotAllowed,
    InvalidMint,
    UnknownMintAlias(String),
    MissingAliasDecimals(String),
    InvalidAmount(String),
    EmptyField(&'static str),
    FieldTooLong { field: &'static str, maximum: usize },
    InvalidControlCharacter(&'static str),
    Config(String),
    ConfigLimit { field: &'static str, maximum: usize },
    UrlTooLong(usize),
    OutputTooLong(usize),
    OutputSerialization(String),
}

impl RequestError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments(_) => "invalid_arguments",
            Self::InvalidRecipient => "invalid_recipient",
            Self::RecipientNotAllowed => "recipient_not_allowed",
            Self::InvalidMint => "invalid_mint",
            Self::UnknownMintAlias(_) => "unknown_mint_alias",
            Self::MissingAliasDecimals(_) => "missing_alias_decimals",
            Self::InvalidAmount(_) => "invalid_amount",
            Self::EmptyField(_) => "empty_field",
            Self::FieldTooLong { .. } => "field_too_long",
            Self::InvalidControlCharacter(_) => "invalid_control_character",
            Self::Config(_) | Self::ConfigLimit { .. } => "invalid_config",
            Self::UrlTooLong(_) => "url_too_long",
            Self::OutputTooLong(_) => "output_too_long",
            Self::OutputSerialization(_) => "output_serialization",
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(error) => write!(formatter, "invalid arguments: {error}"),
            Self::InvalidRecipient => {
                formatter.write_str("recipient must be a base58-encoded 32-byte public key")
            }
            Self::RecipientNotAllowed => {
                formatter.write_str("recipient is not allowed by operator configuration")
            }
            Self::InvalidMint => {
                formatter.write_str("spl_token must be a configured alias or 32-byte public key")
            }
            Self::UnknownMintAlias(alias) => {
                write!(formatter, "unknown mint alias '{alias}'")
            }
            Self::MissingAliasDecimals(alias) => write!(
                formatter,
                "mint alias '{alias}' requires a matching mint_decimals entry"
            ),
            Self::InvalidAmount(reason) => write!(formatter, "invalid amount: {reason}"),
            Self::EmptyField(field) => write!(formatter, "{field} must not be empty"),
            Self::FieldTooLong { field, maximum } => {
                write!(formatter, "{field} exceeds the {maximum}-byte limit")
            }
            Self::InvalidControlCharacter(field) => {
                write!(formatter, "{field} must not contain control characters")
            }
            Self::Config(error) => write!(formatter, "invalid plugin config: {error}"),
            Self::ConfigLimit { field, maximum } => write!(
                formatter,
                "invalid plugin config: {field} exceeds {maximum} entries"
            ),
            Self::UrlTooLong(length) => write!(
                formatter,
                "Solana Pay URL is {length} bytes; maximum is {MAX_URL_BYTES}"
            ),
            Self::OutputTooLong(length) => write!(
                formatter,
                "tool output is {length} bytes; maximum is {MAX_TOOL_OUTPUT_BYTES}"
            ),
            Self::OutputSerialization(error) => {
                write!(formatter, "could not serialize request output: {error}")
            }
        }
    }
}

impl std::error::Error for RequestError {}

/// Parse the host-injected component envelope and always return a model-visible
/// result. Invalid input is a refusal, not a component fault.
pub fn execute_component_input(input: &str) -> ToolResponse {
    let parsed: ComponentArgs = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(error) => {
            return ToolResponse::refusal(RequestError::InvalidArguments(error.to_string()))
        }
    };
    let config = match RequestConfig::from_section(&parsed.config) {
        Ok(value) => value,
        Err(error) => return ToolResponse::refusal(error),
    };
    match build_request(parsed.into(), &config).and_then(serialize_output) {
        Ok(output) => ToolResponse::success(output),
        Err(error) => ToolResponse::refusal(error),
    }
}

pub fn build_request(
    args: RequestArgs,
    config: &RequestConfig,
) -> Result<RequestOutput, RequestError> {
    let recipient =
        Pubkey::from_str(&args.recipient).map_err(|_| RequestError::InvalidRecipient)?;
    if let Some(allowed) = &config.allowed_recipients {
        if !allowed.contains(&recipient) {
            return Err(RequestError::RecipientNotAllowed);
        }
    }

    let invoice_id = validate_text("invoice_id", &args.invoice_id, MAX_INVOICE_BYTES)?;
    if invoice_id.chars().any(char::is_control) {
        return Err(RequestError::InvalidControlCharacter("invoice_id"));
    }
    let asset = resolve_asset(args.spl_token.as_deref(), config)?;
    let amount = canonical_amount(&args.amount, asset.decimals())?;

    let label = args
        .label
        .as_deref()
        .filter(|value| !value.is_empty())
        .or(config.default_label.as_deref())
        .map(|value| validate_text("label", value, MAX_LABEL_BYTES))
        .transpose()?;
    let message = optional_text("message", args.message.as_deref(), MAX_MESSAGE_BYTES)?;
    let memo = optional_text("memo", args.memo.as_deref(), MAX_MEMO_BYTES)?;

    let reference = derive_reference(&recipient, asset.mint().as_ref(), &amount, invoice_id);
    let reference_text = reference.to_string();
    let url = build_url(
        &recipient,
        &amount,
        asset.mint().as_ref(),
        &reference_text,
        label,
        message,
        memo,
    )?;
    let summary = format!(
        "Request: {amount} {} to {} · invoice {}",
        asset.summary_name(),
        elide_address(&recipient),
        quote_untrusted(invoice_id, SUMMARY_INVOICE_CHARS)
    );

    Ok(RequestOutput {
        qr_payload: url.clone(),
        url,
        summary,
        reference: reference_text,
    })
}

/// Derive a reference with fixed-width address fields and u32 big-endian
/// framing for the two variable-width fields. Framing prevents tuples such as
/// (`1`, `23`) and (`12`, `3`) from hashing to the same byte stream.
pub fn derive_reference(
    recipient: &Pubkey,
    mint: Option<&Pubkey>,
    canonical_amount: &str,
    invoice_id: &str,
) -> Pubkey {
    let mut hasher = Sha256::new();
    hasher.update(REFERENCE_DOMAIN);
    hasher.update(recipient.as_bytes());
    match mint {
        Some(mint) => {
            hasher.update([1]);
            hasher.update(mint.as_bytes());
        }
        None => {
            hasher.update([0]);
            hasher.update(NATIVE_SOL_MINT_SENTINEL);
        }
    }
    update_frame(&mut hasher, canonical_amount.as_bytes());
    update_frame(&mut hasher, invoice_id.as_bytes());
    Pubkey::new(hasher.finalize().into())
}

pub fn parameters_schema() -> String {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "recipient": {
                "type": "string",
                "description": "Base58 public key of the wallet that should receive the payment. Do not use a token account."
            },
            "amount": {
                "type": "string",
                "description": "Exact non-negative UI amount as a decimal string; no signs or scientific notation."
            },
            "spl_token": {
                "type": "string",
                "description": "Optional SPL mint public key or operator-configured alias such as USDC. Omit for native SOL."
            },
            "invoice_id": {
                "type": "string",
                "description": "Required merchant invoice identifier used to derive the deterministic payment reference."
            },
            "label": {
                "type": "string",
                "description": "Optional source label shown by compatible wallets."
            },
            "message": {
                "type": "string",
                "description": "Optional payment description shown by compatible wallets."
            },
            "memo": {
                "type": "string",
                "description": "Optional public on-chain memo; never include sensitive information."
            }
        },
        "required": ["recipient", "amount", "invoice_id"]
    })
    .to_string()
}

fn resolve_asset(input: Option<&str>, config: &RequestConfig) -> Result<Asset, RequestError> {
    let Some(input) = input else {
        return Ok(Asset::Sol);
    };
    if input.is_empty() {
        return Err(RequestError::InvalidMint);
    }
    if let Some(alias) = config.aliases.get(input) {
        return Ok(Asset::Alias {
            name: input.to_string(),
            mint: alias.mint,
            decimals: alias.decimals,
        });
    }
    match Pubkey::from_str(input) {
        Ok(mint) => Ok(Asset::DirectMint(mint)),
        Err(_) if is_alias(input) => Err(RequestError::UnknownMintAlias(input.to_string())),
        Err(_) => Err(RequestError::InvalidMint),
    }
}

fn canonical_amount(input: &str, decimals: Option<u8>) -> Result<String, RequestError> {
    validate_text("amount", input, MAX_AMOUNT_BYTES)?;
    if !input.is_ascii() {
        return Err(RequestError::InvalidAmount(
            "only ASCII decimal digits and one optional dot are allowed".to_string(),
        ));
    }
    if let Some(decimals) = decimals {
        let raw = parse_ui_amount(input, decimals).map_err(amount_error)?;
        return format_ui_amount(raw, decimals).map_err(amount_error);
    }

    let mut pieces = input.split('.');
    let whole = pieces.next().ok_or_else(invalid_amount_syntax)?;
    let fraction = pieces.next();
    if pieces.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid_amount_syntax());
    }
    if let Some(fraction) = fraction {
        if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_amount_syntax());
        }
        if fraction.len() > usize::from(MAX_SUPPORTED_DECIMALS) {
            return Err(RequestError::InvalidAmount(format!(
                "direct mints are limited to {MAX_SUPPORTED_DECIMALS} fractional digits without network metadata"
            )));
        }
    }

    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    whole
        .parse::<u64>()
        .map_err(|_| RequestError::InvalidAmount("whole units exceed u64::MAX".to_string()))?;
    let fraction = fraction.unwrap_or_default().trim_end_matches('0');
    if fraction.is_empty() {
        Ok(whole.to_string())
    } else {
        Ok(format!("{whole}.{fraction}"))
    }
}

fn amount_error(error: AmountError) -> RequestError {
    RequestError::InvalidAmount(error.to_string())
}

fn invalid_amount_syntax() -> RequestError {
    RequestError::InvalidAmount(
        "use unsigned decimal digits with an optional non-empty fractional part".to_string(),
    )
}

fn build_url(
    recipient: &Pubkey,
    amount: &str,
    mint: Option<&Pubkey>,
    reference: &str,
    label: Option<&str>,
    message: Option<&str>,
    memo: Option<&str>,
) -> Result<String, RequestError> {
    let mut url = format!("solana:{recipient}");
    let mut first = true;
    append_query(&mut url, &mut first, "amount", amount);
    if let Some(mint) = mint {
        append_query(&mut url, &mut first, "spl-token", &mint.to_string());
    }
    append_query(&mut url, &mut first, "reference", reference);
    if let Some(label) = label {
        append_query(&mut url, &mut first, "label", label);
    }
    if let Some(message) = message {
        append_query(&mut url, &mut first, "message", message);
    }
    if let Some(memo) = memo {
        append_query(&mut url, &mut first, "memo", memo);
    }
    if url.len() > MAX_URL_BYTES {
        return Err(RequestError::UrlTooLong(url.len()));
    }
    Ok(url)
}

fn append_query(url: &mut String, first: &mut bool, key: &str, value: &str) {
    url.push(if *first { '?' } else { '&' });
    *first = false;
    url.push_str(key);
    url.push('=');
    url.push_str(&form_urlencode(value));
}

/// Match `URL.searchParams` encoding used by the official `@solana/pay`
/// encoder: space becomes `+`; alphanumeric, `*`, `-`, `.`, and `_` remain.
fn form_urlencode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                output.push(char::from(*byte));
            }
            b' ' => output.push('+'),
            value => {
                output.push('%');
                output.push(char::from(HEX[usize::from(value >> 4)]));
                output.push(char::from(HEX[usize::from(value & 0x0f)]));
            }
        }
    }
    output
}

fn update_frame(hasher: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn serialize_output(output: RequestOutput) -> Result<String, RequestError> {
    let serialized = serde_json::to_string(&output)
        .map_err(|error| RequestError::OutputSerialization(error.to_string()))?;
    if serialized.len() >= MAX_TOOL_OUTPUT_BYTES {
        return Err(RequestError::OutputTooLong(serialized.len()));
    }
    Ok(serialized)
}

fn optional_text<'a>(
    field: &'static str,
    value: Option<&'a str>,
    maximum: usize,
) -> Result<Option<&'a str>, RequestError> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| validate_text(field, value, maximum))
        .transpose()
}

fn validate_text<'a>(
    field: &'static str,
    value: &'a str,
    maximum: usize,
) -> Result<&'a str, RequestError> {
    if value.is_empty() {
        return Err(RequestError::EmptyField(field));
    }
    if value.len() > maximum {
        return Err(RequestError::FieldTooLong { field, maximum });
    }
    Ok(value)
}

fn validate_alias(alias: &str) -> Result<(), RequestError> {
    if !is_alias(alias) {
        return Err(RequestError::Config(format!(
            "mint alias '{alias}' must start with a letter and contain only letters, digits, '_' or '-' (max {MAX_ALIAS_BYTES} bytes)"
        )));
    }
    Ok(())
}

fn is_alias(alias: &str) -> bool {
    alias.len() <= MAX_ALIAS_BYTES
        && alias
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn parse_assignments(
    value: Option<&String>,
    field: &'static str,
) -> Result<BTreeMap<String, String>, RequestError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    if value.is_empty() {
        return Ok(BTreeMap::new());
    }
    let entries = split_list(value, field)?;
    let mut output = BTreeMap::new();
    for entry in entries {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| RequestError::Config(format!("{field} entries must use NAME=value")))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() || value.contains('=') {
            return Err(RequestError::Config(format!(
                "{field} contains an invalid assignment"
            )));
        }
        if output.insert(key.to_string(), value.to_string()).is_some() {
            return Err(RequestError::Config(format!(
                "{field} defines '{key}' more than once"
            )));
        }
    }
    Ok(output)
}

fn split_list<'a>(value: &'a str, field: &'static str) -> Result<Vec<&'a str>, RequestError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<_> = value.split(',').map(str::trim).collect();
    if entries.iter().any(|entry| entry.is_empty()) {
        return Err(RequestError::Config(format!(
            "{field} contains an empty list entry"
        )));
    }
    Ok(entries)
}
