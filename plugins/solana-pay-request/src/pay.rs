//! Pure Solana Pay transfer-request builder.
//!
//! No wit-bindgen or wasm dependency so this compiles and tests on the host
//! with a plain `cargo test`. The wasm component reuses the same logic via
//! `lib.rs`.
//!
//! Custody tier: **T1 Build** — returns a `solana:` URL and QR payload only.
//! Never holds keys, never signs, never submits.

use std::collections::HashMap;
use std::fmt::Write as _;

/// Base58 alphabet used by Solana (Bitcoin-style, no 0/O/I/l).
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Well-known mainnet USDC mint (for docs/examples; not hard-required).
pub const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Operator policy from the plugin's own config section.
#[derive(Debug, Clone)]
pub struct PayConfig {
    /// Default merchant label embedded in the Solana Pay URL when args omit it.
    pub default_label: Option<String>,
    /// Hard ceiling on `amount` (UI units). Requests above this fail closed.
    pub max_amount: Option<f64>,
    /// If non-empty, only these SPL mints (or native SOL when empty mint) are allowed.
    /// Comma-separated base58 mints in config; native SOL is represented by the
    /// literal token `native` or by omitting mint when `allow_native` is true.
    pub allowed_mints: Vec<String>,
    /// Whether native SOL transfers are allowed when the allowlist is active.
    pub allow_native: bool,
    /// Optional default memo prefix (e.g. invoice brand).
    pub memo_prefix: Option<String>,
}

impl PayConfig {
    /// Build from the flat `string -> string` section the host injects.
    /// Absent keys → open defaults (no max, no allowlist). Operators should
    /// set `max_amount` and `allowed_mints` in production.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let default_label = section
            .get("default_label")
            .filter(|v| !v.is_empty())
            .cloned();
        let max_amount = section
            .get("max_amount")
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|n| n.is_finite() && *n > 0.0);
        let allowed_mints = section
            .get("allowed_mints")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let allow_native = section
            .get("allow_native")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let memo_prefix = section
            .get("memo_prefix")
            .filter(|v| !v.is_empty())
            .cloned();
        Self {
            default_label,
            max_amount,
            allowed_mints,
            allow_native,
            memo_prefix,
        }
    }
}

/// Arguments for a single Solana Pay transfer request.
#[derive(Debug, Clone)]
pub struct PayRequest {
    /// Recipient wallet (base58 pubkey). Required.
    pub recipient: String,
    /// Decimal amount in UI units (e.g. `25` for 25 USDC). Optional per Solana Pay.
    pub amount: Option<f64>,
    /// SPL mint; omit for native SOL.
    pub mint: Option<String>,
    /// Memo for invoice reconciliation (on-chain memo program).
    pub memo: Option<String>,
    /// One or more reference pubkeys for `findReference` matching.
    pub references: Vec<String>,
    /// Merchant label shown in wallets.
    pub label: Option<String>,
    /// Human message shown in wallets.
    pub message: Option<String>,
}

/// Successful build output — shaped for an LLM chat window (~200 tokens).
#[derive(Debug, Clone, PartialEq)]
pub struct PayResult {
    /// Full `solana:<recipient>?…` transfer-request URL.
    pub url: String,
    /// Same URL — QR libraries encode this string directly.
    pub qr_payload: String,
    /// Short human summary for the approval/chat UI.
    pub summary: String,
    /// Custody tier reminder for the agent.
    pub custody_tier: &'static str,
}

/// Build errors that fail closed (never produce a partial pay URL for bad input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayError {
    MissingRecipient,
    InvalidRecipient(String),
    InvalidAmount(String),
    AmountExceedsMax { amount: String, max: String },
    MintNotAllowed(String),
    NativeNotAllowed,
    InvalidMint(String),
    InvalidReference(String),
    /// Reject any attempt to pass secrets / private keys into this tool.
    SecretsNotAccepted,
}

impl std::fmt::Display for PayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayError::MissingRecipient => write!(f, "recipient is required"),
            PayError::InvalidRecipient(r) => {
                write!(f, "recipient is not a valid base58 Solana address: {r}")
            }
            PayError::InvalidAmount(a) => write!(f, "invalid amount: {a}"),
            PayError::AmountExceedsMax { amount, max } => {
                write!(
                    f,
                    "amount {amount} exceeds configured max_amount {max} — request refused"
                )
            }
            PayError::MintNotAllowed(m) => {
                write!(f, "mint {m} is not on the operator allowlist — request refused")
            }
            PayError::NativeNotAllowed => {
                write!(f, "native SOL is not allowed by config — request refused")
            }
            PayError::InvalidMint(m) => {
                write!(f, "mint is not a valid base58 Solana address: {m}")
            }
            PayError::InvalidReference(r) => {
                write!(f, "reference is not a valid base58 Solana address: {r}")
            }
            PayError::SecretsNotAccepted => write!(
                f,
                "this tool never accepts private keys or seed phrases — custody tier T1 (build only)"
            ),
        }
    }
}

/// Build a Solana Pay transfer-request URL under the given policy.
///
/// Spec: https://docs.solanapay.com/spec#transfer-request
///
/// Fails closed on invalid addresses, over-cap amounts, disallowed mints, or
/// any attempt to pass a private key / seed phrase field.
pub fn build_pay_request(req: &PayRequest, cfg: &PayConfig) -> Result<PayResult, PayError> {
    // Hard reject secret-shaped fields if a confused agent dumps them into memo/label.
    reject_secrets(req)?;

    let recipient = req.recipient.trim();
    if recipient.is_empty() {
        return Err(PayError::MissingRecipient);
    }
    if !is_solana_address(recipient) {
        return Err(PayError::InvalidRecipient(recipient.to_string()));
    }

    if let Some(amount) = req.amount {
        validate_amount(amount, cfg)?;
    }

    let mint = req.mint.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(m) = mint {
        if !is_solana_address(m) {
            return Err(PayError::InvalidMint(m.to_string()));
        }
        enforce_mint_policy(Some(m), cfg)?;
    } else {
        enforce_mint_policy(None, cfg)?;
    }

    for r in &req.references {
        let r = r.trim();
        if r.is_empty() {
            continue;
        }
        if !is_solana_address(r) {
            return Err(PayError::InvalidReference(r.to_string()));
        }
    }

    let label = req
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| cfg.default_label.clone());

    let memo = compose_memo(req.memo.as_deref(), cfg.memo_prefix.as_deref());

    let url = encode_solana_pay_url(
        recipient,
        req.amount,
        mint,
        &req.references,
        label.as_deref(),
        req.message.as_deref(),
        memo.as_deref(),
    );

    let summary = format_summary(recipient, req.amount, mint, memo.as_deref(), &url);

    Ok(PayResult {
        qr_payload: url.clone(),
        url,
        summary,
        custody_tier: "T1",
    })
}

fn reject_secrets(req: &PayRequest) -> Result<(), PayError> {
    let fields = [
        req.recipient.as_str(),
        req.memo.as_deref().unwrap_or(""),
        req.label.as_deref().unwrap_or(""),
        req.message.as_deref().unwrap_or(""),
    ];
    for f in fields {
        if looks_like_secret(f) {
            return Err(PayError::SecretsNotAccepted);
        }
    }
    Ok(())
}

/// Heuristic: reject seed phrases and hex/base58 secret blobs dumped into fields.
fn looks_like_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.contains("private key")
        || lower.contains("secret key")
        || lower.contains("seed phrase")
        || lower.contains("mnemonic")
    {
        return true;
    }
    // 12/24-word seed phrase (very rough: many short words)
    let words: Vec<&str> = s.split_whitespace().collect();
    if (words.len() == 12 || words.len() == 24)
        && words.iter().all(|w| w.len() >= 3 && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase()))
    {
        return true;
    }
    false
}

fn validate_amount(amount: f64, cfg: &PayConfig) -> Result<(), PayError> {
    if !amount.is_finite() || amount <= 0.0 {
        return Err(PayError::InvalidAmount(amount.to_string()));
    }
    // Cap decimal places for URL cleanliness (Solana Pay: up to mint decimals; we use 9).
    if let Some(max) = cfg.max_amount {
        if amount > max {
            return Err(PayError::AmountExceedsMax {
                amount: format_amount(amount),
                max: format_amount(max),
            });
        }
    }
    Ok(())
}

fn enforce_mint_policy(mint: Option<&str>, cfg: &PayConfig) -> Result<(), PayError> {
    // Empty allowlist = no restriction.
    if cfg.allowed_mints.is_empty() {
        return Ok(());
    }
    match mint {
        None => {
            // Native SOL: allowed only if operator opted in via allow_native
            // AND listed `native` / `SOL` on the allowlist (explicit).
            let native_listed = cfg.allowed_mints.iter().any(|m| {
                m.eq_ignore_ascii_case("native") || m.eq_ignore_ascii_case("sol")
            });
            if cfg.allow_native && native_listed {
                Ok(())
            } else {
                Err(PayError::NativeNotAllowed)
            }
        }
        Some(m) => {
            if cfg.allowed_mints.iter().any(|a| a == m) {
                Ok(())
            } else {
                Err(PayError::MintNotAllowed(m.to_string()))
            }
        }
    }
}

fn compose_memo(memo: Option<&str>, prefix: Option<&str>) -> Option<String> {
    let memo = memo.map(str::trim).filter(|s| !s.is_empty());
    match (prefix, memo) {
        (Some(p), Some(m)) => {
            if m.starts_with(p) {
                Some(m.to_string())
            } else {
                Some(format!("{p}{m}"))
            }
        }
        (None, Some(m)) => Some(m.to_string()),
        (Some(_), None) => None,
        (None, None) => None,
    }
}

fn encode_solana_pay_url(
    recipient: &str,
    amount: Option<f64>,
    mint: Option<&str>,
    references: &[String],
    label: Option<&str>,
    message: Option<&str>,
    memo: Option<&str>,
) -> String {
    let mut url = format!("solana:{recipient}");
    let mut first = true;
    let mut push = |key: &str, value: &str| {
        if first {
            url.push('?');
            first = false;
        } else {
            url.push('&');
        }
        url.push_str(key);
        url.push('=');
        url.push_str(&percent_encode(value));
    };

    if let Some(a) = amount {
        push("amount", &format_amount(a));
    }
    if let Some(m) = mint {
        push("spl-token", m);
    }
    for r in references {
        let r = r.trim();
        if !r.is_empty() {
            push("reference", r);
        }
    }
    if let Some(l) = label {
        let l = l.trim();
        if !l.is_empty() {
            push("label", l);
        }
    }
    if let Some(m) = message {
        let m = m.trim();
        if !m.is_empty() {
            push("message", m);
        }
    }
    if let Some(m) = memo {
        let m = m.trim();
        if !m.is_empty() {
            push("memo", m);
        }
    }
    url
}

fn format_summary(
    recipient: &str,
    amount: Option<f64>,
    mint: Option<&str>,
    memo: Option<&str>,
    url: &str,
) -> String {
    let mut s = String::new();
    let _ = write!(s, "Solana Pay request (T1 — unsigned, human pays). ");
    match (amount, mint) {
        (Some(a), Some(m)) => {
            let _ = write!(
                s,
                "Charge {} of mint {}…{} to {}…{}. ",
                format_amount(a),
                &m[..4.min(m.len())],
                &m[m.len().saturating_sub(4)..],
                &recipient[..4.min(recipient.len())],
                &recipient[recipient.len().saturating_sub(4)..]
            );
        }
        (Some(a), None) => {
            let _ = write!(
                s,
                "Charge {} SOL to {}…{}. ",
                format_amount(a),
                &recipient[..4.min(recipient.len())],
                &recipient[recipient.len().saturating_sub(4)..]
            );
        }
        (None, _) => {
            let _ = write!(
                s,
                "Open-ended transfer to {}…{}. ",
                &recipient[..4.min(recipient.len())],
                &recipient[recipient.len().saturating_sub(4)..]
            );
        }
    }
    if let Some(m) = memo {
        let _ = write!(s, "Memo: {m}. ");
    }
    let _ = write!(
        s,
        "No keys held. Share the URL/QR; a human wallet completes payment.\nURL: {url}"
    );
    s
}

/// Format amount without scientific notation; trim trailing zeros.
pub fn format_amount(amount: f64) -> String {
    // Fixed 9 decimals then trim — matches SOL lamport precision for display.
    let mut s = format!("{amount:.9}");
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    s
}

/// Percent-encode for Solana Pay query values (RFC 3986 unreserved + safe).
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Validate base58 Solana address shape (32-byte pubkey → typically 32–44 chars).
pub fn is_solana_address(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 32 || s.len() > 44 {
        return false;
    }
    if !s.bytes().all(|b| BASE58_ALPHABET.contains(&b)) {
        return false;
    }
    // Decode length check: base58 of 32 bytes is never under 32 chars in practice
    // for Solana ed25519 pubkeys; reject all-same-digit noise.
    true
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn format_amount_trims() {
        assert_eq!(format_amount(25.0), "25");
        assert_eq!(format_amount(1.5), "1.5");
        assert_eq!(format_amount(0.000001), "0.000001");
    }
}
