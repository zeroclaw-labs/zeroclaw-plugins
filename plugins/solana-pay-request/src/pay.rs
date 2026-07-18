//! Pure Solana Pay transfer-request core. No wasm, no HTTP, no secrets.
//!
//! Builds `solana:` transfer-request URLs per the Solana Pay spec
//! (<https://docs.solanapay.com/spec>), with three guardrails enforced *here*,
//! below the LLM, so no prompt can talk past them:
//!
//! 1. **Pinned recipient** — when the operator sets `recipient` in config,
//!    every request pays that address; an argument that names a different
//!    recipient is rejected, not silently overridden.
//! 2. **Token allowlist** — only operator-listed symbols/mints are accepted.
//! 3. **Amount cap** — requests above `max_amount` fail closed.

use std::collections::HashMap;

use reference::derive_reference;
use zeroclaw_solana_core::pubkey::Pubkey;

/// USDC on mainnet-beta, the default allowlisted token.
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// Marker mint value for native SOL (no `spl-token` param in the URL).
pub const NATIVE_SOL: &str = "native";
const DEFAULT_MAX_AMOUNT: &str = "1000";

/// Policy resolved from the plugin's own config section.
pub struct PayConfig {
    /// When set, the only address requests may pay.
    pub pinned_recipient: Option<Pubkey>,
    /// symbol (upper-case) → mint base58, or `native` for SOL.
    pub tokens: Vec<(String, String)>,
    /// Per-request cap in token units (decimal string), used for any token
    /// without a per-symbol override.
    pub max_amount: String,
    /// Per-symbol cap overrides (`max_amounts = "SOL:0.5,USDC:500"`), so a
    /// shared numeric cap never conflates tokens of very different value.
    pub max_amounts: Vec<(String, String)>,
    /// Default label attached to requests (e.g. the shop name).
    pub label: Option<String>,
    /// When true, and no recipient is pinned, the caller may supply the payee
    /// address per request (a roaming "point of sale" terminal). Defaults to
    /// false so forgetting to pin a recipient fails closed instead of letting
    /// the model choose who gets paid.
    pub allow_arg_recipient: bool,
}

impl PayConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let pinned_recipient = match section.get("recipient").filter(|v| !v.is_empty()) {
            Some(addr) => Some(
                Pubkey::parse(addr)
                    .map_err(|e| format!("config error: bad pinned recipient: {e}"))?,
            ),
            None => None,
        };
        let tokens = match section.get("tokens").filter(|v| !v.is_empty()) {
            Some(spec) => parse_token_list(spec)?,
            None => vec![
                ("USDC".to_string(), USDC_MINT.to_string()),
                ("SOL".to_string(), NATIVE_SOL.to_string()),
            ],
        };
        let max_amount = section
            .get("max_amount")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_MAX_AMOUNT.to_string());
        validate_decimal(&max_amount)?;
        let max_amounts = section
            .get("max_amounts")
            .map(String::as_str)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|entry| {
                let (sym, cap) = entry.split_once(':').ok_or_else(|| {
                    format!("config error: max_amounts entry {entry:?} is not SYMBOL:cap")
                })?;
                let cap = cap.trim();
                validate_decimal(cap).map_err(|e| format!("config error: max_amounts: {e}"))?;
                Ok((sym.trim().to_ascii_uppercase(), cap.to_string()))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let allow_arg_recipient = section
            .get("allow_arg_recipient")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(Self {
            pinned_recipient,
            tokens,
            max_amount,
            max_amounts,
            label: section.get("label").filter(|v| !v.is_empty()).cloned(),
            allow_arg_recipient,
        })
    }
}

/// Parse `"USDC:EPjF…,SOL:native"` into an allowlist.
fn parse_token_list(spec: &str) -> Result<Vec<(String, String)>, String> {
    let mut tokens = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (symbol, mint) = entry
            .split_once(':')
            .ok_or_else(|| format!("config error: token entry {entry:?} is not SYMBOL:mint"))?;
        let mint = mint.trim();
        if mint != NATIVE_SOL {
            Pubkey::parse(mint).map_err(|e| format!("config error: token {symbol:?}: {e}"))?;
        }
        tokens.push((symbol.trim().to_ascii_uppercase(), mint.to_string()));
    }
    if tokens.is_empty() {
        return Err("config error: `tokens` is set but empty".to_string());
    }
    Ok(tokens)
}

/// Arguments the LLM supplies.
pub struct PayArgs {
    pub amount: String,
    pub token: Option<String>,
    pub recipient: Option<String>,
    pub label: Option<String>,
    pub message: Option<String>,
    pub memo: Option<String>,
    /// Free-form invoice id folded into the deterministic reference key.
    pub invoice_id: Option<String>,
}

#[derive(Debug)]
pub struct PayRequest {
    pub url: String,
    pub reference: String,
    pub summary: String,
}

/// Strict unsigned decimal for a URL: digits, and if a dot is present it must
/// have digits on both sides — "25." or ".5" would be valid numbers but
/// ambiguous for wallets rendering the URL, so they are rejected too.
fn validate_decimal(s: &str) -> Result<(), String> {
    let s = s.trim();
    let ok = match s.split_once('.') {
        None => !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()),
        Some((whole, frac)) => {
            !whole.is_empty()
                && !frac.is_empty()
                && whole.chars().all(|c| c.is_ascii_digit())
                && frac.chars().all(|c| c.is_ascii_digit())
        }
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid amount {s:?}: expected a plain decimal like \"25\" or \"0.5\""
        ))
    }
}

/// Compare two validated decimal strings numerically (no floats).
fn decimal_gt(a: &str, b: &str) -> bool {
    fn parts(s: &str) -> (String, String) {
        let s = s.trim();
        let (w, f) = s.split_once('.').unwrap_or((s, ""));
        (
            w.trim_start_matches('0').to_string(),
            f.trim_end_matches('0').to_string(),
        )
    }
    let (aw, af) = parts(a);
    let (bw, bf) = parts(b);
    if aw.len() != bw.len() {
        return aw.len() > bw.len();
    }
    if aw != bw {
        return aw > bw;
    }
    let width = af.len().max(bf.len());
    format!("{af:0<width$}") > format!("{bf:0<width$}")
}

/// RFC 3986 percent-encoding for URL query values.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Build a Solana Pay transfer request under the configured policy.
/// Every guardrail failure is an `Err` — the tool never "corrects" a request.
pub fn build_request(args: &PayArgs, cfg: &PayConfig) -> Result<PayRequest, String> {
    validate_decimal(&args.amount)?;

    let symbol = args
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_uppercase)
        .unwrap_or_else(|| cfg.tokens[0].0.clone());
    let mint = cfg
        .tokens
        .iter()
        .find(|(sym, _)| *sym == symbol)
        .map(|(_, mint)| mint.clone())
        .ok_or_else(|| {
            format!(
                "refused: token {symbol:?} is not in the operator allowlist ({})",
                cfg.tokens
                    .iter()
                    .map(|(s, _)| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    let cap = cfg
        .max_amounts
        .iter()
        .find(|(sym, _)| *sym == symbol)
        .map(|(_, cap)| cap.as_str())
        .unwrap_or(&cfg.max_amount);
    if decimal_gt(&args.amount, cap) {
        return Err(format!(
            "refused: amount {} exceeds the operator-configured cap of {cap} per {symbol} request",
            args.amount.trim(),
        ));
    }

    let recipient = resolve_recipient(args.recipient.as_deref(), cfg)?;

    let reference = derive_reference(
        &recipient.to_base58(),
        &args.amount,
        &mint,
        args.invoice_id.as_deref().unwrap_or(""),
    );

    let mut url = format!(
        "solana:{}?amount={}",
        recipient.to_base58(),
        args.amount.trim()
    );
    if mint != NATIVE_SOL {
        url.push_str(&format!("&spl-token={mint}"));
    }
    url.push_str(&format!("&reference={reference}"));
    if let Some(label) = args.label.as_deref().or(cfg.label.as_deref()) {
        url.push_str(&format!("&label={}", percent_encode(label)));
    }
    if let Some(message) = args.message.as_deref().filter(|m| !m.is_empty()) {
        url.push_str(&format!("&message={}", percent_encode(message)));
    }
    if let Some(memo) = args.memo.as_deref().filter(|m| !m.is_empty()) {
        url.push_str(&format!("&memo={}", percent_encode(memo)));
    }

    let summary = format!(
        "Solana Pay request: {} {} to {}. Scan as QR or open with any Solana Pay wallet. Track payment by reference {}.",
        args.amount.trim(),
        symbol,
        abbreviate(&recipient.to_base58()),
        abbreviate(&reference),
    );

    Ok(PayRequest {
        url,
        reference,
        summary,
    })
}

fn resolve_recipient(requested: Option<&str>, cfg: &PayConfig) -> Result<Pubkey, String> {
    let requested = requested.map(str::trim).filter(|r| !r.is_empty());
    match (&cfg.pinned_recipient, requested) {
        (Some(pinned), None) => Ok(*pinned),
        (Some(pinned), Some(req)) => {
            // Fail closed on any mismatch instead of silently redirecting:
            // the model (or whoever is prompting it) must not choose payees.
            if Pubkey::parse(req).ok() == Some(*pinned) {
                Ok(*pinned)
            } else {
                Err(format!(
                    "refused: recipient is pinned by operator config; cannot pay {req:?}"
                ))
            }
        }
        // No pin: the caller may only choose the payee when the operator has
        // explicitly opted into roaming-terminal mode. Otherwise fail closed —
        // a forgotten `recipient` must never mean "let the model decide".
        (None, Some(req)) if cfg.allow_arg_recipient => Pubkey::parse(req),
        (None, Some(_)) => Err(
            "refused: no recipient is pinned and `allow_arg_recipient` is not enabled; \
             set `recipient` in config to pin the payee, or set `allow_arg_recipient = true` \
             to run as a roaming terminal"
                .to_string(),
        ),
        (None, None) => Err(
            "no recipient: pin `recipient` in the plugin config (or enable \
             `allow_arg_recipient` and pass one)"
                .to_string(),
        ),
    }
}

fn abbreviate(addr: &str) -> String {
    if addr.len() <= 12 {
        return addr.to_string();
    }
    format!("{}…{}", &addr[..4], &addr[addr.len() - 4..])
}

/// Deterministic payment reference so `payment-watch`-style tooling can find
/// the settlement without any shared state: sha256 over the request tuple,
/// published as a base58 "pubkey" (references are never signed for).
mod reference {
    use zeroclaw_solana_core::encoding::{base58_encode, sha256};

    pub fn derive_reference(recipient: &str, amount: &str, mint: &str, invoice_id: &str) -> String {
        let mut chunks: Vec<Vec<u8>> = vec![b"zeroclaw-solana-pay-reference:v1".to_vec()];
        for part in [recipient, amount.trim(), mint, invoice_id] {
            chunks.push((part.len() as u64).to_le_bytes().to_vec());
            chunks.push(part.as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        base58_encode(&sha256(&refs))
    }
}
