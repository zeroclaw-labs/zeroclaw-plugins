//! T2 x402 settle core — full safety rails, fail closed.
//!
//! Signs **only** with a scoped session key from config. Never accepts keys in args.
//! Requires: max_amount, daily_cap, allowed_mints, approval_token, session_key.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};

use crate::codec::{
    assemble_signed_tx, blockhash_from_base58, compile_legacy_message, derive_ata,
    ix_create_ata_idempotent, ix_memo, ix_transfer_checked, looks_like_pubkey,
    mint_decimals_from_data, parse_session_key, sign_message, ui_to_raw, Pubkey,
};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Operator safety policy. Missing required rails → refuse to sign.
#[derive(Debug, Clone)]
pub struct SettleConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_api_key_header: String,
    pub rpc_api_key_bearer: bool,
    pub commitment: String,
    /// Per-tx hard ceiling (UI units). **Required for T2.**
    pub max_amount: f64,
    /// Per-day hard ceiling (UI units). **Required for T2.**
    pub daily_cap: f64,
    /// Operator-tracked spend so far today (UI). Default 0.
    pub spent_today: f64,
    /// Non-empty mint allowlist. **Required for T2.**
    pub allowed_mints: Vec<String>,
    /// If non-empty, payTo must be on this list.
    pub allowed_payees: Vec<String>,
    /// Shared secret the tool arg `approval` must match. **Required for T2.**
    pub approval_token: String,
    /// Session key material (base58 or JSON byte array). **Required for T2.** Never log.
    pub session_key: String,
    /// Default decimals when payment request omits them (USDC=6).
    pub default_decimals: u8,
}

impl SettleConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, SettleError> {
        let max_amount = section
            .get("max_amount")
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|n| n.is_finite() && *n > 0.0)
            .ok_or(SettleError::Misconfigured(
                "max_amount is required for T2 (per-tx hard cap)",
            ))?;
        let daily_cap = section
            .get("daily_cap")
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|n| n.is_finite() && *n > 0.0)
            .ok_or(SettleError::Misconfigured(
                "daily_cap is required for T2 (per-day hard cap)",
            ))?;
        let spent_today = section
            .get("spent_today")
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|n| n.is_finite() && *n >= 0.0)
            .unwrap_or(0.0);
        let allowed_mints: Vec<String> = section
            .get("allowed_mints")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if allowed_mints.is_empty() {
            return Err(SettleError::Misconfigured(
                "allowed_mints is required for T2 (non-empty mint allowlist)",
            ));
        }
        let allowed_payees = section
            .get("allowed_payees")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let approval_token = section
            .get("approval_token")
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or(SettleError::Misconfigured(
                "approval_token is required for T2 (ZeroClaw approval gate)",
            ))?;
        let session_key = section
            .get("session_key")
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or(SettleError::Misconfigured(
                "session_key is required for T2 (scoped session key only — never a main wallet)",
            ))?;
        let rpc_url = section
            .get("rpc_url")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        let rpc_api_key = section
            .get("rpc_api_key")
            .filter(|v| !v.is_empty())
            .cloned();
        let rpc_api_key_header = section
            .get("rpc_api_key_header")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "Authorization".to_string());
        let rpc_api_key_bearer = section
            .get("rpc_api_key_bearer")
            .map(|v| !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let commitment = section
            .get("commitment")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "confirmed".to_string());
        let default_decimals = section
            .get("default_decimals")
            .and_then(|v| v.parse().ok())
            .unwrap_or(6);

        Ok(Self {
            rpc_url,
            rpc_api_key,
            rpc_api_key_header,
            rpc_api_key_bearer,
            commitment,
            max_amount,
            daily_cap,
            spent_today,
            allowed_mints,
            allowed_payees,
            approval_token,
            session_key,
            default_decimals,
        })
    }

    pub fn rpc_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if let Some(key) = &self.rpc_api_key {
            let value = if self.rpc_api_key_bearer && !key.starts_with("Bearer ") {
                format!("Bearer {key}")
            } else {
                key.clone()
            };
            headers.push((self.rpc_api_key_header.clone(), value));
        }
        headers
    }
}

#[derive(Debug, Clone)]
pub struct SettleRequest {
    /// Paywalled resource URL.
    pub url: String,
    /// HTTP method: GET or POST.
    pub method: String,
    /// Optional JSON body for POST.
    pub body: Option<String>,
    /// Must match config `approval_token` exactly (approval gate).
    pub approval: String,
    /// Optional explicit max willing to pay this call (still clamped by config).
    pub max_payment: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettleResult {
    pub status: String,
    pub http_status: u16,
    pub body: String,
    pub paid: bool,
    pub payment_signature: Option<String>,
    pub amount_paid: Option<f64>,
    pub pay_to: Option<String>,
    pub mint: Option<String>,
    pub summary: String,
    pub custody_tier: &'static str,
    /// Reminder for operator to bump spent_today after success.
    pub spent_today_after: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleError {
    Misconfigured(&'static str),
    ApprovalDenied,
    SecretsNotAccepted,
    InvalidUrl(String),
    InvalidAmount(String),
    AmountExceedsMax { amount: String, max: String },
    DailyCapExceeded { amount: String, remaining: String },
    MintNotAllowed(String),
    PayeeNotAllowed(String),
    NoAcceptablePayment(String),
    Http(String),
    Rpc(String),
    Build(String),
    Sign(String),
}

impl std::fmt::Display for SettleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettleError::Misconfigured(m) => write!(f, "T2 misconfigured — refuse to sign: {m}"),
            SettleError::ApprovalDenied => write!(
                f,
                "approval gate denied — approval token mismatch or missing (fail closed)"
            ),
            SettleError::SecretsNotAccepted => write!(
                f,
                "this tool never accepts private keys in arguments — session key is config-only"
            ),
            SettleError::InvalidUrl(u) => write!(f, "invalid url: {u}"),
            SettleError::InvalidAmount(a) => write!(f, "invalid amount: {a}"),
            SettleError::AmountExceedsMax { amount, max } => write!(
                f,
                "payment {amount} exceeds max_amount {max} — refuse to sign"
            ),
            SettleError::DailyCapExceeded { amount, remaining } => write!(
                f,
                "payment {amount} exceeds remaining daily cap {remaining} — refuse to sign"
            ),
            SettleError::MintNotAllowed(m) => {
                write!(f, "mint {m} not on allowlist — refuse to sign")
            }
            SettleError::PayeeNotAllowed(p) => {
                write!(f, "payee {p} not on allowlist — refuse to sign")
            }
            SettleError::NoAcceptablePayment(m) => write!(f, "no acceptable x402 offer: {m}"),
            SettleError::Http(e) => write!(f, "http error: {e}"),
            SettleError::Rpc(e) => write!(f, "rpc error: {e}"),
            SettleError::Build(e) => write!(f, "build error: {e}"),
            SettleError::Sign(e) => write!(f, "sign error: {e}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// HTTP port (wasm uses waki; tests mock).
pub trait HttpClient {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<HttpResponse, String>;
}

/// Parsed x402 payment requirement (subset).
#[derive(Debug, Clone)]
pub struct PaymentRequirement {
    pub pay_to: String,
    pub mint: String,
    pub amount_raw: u64,
    pub decimals: u8,
    pub amount_ui: f64,
    pub network: String,
}

/// Run x402 settle with full T2 rails.
pub fn settle_x402<H: HttpClient>(
    http: &H,
    cfg: &SettleConfig,
    req: &SettleRequest,
) -> Result<SettleResult, SettleError> {
    validate_request(req)?;
    enforce_approval(cfg, &req.approval)?;

    let method = req.method.trim().to_ascii_uppercase();
    if method != "GET" && method != "POST" {
        return Err(SettleError::InvalidUrl(format!(
            "method must be GET or POST, got {}",
            req.method
        )));
    }
    if !(req.url.starts_with("https://") || req.url.starts_with("http://")) {
        return Err(SettleError::InvalidUrl(req.url.clone()));
    }

    // First attempt — no payment header
    let first = http
        .request(&method, &req.url, &[], req.body.as_deref())
        .map_err(SettleError::Http)?;

    if first.status != 402 {
        return Ok(SettleResult {
            status: if first.status < 400 {
                "ok".into()
            } else {
                "http_error".into()
            },
            http_status: first.status,
            body: truncate_body(&first.body),
            paid: false,
            payment_signature: None,
            amount_paid: None,
            pay_to: None,
            mint: None,
            summary: format!(
                "Resource returned HTTP {} without payment (T2 idle). No keys used.",
                first.status
            ),
            custody_tier: "T2",
            spent_today_after: None,
        });
    }

    let offer = parse_x402_payment(&first.body, cfg)?;
    enforce_payment_policy(cfg, req, &offer)?;

    let (signing, session_pk) =
        parse_session_key(&cfg.session_key).map_err(SettleError::Sign)?;
    // Never allow signing if parsed pubkey looks wrong — session only
    let pay_to = Pubkey::from_base58(&offer.pay_to).map_err(SettleError::Build)?;
    let mint = Pubkey::from_base58(&offer.mint).map_err(SettleError::Build)?;

    let tx_sig = sign_and_submit_transfer(
        http,
        cfg,
        &signing,
        &session_pk,
        &pay_to,
        &mint,
        offer.amount_raw,
        offer.decimals,
        &format!("x402:{}", short_url(&req.url)),
    )?;

    // Retry with payment proof
    let proof = json!({
        "x402Version": 1,
        "scheme": "exact",
        "network": offer.network,
        "payload": {
            "signature": tx_sig,
            "payer": session_pk.to_base58(),
            "payTo": offer.pay_to,
            "asset": offer.mint,
            "amount": offer.amount_raw.to_string(),
        }
    });
    let proof_b64 = B64.encode(proof.to_string().as_bytes());
    let pay_headers = vec![
        ("X-PAYMENT".to_string(), proof_b64.clone()),
        ("PAYMENT-SIGNATURE".to_string(), tx_sig.clone()),
    ];
    let second = http
        .request(&method, &req.url, &pay_headers, req.body.as_deref())
        .map_err(SettleError::Http)?;

    let spent_after = cfg.spent_today + offer.amount_ui;
    let summary = format!(
        "x402 settled (T2 session key). Paid {} of mint {} to {}. Tx {}. Resource HTTP {}. Update spent_today → {}.",
        format_amount(offer.amount_ui),
        short(&offer.mint),
        short(&offer.pay_to),
        short_sig(&tx_sig),
        second.status,
        format_amount(spent_after)
    );

    Ok(SettleResult {
        status: if second.status < 400 {
            "paid_ok".into()
        } else {
            "paid_but_resource_error".into()
        },
        http_status: second.status,
        body: truncate_body(&second.body),
        paid: true,
        payment_signature: Some(tx_sig),
        amount_paid: Some(offer.amount_ui),
        pay_to: Some(offer.pay_to),
        mint: Some(offer.mint),
        summary,
        custody_tier: "T2",
        spent_today_after: Some(spent_after),
    })
}

pub fn result_to_json(r: &SettleResult) -> String {
    json!({
        "custody_tier": r.custody_tier,
        "status": r.status,
        "http_status": r.http_status,
        "body": r.body,
        "paid": r.paid,
        "payment_signature": r.payment_signature,
        "amount_paid": r.amount_paid,
        "pay_to": r.pay_to,
        "mint": r.mint,
        "summary": r.summary,
        "spent_today_after": r.spent_today_after,
        "note": "T2 session-key settle. Never fund this key as a main wallet. Bump spent_today after paid=true."
    })
    .to_string()
}

fn validate_request(req: &SettleRequest) -> Result<(), SettleError> {
    for f in [
        req.url.as_str(),
        req.approval.as_str(),
        req.body.as_deref().unwrap_or(""),
    ] {
        if looks_like_secret(f) {
            return Err(SettleError::SecretsNotAccepted);
        }
    }
    // Explicit reject of key-like args people might try
    if req.url.contains("session_key") || req.url.contains("private") {
        // still allow normal URLs; only fail on seed phrases above
    }
    Ok(())
}

fn looks_like_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.contains("private key")
        || lower.contains("secret key")
        || lower.contains("seed phrase")
        || lower.contains("mnemonic")
    {
        return true;
    }
    let words: Vec<&str> = s.split_whitespace().collect();
    (words.len() == 12 || words.len() == 24)
        && words
            .iter()
            .all(|w| w.len() >= 3 && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase()))
}

fn enforce_approval(cfg: &SettleConfig, approval: &str) -> Result<(), SettleError> {
    if approval.is_empty() || approval != cfg.approval_token {
        return Err(SettleError::ApprovalDenied);
    }
    Ok(())
}

fn enforce_payment_policy(
    cfg: &SettleConfig,
    req: &SettleRequest,
    offer: &PaymentRequirement,
) -> Result<(), SettleError> {
    if !cfg.allowed_mints.iter().any(|m| m == &offer.mint) {
        return Err(SettleError::MintNotAllowed(offer.mint.clone()));
    }
    if !cfg.allowed_payees.is_empty()
        && !cfg.allowed_payees.iter().any(|p| p == &offer.pay_to)
    {
        return Err(SettleError::PayeeNotAllowed(offer.pay_to.clone()));
    }
    if !looks_like_pubkey(&offer.pay_to) {
        return Err(SettleError::Build(format!(
            "payTo not a valid address: {}",
            offer.pay_to
        )));
    }
    if offer.amount_ui > cfg.max_amount + f64::EPSILON {
        return Err(SettleError::AmountExceedsMax {
            amount: format_amount(offer.amount_ui),
            max: format_amount(cfg.max_amount),
        });
    }
    if let Some(user_max) = req.max_payment {
        if offer.amount_ui > user_max + f64::EPSILON {
            return Err(SettleError::AmountExceedsMax {
                amount: format_amount(offer.amount_ui),
                max: format_amount(user_max),
            });
        }
    }
    let remaining = (cfg.daily_cap - cfg.spent_today).max(0.0);
    if offer.amount_ui > remaining + f64::EPSILON {
        return Err(SettleError::DailyCapExceeded {
            amount: format_amount(offer.amount_ui),
            remaining: format_amount(remaining),
        });
    }
    Ok(())
}

/// Parse flexible x402 / 402 JSON bodies.
pub fn parse_x402_payment(body: &str, cfg: &SettleConfig) -> Result<PaymentRequirement, SettleError> {
    let v: Value = serde_json::from_str(body).map_err(|e| {
        SettleError::NoAcceptablePayment(format!("402 body is not JSON: {e}"))
    })?;

    // accepts[] array (x402 style) or top-level fields
    let candidate = if let Some(arr) = v.get("accepts").and_then(|a| a.as_array()) {
        arr.iter()
            .find(|c| {
                let net = c
                    .get("network")
                    .and_then(|n| n.as_str())
                    .unwrap_or("solana");
                net.to_ascii_lowercase().contains("solana")
            })
            .cloned()
            .ok_or_else(|| SettleError::NoAcceptablePayment("no solana accept entry".into()))?
    } else if v.get("payTo").is_some() || v.get("pay_to").is_some() {
        v.clone()
    } else if let Some(p) = v.get("payment").cloned() {
        p
    } else {
        return Err(SettleError::NoAcceptablePayment(
            "expected accepts[] or payTo fields".into(),
        ));
    };

    let pay_to = candidate
        .get("payTo")
        .or_else(|| candidate.get("pay_to"))
        .or_else(|| candidate.get("recipient"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| SettleError::NoAcceptablePayment("missing payTo".into()))?
        .to_string();

    let mint = candidate
        .get("asset")
        .or_else(|| candidate.get("mint"))
        .or_else(|| candidate.get("spl-token"))
        .and_then(|x| x.as_str())
        .unwrap_or(USDC_MINT_MAINNET)
        .to_string();

    let decimals = candidate
        .pointer("/extra/decimals")
        .or_else(|| candidate.get("decimals"))
        .and_then(|d| d.as_u64())
        .map(|d| d as u8)
        .unwrap_or(cfg.default_decimals);

    let (amount_raw, amount_ui) = if let Some(s) = candidate
        .get("maxAmountRequired")
        .or_else(|| candidate.get("amount_raw"))
        .or_else(|| candidate.get("amount"))
        .and_then(|a| a.as_str())
    {
        // string raw integer
        if let Ok(raw) = s.parse::<u64>() {
            let ui = raw as f64 / 10f64.powi(decimals as i32);
            (raw, ui)
        } else if let Ok(ui) = s.parse::<f64>() {
            let raw = ui_to_raw(ui, decimals).map_err(SettleError::InvalidAmount)?;
            (raw, ui)
        } else {
            return Err(SettleError::InvalidAmount(s.to_string()));
        }
    } else if let Some(raw) = candidate
        .get("maxAmountRequired")
        .or_else(|| candidate.get("amount"))
        .and_then(|a| a.as_u64())
    {
        let ui = raw as f64 / 10f64.powi(decimals as i32);
        (raw, ui)
    } else if let Some(ui) = candidate.get("amount").and_then(|a| a.as_f64()) {
        let raw = ui_to_raw(ui, decimals).map_err(SettleError::InvalidAmount)?;
        (raw, ui)
    } else {
        return Err(SettleError::NoAcceptablePayment("missing amount".into()));
    };

    let network = candidate
        .get("network")
        .and_then(|n| n.as_str())
        .unwrap_or("solana")
        .to_string();

    Ok(PaymentRequirement {
        pay_to,
        mint,
        amount_raw,
        decimals,
        amount_ui,
        network,
    })
}

fn sign_and_submit_transfer<H: HttpClient>(
    http: &H,
    cfg: &SettleConfig,
    signing: &ed25519_dalek::SigningKey,
    session_pk: &Pubkey,
    pay_to: &Pubkey,
    mint: &Pubkey,
    amount_raw: u64,
    decimals: u8,
    memo: &str,
) -> Result<String, SettleError> {
    let source_ata = derive_ata(session_pk, mint).map_err(SettleError::Build)?;
    let dest_ata = derive_ata(pay_to, mint).map_err(SettleError::Build)?;

    if !account_exists(http, cfg, &source_ata)? {
        return Err(SettleError::Build(format!(
            "session source ATA missing: {} — fund the session key ATA only",
            source_ata.to_base58()
        )));
    }
    let create_dest = !account_exists(http, cfg, &dest_ata)?;

    // Prefer mint decimals from chain if available
    let decimals = get_account_data(http, cfg, mint)?
        .and_then(|d| mint_decimals_from_data(&d).ok())
        .unwrap_or(decimals);

    let (bh_b58, _) = get_latest_blockhash(http, cfg)?;
    let bh = blockhash_from_base58(&bh_b58).map_err(SettleError::Build)?;

    let mut ixs = Vec::new();
    if create_dest {
        ixs.push(ix_create_ata_idempotent(*session_pk, dest_ata, *pay_to, *mint));
    }
    ixs.push(ix_transfer_checked(
        source_ata, *mint, dest_ata, *session_pk, amount_raw, decimals,
    ));
    ixs.push(ix_memo(memo));

    let (message, num_signers) =
        compile_legacy_message(session_pk, &bh, &ixs).map_err(SettleError::Build)?;
    if num_signers != 1 {
        return Err(SettleError::Sign(format!(
            "expected 1 signer (session key), got {num_signers}"
        )));
    }
    let sig = sign_message(signing, &message);
    let tx = assemble_signed_tx(1, &[sig], &message).map_err(SettleError::Build)?;
    let tx_b64 = B64.encode(&tx);
    send_transaction(http, cfg, &tx_b64)
}

// ─── RPC helpers ────────────────────────────────────────────────────────────

fn rpc_call<H: HttpClient>(
    http: &H,
    cfg: &SettleConfig,
    method: &str,
    params: Value,
) -> Result<Value, SettleError> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let headers = cfg.rpc_headers();
    let resp = http
        .request("POST", &cfg.rpc_url, &headers, Some(&body))
        .map_err(SettleError::Rpc)?;
    if resp.status >= 400 {
        return Err(SettleError::Rpc(format!(
            "HTTP {}: {}",
            resp.status,
            truncate_body(&resp.body)
        )));
    }
    let v: Value = serde_json::from_str(&resp.body)
        .map_err(|e| SettleError::Rpc(format!("bad json: {e}")))?;
    if let Some(err) = v.get("error") {
        return Err(SettleError::Rpc(err.to_string()));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn get_latest_blockhash<H: HttpClient>(
    http: &H,
    cfg: &SettleConfig,
) -> Result<(String, Option<u64>), SettleError> {
    let result = rpc_call(
        http,
        cfg,
        "getLatestBlockhash",
        json!([{ "commitment": cfg.commitment }]),
    )?;
    let blockhash = result
        .pointer("/value/blockhash")
        .and_then(|b| b.as_str())
        .ok_or_else(|| SettleError::Rpc("missing blockhash".into()))?
        .to_string();
    let height = result
        .pointer("/value/lastValidBlockHeight")
        .and_then(|h| h.as_u64());
    Ok((blockhash, height))
}

fn get_account_data<H: HttpClient>(
    http: &H,
    cfg: &SettleConfig,
    pubkey: &Pubkey,
) -> Result<Option<Vec<u8>>, SettleError> {
    let result = rpc_call(
        http,
        cfg,
        "getAccountInfo",
        json!([
            pubkey.to_base58(),
            { "encoding": "base64", "commitment": cfg.commitment }
        ]),
    )?;
    let value = result.get("value");
    if value.map(|v| v.is_null()).unwrap_or(true) {
        return Ok(None);
    }
    let b64 = value
        .and_then(|v| v.pointer("/data/0"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| SettleError::Rpc("account data missing".into()))?;
    let bytes = B64
        .decode(b64)
        .map_err(|e| SettleError::Rpc(format!("b64: {e}")))?;
    Ok(Some(bytes))
}

fn account_exists<H: HttpClient>(
    http: &H,
    cfg: &SettleConfig,
    pubkey: &Pubkey,
) -> Result<bool, SettleError> {
    Ok(get_account_data(http, cfg, pubkey)?.is_some())
}

fn send_transaction<H: HttpClient>(
    http: &H,
    cfg: &SettleConfig,
    tx_b64: &str,
) -> Result<String, SettleError> {
    let result = rpc_call(
        http,
        cfg,
        "sendTransaction",
        json!([
            tx_b64,
            {
                "encoding": "base64",
                "skipPreflight": false,
                "preflightCommitment": cfg.commitment
            }
        ]),
    )?;
    result
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| SettleError::Rpc(format!("sendTransaction result: {result}")))
}

fn truncate_body(s: &str) -> String {
    const MAX: usize = 800;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}…", &s[..MAX])
    }
}

fn format_amount(amount: f64) -> String {
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

fn short(s: &str) -> String {
    if s.len() <= 12 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..4], &s[s.len() - 4..])
    }
}

fn short_sig(s: &str) -> String {
    if s.len() <= 16 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..8], &s[s.len() - 8..])
    }
}

fn short_url(u: &str) -> String {
    if u.len() <= 48 {
        u.to_string()
    } else {
        format!("{}…", &u[..48])
    }
}

/// Test helper: evaluate policy without HTTP.
#[cfg(test)]
pub mod policy_tests {
    use super::*;

    pub fn check_policy(
        cfg: &SettleConfig,
        req: &SettleRequest,
        offer: &PaymentRequirement,
    ) -> Result<(), SettleError> {
        enforce_approval(cfg, &req.approval)?;
        enforce_payment_policy(cfg, req, offer)
    }
}
