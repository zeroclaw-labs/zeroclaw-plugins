//! Pure payment-watch core. No wit-bindgen or wasm dependency.
//!
//! Custody tier: **T0 Read** — RPC reads only. Never holds keys, never signs,
//! never submits. Pair with `solana-pay-request` (T1) to close the invoice loop.
//!
//! HTTP is injected via [`HttpPost`] so host tests mock the network.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde_json::{json, Value};

/// Base58 alphabet used by Solana (Bitcoin-style, no 0/O/I/l).
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Default public mainnet RPC (operators should set their own).
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Hard cap on how many signatures we scan (context + rate-limit safety).
pub const MAX_SIGNATURES_SCAN: usize = 25;

/// Operator policy from the plugin's own config section.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub rpc_url: String,
    /// Optional API key header value (e.g. Helius / Triton). Never logged.
    pub rpc_api_key: Option<String>,
    /// Header name for the API key (default `Authorization` with Bearer, or custom).
    pub rpc_api_key_header: String,
    /// Whether to prefix api key with `Bearer `.
    pub rpc_api_key_bearer: bool,
    pub commitment: String,
    /// Max signatures to fetch per poll (clamped to [`MAX_SIGNATURES_SCAN`]).
    pub max_signatures: usize,
}

impl WatchConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Self {
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
        let max_signatures = section
            .get("max_signatures")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(15)
            .clamp(1, MAX_SIGNATURES_SCAN);
        Self {
            rpc_url,
            rpc_api_key,
            rpc_api_key_header,
            rpc_api_key_bearer,
            commitment,
            max_signatures,
        }
    }

    /// Extra headers for the RPC POST (api key only — never put secrets in the body).
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

/// What the agent asked us to watch for.
#[derive(Debug, Clone)]
pub struct WatchQuery {
    /// Recipient wallet expected to receive funds (base58). Recommended.
    pub recipient: Option<String>,
    /// Solana Pay reference pubkey — preferred matching key (account on the tx).
    pub reference: Option<String>,
    /// Expected decimal amount in UI units.
    pub expected_amount: Option<f64>,
    /// SPL mint; omit for native SOL.
    pub mint: Option<String>,
    /// Optional memo substring that must appear in the tx.
    pub memo_contains: Option<String>,
    /// Skip signatures older than this (exclusive).
    pub until_signature: Option<String>,
    /// Relative amount tolerance (default 0.0 = exact after decimal compare).
    pub amount_tolerance: f64,
}

/// Outcome of one poll.
#[derive(Debug, Clone, PartialEq)]
pub enum WatchStatus {
    /// Matching payment found.
    Paid(PaymentHit),
    /// No matching tx yet.
    Pending { scanned: usize, watched: String },
    /// Found candidate txs but none met amount/memo filters.
    NoMatch { scanned: usize, candidates: usize },
}

#[derive(Debug, Clone, PartialEq)]
pub struct PaymentHit {
    pub signature: String,
    pub amount: Option<f64>,
    pub mint: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub memo: Option<String>,
    pub slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WatchReport {
    pub status: WatchStatus,
    pub summary: String,
    pub custody_tier: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchError {
    MissingWatchTarget,
    InvalidAddress(String),
    InvalidAmount(String),
    SecretsNotAccepted,
    Rpc(String),
    BadRpcResponse(String),
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchError::MissingWatchTarget => write!(
                f,
                "provide at least one of recipient or reference to watch"
            ),
            WatchError::InvalidAddress(a) => {
                write!(f, "not a valid base58 Solana address: {a}")
            }
            WatchError::InvalidAmount(a) => write!(f, "invalid expected_amount: {a}"),
            WatchError::SecretsNotAccepted => write!(
                f,
                "this tool never accepts private keys or seed phrases — custody tier T0 (read only)"
            ),
            WatchError::Rpc(e) => write!(f, "rpc error: {e}"),
            WatchError::BadRpcResponse(e) => write!(f, "bad rpc response: {e}"),
        }
    }
}

/// Minimal HTTP port — implemented with `waki` in the wasm shim, mocked in tests.
pub trait HttpPost {
    fn post_json(
        &self,
        url: &str,
        body: &str,
        headers: &[(String, String)],
    ) -> Result<String, String>;
}

/// Poll Solana for a payment matching `query` under `cfg`.
pub fn watch_payment<H: HttpPost>(
    http: &H,
    cfg: &WatchConfig,
    query: &WatchQuery,
) -> Result<WatchReport, WatchError> {
    validate_query(query)?;

    let watch_key = query
        .reference
        .as_deref()
        .or(query.recipient.as_deref())
        .expect("validated");

    let sigs = get_signatures_for_address(
        http,
        cfg,
        watch_key,
        cfg.max_signatures,
        query.until_signature.as_deref(),
    )?;

    if sigs.is_empty() {
        let status = WatchStatus::Pending {
            scanned: 0,
            watched: short_addr(watch_key),
        };
        return Ok(WatchReport {
            summary: format_summary(&status),
            status,
            custody_tier: "T0",
        });
    }

    let mut candidates = 0usize;
    for sig in &sigs {
        let tx = match get_transaction(http, cfg, sig) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(_) => continue, // skip unfetchable; keep scanning
        };
        candidates += 1;
        if let Some(hit) = match_transaction(&tx, sig, query) {
            let status = WatchStatus::Paid(hit);
            return Ok(WatchReport {
                summary: format_summary(&status),
                status,
                custody_tier: "T0",
            });
        }
    }

    let status = if candidates == 0 {
        WatchStatus::Pending {
            scanned: sigs.len(),
            watched: short_addr(watch_key),
        }
    } else {
        WatchStatus::NoMatch {
            scanned: sigs.len(),
            candidates,
        }
    };
    Ok(WatchReport {
        summary: format_summary(&status),
        status,
        custody_tier: "T0",
    })
}

fn validate_query(query: &WatchQuery) -> Result<(), WatchError> {
    let fields = [
        query.recipient.as_deref().unwrap_or(""),
        query.reference.as_deref().unwrap_or(""),
        query.memo_contains.as_deref().unwrap_or(""),
    ];
    for f in fields {
        if looks_like_secret(f) {
            return Err(WatchError::SecretsNotAccepted);
        }
    }

    let has_recipient = query
        .recipient
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some();
    let has_reference = query
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some();
    if !has_recipient && !has_reference {
        return Err(WatchError::MissingWatchTarget);
    }
    if let Some(r) = query.recipient.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !is_solana_address(r) {
            return Err(WatchError::InvalidAddress(r.to_string()));
        }
    }
    if let Some(r) = query.reference.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !is_solana_address(r) {
            return Err(WatchError::InvalidAddress(r.to_string()));
        }
    }
    if let Some(m) = query.mint.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if !is_solana_address(m) {
            return Err(WatchError::InvalidAddress(m.to_string()));
        }
    }
    if let Some(a) = query.expected_amount {
        if !a.is_finite() || a <= 0.0 {
            return Err(WatchError::InvalidAmount(a.to_string()));
        }
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
    if (words.len() == 12 || words.len() == 24)
        && words
            .iter()
            .all(|w| w.len() >= 3 && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase()))
    {
        return true;
    }
    false
}

// ─── JSON-RPC helpers ───────────────────────────────────────────────────────

fn rpc_call<H: HttpPost>(
    http: &H,
    cfg: &WatchConfig,
    method: &str,
    params: Value,
) -> Result<Value, WatchError> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let headers = cfg.rpc_headers();
    let raw = http
        .post_json(&cfg.rpc_url, &body, &headers)
        .map_err(WatchError::Rpc)?;
    let v: Value =
        serde_json::from_str(&raw).map_err(|e| WatchError::BadRpcResponse(e.to_string()))?;
    if let Some(err) = v.get("error") {
        return Err(WatchError::Rpc(err.to_string()));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn get_signatures_for_address<H: HttpPost>(
    http: &H,
    cfg: &WatchConfig,
    address: &str,
    limit: usize,
    until: Option<&str>,
) -> Result<Vec<String>, WatchError> {
    let mut opts = json!({
        "limit": limit,
        "commitment": cfg.commitment,
    });
    if let Some(u) = until {
        opts["until"] = json!(u);
    }
    let result = rpc_call(http, cfg, "getSignaturesForAddress", json!([address, opts]))?;
    let arr = result
        .as_array()
        .ok_or_else(|| WatchError::BadRpcResponse("expected signature array".into()))?;
    let mut out = Vec::new();
    for item in arr {
        if let Some(sig) = item.get("signature").and_then(|s| s.as_str()) {
            // Skip failed txs when err is present and non-null
            let failed = item.get("err").map(|e| !e.is_null()).unwrap_or(false);
            if !failed {
                out.push(sig.to_string());
            }
        }
    }
    Ok(out)
}

fn get_transaction<H: HttpPost>(
    http: &H,
    cfg: &WatchConfig,
    signature: &str,
) -> Result<Option<Value>, WatchError> {
    let result = rpc_call(
        http,
        cfg,
        "getTransaction",
        json!([
            signature,
            {
                "encoding": "jsonParsed",
                "commitment": cfg.commitment,
                "maxSupportedTransactionVersion": 0
            }
        ]),
    )?;
    if result.is_null() {
        return Ok(None);
    }
    Ok(Some(result))
}

// ─── Match logic ────────────────────────────────────────────────────────────

fn match_transaction(tx: &Value, signature: &str, query: &WatchQuery) -> Option<PaymentHit> {
    // Reference must appear as an account key when provided.
    if let Some(reference) = query
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !tx_mentions_account(tx, reference) {
            return None;
        }
    }

    let memo = extract_memo(tx);
    if let Some(want) = query
        .memo_contains
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match &memo {
            Some(m) if m.contains(want) => {}
            _ => return None,
        }
    }

    let mint = query
        .mint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let recipient = query
        .recipient
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let (amount, from, to) = if let Some(m) = mint {
        extract_spl_transfer(tx, m, recipient)?
    } else if recipient.is_some() || query.expected_amount.is_some() {
        // Native SOL path when mint omitted
        extract_sol_transfer(tx, recipient)?
    } else {
        // Reference-only watch without amount: any successful tx mentioning ref
        (None, None, recipient.map(|s| s.to_string()))
    };

    if let Some(expected) = query.expected_amount {
        let got = amount?;
        let tol = query.amount_tolerance.max(0.0);
        if (got - expected).abs() > tol + f64::EPSILON {
            return None;
        }
    }

    // If recipient was specified, ensure transfer `to` matches when we have it
    if let (Some(r), Some(t)) = (recipient, to.as_deref()) {
        if r != t {
            return None;
        }
    }

    let slot = tx.get("slot").and_then(|s| s.as_u64());
    Some(PaymentHit {
        signature: signature.to_string(),
        amount,
        mint: mint.map(|s| s.to_string()),
        from,
        to,
        memo,
        slot,
    })
}

fn tx_mentions_account(tx: &Value, address: &str) -> bool {
    let keys = account_keys(tx);
    keys.iter().any(|k| k == address)
}

fn account_keys(tx: &Value) -> Vec<String> {
    let mut keys = Vec::new();
    let message = tx
        .pointer("/transaction/message")
        .cloned()
        .unwrap_or(Value::Null);

    // jsonParsed: accountKeys is array of strings or {pubkey, signer, writable}
    if let Some(arr) = message.get("accountKeys").and_then(|a| a.as_array()) {
        for k in arr {
            if let Some(s) = k.as_str() {
                keys.push(s.to_string());
            } else if let Some(s) = k.get("pubkey").and_then(|p| p.as_str()) {
                keys.push(s.to_string());
            }
        }
    }
    keys
}

fn extract_memo(tx: &Value) -> Option<String> {
    // Parsed instructions
    let message = tx.pointer("/transaction/message")?;
    if let Some(ixs) = message.get("instructions").and_then(|a| a.as_array()) {
        for ix in ixs {
            let program = ix
                .get("program")
                .and_then(|p| p.as_str())
                .or_else(|| ix.get("programId").and_then(|p| p.as_str()))
                .unwrap_or("");
            if program == "spl-memo" || program.contains("Memo") {
                if let Some(parsed) = ix.pointer("/parsed") {
                    if let Some(s) = parsed.as_str() {
                        return Some(s.to_string());
                    }
                    if let Some(s) = parsed.get("memo").or_else(|| parsed.get("message")).and_then(|m| m.as_str())
                    {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    // Inner instructions
    if let Some(inner) = tx.pointer("/meta/innerInstructions").and_then(|a| a.as_array()) {
        for group in inner {
            if let Some(ixs) = group.get("instructions").and_then(|a| a.as_array()) {
                for ix in ixs {
                    let program = ix
                        .get("program")
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    if program == "spl-memo" {
                        if let Some(s) = ix.pointer("/parsed").and_then(|p| p.as_str()) {
                            return Some(s.to_string());
                        }
                    }
                }
            }
        }
    }
    // Log messages: "Program log: Memo (len …): \"…\""
    if let Some(logs) = tx.pointer("/meta/logMessages").and_then(|a| a.as_array()) {
        for log in logs {
            if let Some(s) = log.as_str() {
                if let Some(memo) = parse_memo_log(s) {
                    return Some(memo);
                }
            }
        }
    }
    None
}

fn parse_memo_log(log: &str) -> Option<String> {
    // Common forms:
    // Program log: Memo (len 11): "Invoice #1"
    // Program log: Memo: Invoice #1
    if let Some(idx) = log.find("Memo") {
        let rest = &log[idx..];
        if let Some(start) = rest.find('"') {
            let after = &rest[start + 1..];
            if let Some(end) = after.find('"') {
                return Some(after[..end].to_string());
            }
        }
        if let Some(pos) = rest.find(": ") {
            let m = rest[pos + 2..].trim();
            if !m.is_empty() && !m.starts_with('(') {
                return Some(m.to_string());
            }
        }
    }
    None
}

/// Extract SPL token transfer amount (UI units) involving optional recipient owner.
fn extract_spl_transfer(
    tx: &Value,
    mint: &str,
    recipient: Option<&str>,
) -> Option<(Option<f64>, Option<String>, Option<String>)> {
    // Prefer parsed transfer instructions
    if let Some(hit) = extract_spl_from_instructions(tx, mint, recipient) {
        return Some(hit);
    }
    // Fallback: token balance deltas
    extract_spl_from_balances(tx, mint, recipient)
}

fn extract_spl_from_instructions(
    tx: &Value,
    mint: &str,
    recipient: Option<&str>,
) -> Option<(Option<f64>, Option<String>, Option<String>)> {
    let message = tx.pointer("/transaction/message")?;
    let ixs = message.get("instructions")?.as_array()?;
    for ix in ixs {
        let program = ix.get("program").and_then(|p| p.as_str()).unwrap_or("");
        if program != "spl-token" && program != "spl-token-2022" {
            continue;
        }
        let parsed = ix.get("parsed")?;
        let type_ = parsed.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if type_ != "transfer" && type_ != "transferChecked" {
            continue;
        }
        let info = parsed.get("info")?;
        let dest_owner = info
            .get("destination")
            .and_then(|d| d.as_str())
            // transferChecked sometimes uses authority/destination differently
            .or_else(|| info.get("destinationOwner").and_then(|d| d.as_str()));
        // For transfer, destination is token account; owner may be in postTokenBalances
        let token_amount = info
            .pointer("/tokenAmount/uiAmount")
            .and_then(|a| a.as_f64())
            .or_else(|| {
                info.get("amount")
                    .and_then(|a| a.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|raw| {
                        // without decimals treat as raw — prefer uiAmount
                        raw
                    })
            })
            .or_else(|| info.get("uiAmount").and_then(|a| a.as_f64()));

        let ix_mint = info.get("mint").and_then(|m| m.as_str());
        if let Some(im) = ix_mint {
            if im != mint {
                continue;
            }
        }

        // If we only have destination ATA, resolve owner via postTokenBalances
        let to_owner = resolve_token_account_owner(tx, dest_owner.unwrap_or(""))
            .or_else(|| dest_owner.map(|s| s.to_string()));

        if let Some(r) = recipient {
            if let Some(ref owner) = to_owner {
                if owner != r && dest_owner != Some(r) {
                    continue;
                }
            }
        }

        let from = info
            .get("authority")
            .or_else(|| info.get("source"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());

        // Prefer balance-based UI amount when instruction amount is raw
        let amount = token_amount.or_else(|| {
            extract_spl_from_balances(tx, mint, recipient).and_then(|(a, _, _)| a)
        });

        return Some((amount, from, to_owner.or_else(|| recipient.map(|s| s.to_string()))));
    }
    None
}

fn resolve_token_account_owner(tx: &Value, token_account: &str) -> Option<String> {
    if token_account.is_empty() {
        return None;
    }
    let balances = tx.pointer("/meta/postTokenBalances")?.as_array()?;
    for b in balances {
        if b.get("accountIndex").is_some() {
            // Match by owner field when pubkey equals — actually we need account keys
            let keys = account_keys(tx);
            if let Some(idx) = b.get("accountIndex").and_then(|i| i.as_u64()) {
                if keys.get(idx as usize).map(|s| s.as_str()) == Some(token_account) {
                    return b
                        .get("owner")
                        .and_then(|o| o.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }
    // Also: if token_account is already an owner in balances
    for b in balances {
        if b.get("owner").and_then(|o| o.as_str()) == Some(token_account) {
            return Some(token_account.to_string());
        }
    }
    None
}

fn extract_spl_from_balances(
    tx: &Value,
    mint: &str,
    recipient: Option<&str>,
) -> Option<(Option<f64>, Option<String>, Option<String>)> {
    let pre = tx.pointer("/meta/preTokenBalances")?.as_array()?;
    let post = tx.pointer("/meta/postTokenBalances")?.as_array()?;

    // Build map (owner, mint) -> uiAmount
    let pre_map = token_balance_map(pre, mint);
    let post_map = token_balance_map(post, mint);

    // Find owner whose balance increased
    for (owner, post_amt) in &post_map {
        if let Some(r) = recipient {
            if owner != r {
                continue;
            }
        }
        let pre_amt = pre_map.get(owner).copied().unwrap_or(0.0);
        let delta = post_amt - pre_amt;
        if delta > 0.0 {
            // Find a decreased owner as from
            let from = pre_map
                .iter()
                .find(|(o, pre_a)| {
                    let post_a = post_map.get(*o).copied().unwrap_or(0.0);
                    *pre_a - post_a > 0.0 && *o != owner
                })
                .map(|(o, _)| o.clone());
            return Some((Some(delta), from, Some(owner.clone())));
        }
    }
    None
}

fn token_balance_map(balances: &[Value], mint: &str) -> HashMap<String, f64> {
    let mut map = HashMap::new();
    for b in balances {
        let m = b.get("mint").and_then(|x| x.as_str()).unwrap_or("");
        if m != mint {
            continue;
        }
        let owner = match b.get("owner").and_then(|o| o.as_str()) {
            Some(o) => o.to_string(),
            None => continue,
        };
        let amt = b
            .pointer("/uiTokenAmount/uiAmount")
            .and_then(|a| a.as_f64())
            .unwrap_or(0.0);
        *map.entry(owner).or_insert(0.0) += amt;
    }
    map
}

fn extract_sol_transfer(
    tx: &Value,
    recipient: Option<&str>,
) -> Option<(Option<f64>, Option<String>, Option<String>)> {
    let keys = account_keys(tx);
    let pre = tx.pointer("/meta/preBalances")?.as_array()?;
    let post = tx.pointer("/meta/postBalances")?.as_array()?;
    if pre.len() != post.len() || pre.len() != keys.len() {
        // still try min length
    }
    let n = pre.len().min(post.len()).min(keys.len());
    let mut best: Option<(f64, String, Option<String>)> = None;
    for i in 0..n {
        let pre_lamports = pre[i].as_u64()?;
        let post_lamports = post[i].as_u64()?;
        if post_lamports <= pre_lamports {
            continue;
        }
        let delta = (post_lamports - pre_lamports) as f64 / 1_000_000_000.0;
        let owner = keys[i].clone();
        if let Some(r) = recipient {
            if owner != r {
                continue;
            }
        }
        // Find largest decrease as from
        let mut from = None;
        let mut max_dec = 0u64;
        for j in 0..n {
            let dec = pre[j].as_u64().unwrap_or(0).saturating_sub(post[j].as_u64().unwrap_or(0));
            if dec > max_dec {
                max_dec = dec;
                from = Some(keys[j].clone());
            }
        }
        if best.as_ref().map(|(d, _, _)| delta > *d).unwrap_or(true) {
            best = Some((delta, owner, from));
        }
    }
    best.map(|(amt, to, from)| (Some(amt), from, Some(to)))
}

// ─── Output shaping ─────────────────────────────────────────────────────────

fn format_summary(status: &WatchStatus) -> String {
    match status {
        WatchStatus::Paid(hit) => {
            let mut s = String::new();
            let _ = write!(s, "Invoice paid (T0 read-only). ");
            if let Some(a) = hit.amount {
                let asset = hit
                    .mint
                    .as_ref()
                    .map(|m| format!("mint {}", short_addr(m)))
                    .unwrap_or_else(|| "SOL".to_string());
                let _ = write!(s, "Received {} {}. ", format_amount(a), asset);
            }
            if let Some(from) = &hit.from {
                let _ = write!(s, "From {}. ", short_addr(from));
            }
            if let Some(memo) = &hit.memo {
                let _ = write!(s, "Memo: {memo}. ");
            }
            let _ = write!(s, "Sig: {}. No keys held.", short_sig(&hit.signature));
            s
        }
        WatchStatus::Pending { scanned, watched } => {
            format!(
                "Payment not seen yet (T0). Watched {watched}, scanned {scanned} signature(s). Poll again later."
            )
        }
        WatchStatus::NoMatch {
            scanned,
            candidates,
        } => format!(
            "No matching payment (T0). Scanned {scanned} signature(s), {candidates} candidate tx(s) failed amount/memo filters."
        ),
    }
}

fn short_sig(sig: &str) -> String {
    if sig.len() <= 16 {
        return sig.to_string();
    }
    format!("{}…{}", &sig[..8], &sig[sig.len() - 8..])
}

/// Compact JSON-ish fields for the tool output (kept short for the model).
pub fn report_to_json(report: &WatchReport) -> String {
    let mut obj = json!({
        "custody_tier": report.custody_tier,
        "summary": report.summary,
    });
    match &report.status {
        WatchStatus::Paid(hit) => {
            obj["status"] = json!("paid");
            obj["signature"] = json!(hit.signature);
            if let Some(a) = hit.amount {
                obj["amount"] = json!(a);
            }
            if let Some(m) = &hit.mint {
                obj["mint"] = json!(m);
            }
            if let Some(f) = &hit.from {
                obj["from"] = json!(f);
            }
            if let Some(t) = &hit.to {
                obj["to"] = json!(t);
            }
            if let Some(m) = &hit.memo {
                obj["memo"] = json!(m);
            }
            if let Some(slot) = hit.slot {
                obj["slot"] = json!(slot);
            }
        }
        WatchStatus::Pending { scanned, watched } => {
            obj["status"] = json!("pending");
            obj["scanned"] = json!(scanned);
            obj["watched"] = json!(watched);
        }
        WatchStatus::NoMatch {
            scanned,
            candidates,
        } => {
            obj["status"] = json!("no_match");
            obj["scanned"] = json!(scanned);
            obj["candidates"] = json!(candidates);
        }
    }
    obj.to_string()
}

pub fn format_amount(amount: f64) -> String {
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

pub fn short_addr(s: &str) -> String {
    if s.len() <= 12 {
        return s.to_string();
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

pub fn is_solana_address(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 32 || s.len() > 44 {
        return false;
    }
    s.bytes().all(|b| BASE58_ALPHABET.contains(&b))
}


