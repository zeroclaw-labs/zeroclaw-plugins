//! Pure logic for the `sol-token-balances` tool.
//!
//! Everything here — resolving config, validating a base58 pubkey, building the
//! JSON-RPC request, parsing the `getTokenAccountsByOwner` response, building
//! and parsing the Jupiter price request, and formatting the result — has no
//! wit-bindgen or wasm dependency, so it compiles and tests on the host with a
//! plain `cargo test`. The wasm component reuses the exact same functions
//! through `lib.rs`, keeping the component glue too thin to be wrong.

use std::collections::HashMap;

use serde_json::Value;

/// Public Solana mainnet-beta JSON-RPC endpoint, used when the operator has not
/// configured an override.
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Base URL of Jupiter's free (no-API-key) "lite" price service. The full price
/// endpoint is `{base}/price/v3`. Verified current as of 2026-07: the older
/// `price.jup.ag/v4|v6` hosts are retired and `api.jup.ag` now requires an
/// `x-api-key`, while `lite-api.jup.ag` stays key-free (rate limited).
pub const DEFAULT_JUPITER_BASE_URL: &str = "https://lite-api.jup.ag";

/// The classic SPL Token program id. `getTokenAccountsByOwner` is scoped to it
/// so the tool reports standard SPL token balances.
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Jupiter's price API accepts up to 50 comma-separated mint ids per call, so
/// mints are queried in batches of this size.
pub const PRICE_BATCH_SIZE: usize = 50;

/// Runtime configuration resolved from the plugin's own jailed config section.
pub struct TokenConfig {
    /// JSON-RPC endpoint the tool POSTs to.
    pub rpc_url: String,
    /// Base URL for Jupiter's price service (`{base}/price/v3`).
    pub jupiter_base_url: String,
}

impl TokenConfig {
    /// Build from the flat `string -> string` section the host injects. Absent,
    /// empty, or whitespace-only values fall back to the public defaults, which
    /// is also exactly what an unprivileged plugin (no `config_read` permission)
    /// sees.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let pick = |key: &str, default: &str| -> String {
            section
                .get(key)
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| default.to_string())
        };
        Self {
            rpc_url: pick("rpc_url", DEFAULT_RPC_URL),
            jupiter_base_url: pick("jupiter_base_url", DEFAULT_JUPITER_BASE_URL),
        }
    }
}

/// One SPL token balance held by the queried owner.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenBalance {
    /// The token's mint address (base58).
    pub mint: String,
    /// The token account (associated or otherwise) that holds the balance.
    pub account: String,
    /// Human-readable ("ui") amount = raw / 10^decimals.
    pub amount: f64,
    /// Mint decimals.
    pub decimals: u64,
    /// Exact raw balance in base units, as a decimal string (never lossy).
    pub raw: String,
}

/// Validate a base58-encoded Solana public key: it must decode cleanly to
/// exactly 32 bytes. Returns the trimmed, normalized address on success and a
/// human-readable reason on failure.
pub fn validate_pubkey(address: &str) -> Result<String, String> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err("address is empty".to_string());
    }
    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|e| format!("address is not valid base58: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "address must decode to 32 bytes, got {}",
            decoded.len()
        ));
    }
    Ok(trimmed.to_string())
}

/// Build the JSON-RPC 2.0 request body for `getTokenAccountsByOwner` against
/// `owner`, scoped to the SPL Token program and using `jsonParsed` encoding so
/// the mint and amount come back already decoded. The caller is expected to
/// have validated `owner` already.
pub fn build_request_body(owner: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            owner,
            { "programId": TOKEN_PROGRAM_ID },
            { "encoding": "jsonParsed" },
        ],
    })
    .to_string()
}

/// Parse a `getTokenAccountsByOwner` (`jsonParsed`) response into a list of
/// non-zero token balances. Accounts whose raw balance is zero are skipped. A
/// JSON-RPC `error.message` is surfaced as `Err`.
pub fn parse_token_accounts(body: &str) -> Result<Vec<TokenBalance>, String> {
    let v: Value =
        serde_json::from_str(body).map_err(|e| format!("RPC response is not valid JSON: {e}"))?;

    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown RPC error");
        return Err(format!("RPC error: {msg}"));
    }

    let accounts = v
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(Value::as_array)
        .ok_or_else(|| "RPC response missing result.value array".to_string())?;

    let mut out = Vec::new();
    for entry in accounts {
        let account = entry
            .get("pubkey")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let info = match entry.pointer("/account/data/parsed/info") {
            Some(i) => i,
            None => continue, // not a jsonParsed spl-token account; skip defensively
        };

        let mint = match info.get("mint").and_then(Value::as_str) {
            Some(m) => m.to_string(),
            None => continue,
        };

        let token_amount = info.get("tokenAmount");
        let raw = token_amount
            .and_then(|t| t.get("amount"))
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_string();

        // Skip zero balances — the whole point of the tool is the holdings that
        // matter, and closed/empty accounts are noise.
        if raw.chars().all(|c| c == '0') {
            continue;
        }

        let decimals = token_amount
            .and_then(|t| t.get("decimals"))
            .and_then(Value::as_u64)
            .unwrap_or(0);

        // Prefer the RPC's own uiAmount; fall back to uiAmountString, then to a
        // computed value, so a null uiAmount never drops a real balance.
        let amount = token_amount
            .and_then(|t| t.get("uiAmount"))
            .and_then(Value::as_f64)
            .or_else(|| {
                token_amount
                    .and_then(|t| t.get("uiAmountString"))
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<f64>().ok())
            })
            .unwrap_or_else(|| ui_from_raw(&raw, decimals));

        out.push(TokenBalance {
            mint,
            account,
            amount,
            decimals,
            raw,
        });
    }
    Ok(out)
}

/// Compute a human-readable amount from a raw base-unit string and decimals.
/// Display convenience only; `raw` remains the exact value.
pub fn ui_from_raw(raw: &str, decimals: u64) -> f64 {
    let raw_f: f64 = raw.parse().unwrap_or(0.0);
    raw_f / 10f64.powi(decimals as i32)
}

/// Split a de-duplicated mint list into Jupiter-price-sized batches (<= 50).
pub fn mint_batches(mints: &[String]) -> Vec<Vec<String>> {
    mints.chunks(PRICE_BATCH_SIZE).map(|c| c.to_vec()).collect()
}

/// Collect the distinct mints from a set of balances, preserving first-seen
/// order (so batching is deterministic and testable).
pub fn distinct_mints(tokens: &[TokenBalance]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for t in tokens {
        if seen.insert(t.mint.clone()) {
            out.push(t.mint.clone());
        }
    }
    out
}

/// Build the Jupiter price URL for one batch of mints:
/// `{base}/price/v3?ids=mint1,mint2,...`.
pub fn build_price_url(base_url: &str, mints: &[String]) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/price/v3?ids={}", mints.join(","))
}

/// Parse a Jupiter `price/v3` response into a `mint -> usdPrice` map. Mints
/// without a reliable price are simply absent from Jupiter's response (and so
/// from this map). A malformed body is an error.
pub fn parse_price_response(body: &str) -> Result<HashMap<String, f64>, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("Jupiter price response is not valid JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "Jupiter price response is not a JSON object".to_string())?;

    let mut out = HashMap::new();
    for (mint, entry) in obj {
        if let Some(price) = entry.get("usdPrice").and_then(Value::as_f64) {
            out.insert(mint.clone(), price);
        }
    }
    Ok(out)
}

/// Format a successful lookup as a compact JSON object string — the `output`
/// the tool hands back to the model.
///
/// When `prices` is `Some`, each token is enriched with `usd_price` and
/// `usd_value` (present only for mints Jupiter priced), plus a portfolio
/// `total_usd` and the count of priced tokens. When `None`, USD enrichment was
/// not requested and those fields are omitted.
pub fn format_output(
    address: &str,
    rpc_url: &str,
    tokens: &[TokenBalance],
    prices: Option<&HashMap<String, f64>>,
) -> String {
    let mut total_usd = 0.0f64;
    let mut priced_count = 0usize;

    let token_json: Vec<Value> = tokens
        .iter()
        .map(|t| {
            let mut obj = serde_json::json!({
                "mint": t.mint,
                "account": t.account,
                "amount": t.amount,
                "decimals": t.decimals,
                "raw": t.raw,
            });
            if let Some(map) = prices {
                if let Some(price) = map.get(&t.mint) {
                    let value = t.amount * price;
                    total_usd += value;
                    priced_count += 1;
                    obj["usd_price"] = serde_json::json!(price);
                    obj["usd_value"] = serde_json::json!(value);
                }
            }
            obj
        })
        .collect();

    let mut out = serde_json::json!({
        "address": address,
        "rpc_url": rpc_url,
        "token_count": tokens.len(),
        "tokens": token_json,
    });

    if prices.is_some() {
        out["usd_enabled"] = serde_json::json!(true);
        out["total_usd"] = serde_json::json!(total_usd);
        out["priced_token_count"] = serde_json::json!(priced_count);
    }

    out.to_string()
}
