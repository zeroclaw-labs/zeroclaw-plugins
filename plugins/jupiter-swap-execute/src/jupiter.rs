//! Pure Jupiter swap core. No wit-bindgen or wasm dependency so it compiles
//! and tests on the host with `cargo test`.
//!
//! Jupiter API (public.jupiterapi.com — QuickNode hosted, no CloudFront):
//!   - GET  /quote → swap quote (V6 format)
//!   - POST /swap  → assembled unsigned transaction
//!
//! Jupiter Price API V3: https://api.jup.ag/price/v3
//!   - GET ?ids={mints} → USD prices + 24h change
//!
//! Keyless access: public.jupiterapi.com has no rate limits.
//! Production: api.jup.ag with x-api-key header.
//!
//! IMPORTANT: Use `asLegacyTransaction: true` in swap POST body to avoid
//! address lookup tables. OutLayer TEE signs the serialized message bytes,
//! and V0 transactions with ALTs have a compiled-message hash mismatch that
//! causes SignatureFailure. Legacy transactions have no ALTs so the message
//! bytes == compiled message bytes and custody signing works correctly.

use std::collections::HashMap;

// ── Well-known mints ──────────────────────────────────────────────────

pub const SOL_MINT: &str = "So11111111111111111111111111111111111111112"; // 43 chars: wrapped SOL
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

// ── Config ────────────────────────────────────────────────────────────

/// Plugin config resolved from the host's jailed config section.
#[derive(Debug, Clone)]
pub struct SwapConfig {
    /// Jupiter Swap API base URL.
    /// Default: public.jupiterapi.com (QuickNode hosted, no CloudFront).
    pub swap_api: String,
    /// Jupiter Price API V3 URL.
    pub price_api: String,
    /// Optional Jupiter API key for api.jup.ag (higher rate limits).
    pub jupiter_api_key: String,
    /// OutLayer API base URL.
    pub outlayer_api: String,
    /// OutLayer API key (read from config, never hardcoded).
    pub outlayer_api_key: String,
    /// Solana RPC URL for blockhash and broadcast.
    pub solana_rpc: String,
    /// Max slippage in basis points (e.g. 50 = 0.5%).
    pub max_slippage_bps: u32,
    /// Comma-separated allowed mint addresses (empty = allow all).
    pub allowed_mints: Vec<String>,
    /// Daily spend cap in USD (0 = no cap).
    pub daily_spend_cap_usd: f64,
}

impl SwapConfig {
    /// Build from the flat `string -> string` section the host injects.
    /// Missing keys fall back to safe defaults.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let swap_api = section
            .get("swap_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://public.jupiterapi.com".to_string());
        let price_api = section
            .get("price_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://api.jup.ag/price/v3".to_string());
        let jupiter_api_key = section.get("jupiter_api_key").cloned().unwrap_or_default();
        let outlayer_api = section
            .get("outlayer_api")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://api.outlayer.fastnear.com".to_string());
        let outlayer_api_key = section.get("outlayer_api_key").cloned().unwrap_or_default();
        let max_slippage_bps = section
            .get("max_slippage_bps")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let allowed_mints = section
            .get("allowed_mints")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        let daily_spend_cap_usd = section
            .get("daily_spend_cap_usd")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500.0);
        let solana_rpc = section
            .get("solana_rpc")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());
        Self {
            swap_api,
            price_api,
            jupiter_api_key,
            outlayer_api,
            outlayer_api_key,
            solana_rpc,
            max_slippage_bps,
            allowed_mints,
            daily_spend_cap_usd,
        }
    }

    /// Whether we have a Jupiter API key (higher rate limits).
    pub fn has_jupiter_key(&self) -> bool {
        !self.jupiter_api_key.is_empty()
    }
}

// ── Request builders ──────────────────────────────────────────────────

/// Build Jupiter Price API V3 URL.
/// GET {price_api}?ids={mints}
pub fn build_price_url(cfg: &SwapConfig, mints: &[&str]) -> String {
    let ids = mints.join(",");
    format!("{}?ids={}", cfg.price_api, ids)
}

/// Build Jupiter quote URL.
/// GET {swap_api}/quote?inputMint=..&outputMint=..&amount=..&slippageBps=..&asLegacyTransaction=true
pub fn build_quote_url(
    cfg: &SwapConfig,
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: u32,
) -> String {
    let slippage = slippage_bps.min(cfg.max_slippage_bps);
    format!(
        "{}/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}&asLegacyTransaction=true",
        cfg.swap_api, input_mint, output_mint, amount, slippage
    )
}

/// Shape a Jupiter /quote response into a compact string for the LLM.
pub fn shape_quote_response(raw: &serde_json::Value) -> String {
    let in_amount = raw.get("inAmount").and_then(|v| v.as_str()).unwrap_or("?");
    let out_amount = raw.get("outAmount").and_then(|v| v.as_str()).unwrap_or("?");
    let price_impact = raw
        .get("priceImpactPct")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let swap_mode = raw
        .get("swapMode")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    format!(
        "Quote: {} in → {} out. Impact: {:.3}%. Mode: {}.",
        in_amount, out_amount, price_impact, swap_mode
    )
}

/// Build Jupiter Swap API V2 execute request body (kept for backward compat).
/// POST {swap_api}/execute — not used in custody flow but available.
#[allow(dead_code)]
pub fn build_execute_body(signed_transaction: &str, request_id: &str) -> serde_json::Value {
    serde_json::json!({
        "signedTransaction": signed_transaction,
        "requestId": request_id,
    })
}

/// Build OutLayer address derivation URL.
/// GET {outlayer_api}/wallet/v1/address?chain=solana
pub fn build_outlayer_address_url(cfg: &SwapConfig) -> String {
    format!("{}/wallet/v1/address?chain=solana", cfg.outlayer_api)
}

/// Build OutLayer balance URL.
/// GET {outlayer_api}/wallet/v1/balance?chain=solana&token={mint}
pub fn build_outlayer_balance_url(cfg: &SwapConfig, mint: &str) -> String {
    format!(
        "{}/wallet/v1/balance?chain=solana&token={}",
        cfg.outlayer_api, mint
    )
}

/// Build OutLayer Solana sign-transaction request body.
/// POST {outlayer_api}/wallet/v1/solana/sign-transaction
///
/// OutLayer signs the serialized **message** bytes (not full tx) with its
/// TEE-held ed25519 key. Returns a base58 signature.
///
/// IMPORTANT: For V0 transactions with address lookup tables, the message
/// bytes must be the compiled message (with ALT addresses expanded), not
/// the raw MessageV0 bytes. The compiled message is what validators verify.
/// To avoid this complexity, use asLegacyTransaction=true which produces
/// legacy transactions with no ALTs.
pub fn build_outlayer_solana_sign_body(unsigned_message_base64: &str) -> serde_json::Value {
    serde_json::json!({
        "chain": "solana",
        "unsigned_tx": unsigned_message_base64
    })
}

/// Shape an OutLayer Solana sign response into a compact string.
/// Response: { signature: base58, chain: "solana", wallet_id: uuid }
pub fn shape_outlayer_sign_response(raw: &serde_json::Value) -> String {
    let signature = raw.get("signature").and_then(|v| v.as_str()).unwrap_or("?");
    let wallet_id = raw.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("?");
    format!("Signed by OutLayer ({}). Sig: {}", wallet_id, signature)
}

// ── Output shaping ────────────────────────────────────────────────────

/// Shape a Jupiter Price API V3 response into a compact string for the LLM.
/// V3 format: { "mint": { "usdPrice": f64, "priceChange24h": f64, ... } }
/// Target: ~200 tokens.
pub fn shape_price_response(raw: &serde_json::Value) -> String {
    let prices = raw.as_object().filter(|m| !m.is_empty());
    if let Some(prices) = prices {
        let mut lines = Vec::new();
        for (mint, info) in prices {
            let usd_price = info.get("usdPrice").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let change_24h = info
                .get("priceChange24h")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let sign = if change_24h >= 0.0 { "+" } else { "" };
            let symbol = mint_short(mint);
            lines.push(format!(
                "{}: ${:.2} (24h: {}{:.2}%)",
                symbol, usd_price, sign, change_24h
            ));
        }
        lines.join(", ")
    } else {
        "No prices found.".to_string()
    }
}

/// Shape a Jupiter Swap API V2 order response into a compact string for the LLM.
/// V2 /order format: { requestId, outAmount, router, mode, feeBps, ... }
pub fn shape_order_response(raw: &serde_json::Value) -> String {
    let out_amount = raw.get("outAmount").and_then(|v| v.as_str()).unwrap_or("?");
    let router = raw
        .get("router")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let fee_bps = raw
        .get("feeBps")
        .and_then(|v| v.as_number())
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    let has_tx = raw
        .get("transaction")
        .and_then(|v| v.as_str())
        .map_or(false, |s| !s.is_empty() && s != "null");

    let fee_display = fee_bps as f64 / 100.0;
    let tx_status = if has_tx {
        "ready to sign"
    } else {
        "quote-only"
    };

    format!(
        "Order: {} out. Router: {}. Fee: {:.2} bps ({}). {}.",
        out_amount, router, fee_display, tx_status, tx_status
    )
}

/// Shape a Jupiter execute response into a compact string.
/// V2 /execute format: { status, signature, totalInputAmount, totalOutputAmount, ... }
pub fn shape_execute_response(raw: &serde_json::Value) -> String {
    let status = raw
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let signature = raw
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let total_in = raw
        .get("totalInputAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let total_out = raw
        .get("totalOutputAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("?");

    match status {
        "Success" => format!(
            "Swap executed. In: {} Out: {}. Tx: {}",
            total_in, total_out, signature
        ),
        _ => format!(
            "Swap {}: in {} out {}. Tx: {}",
            status.to_lowercase(),
            total_in,
            total_out,
            signature
        ),
    }
}

/// Extract the base64 transaction from a Jupiter /order response.
pub fn extract_order_transaction(order_response: &serde_json::Value) -> Result<String, String> {
    order_response
        .get("transaction")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "null")
        .map(|s| s.to_string())
        .ok_or_else(|| {
            let code = order_response
                .get("errorCode")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let msg = order_response
                .get("errorMessage")
                .and_then(|v| v.as_str())
                .unwrap_or("No transaction in response");
            format!("Order error ({}): {}", code, msg)
        })
}

/// Extract the request ID from a Jupiter /order response.
pub fn extract_request_id(order_response: &serde_json::Value) -> Result<String, String> {
    order_response
        .get("requestId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No requestId in order response".to_string())
}

// ── Mint allowlist enforcement ───────────────────────────────────────

/// Check if a mint is in the allowlist. Empty allowlist = allow all.
pub fn is_mint_allowed(cfg: &SwapConfig, mint: &str) -> bool {
    cfg.allowed_mints.is_empty() || cfg.allowed_mints.iter().any(|m| *m == mint.to_lowercase())
}

/// Reject if either mint is not in the allowlist. Returns an error message.
pub fn enforce_mint_allowlist(
    cfg: &SwapConfig,
    input_mint: &str,
    output_mint: &str,
) -> Result<(), String> {
    if !is_mint_allowed(cfg, input_mint) {
        return Err(format!(
            "Input mint {} not in allowlist. Transaction rejected.",
            mint_short(input_mint)
        ));
    }
    if !is_mint_allowed(cfg, output_mint) {
        return Err(format!(
            "Output mint {} not in allowlist. Transaction rejected.",
            mint_short(output_mint)
        ));
    }
    Ok(())
}

// ── V1 Swap helpers ─────────────────────────────────────────────────

/// Build Jupiter /swap POST body.
/// POST {swap_api}/swap
/// Body: { quoteResponse: ..., userPublicKey: ..., wrapAndUnwrapSol: true, asLegacyTransaction: true }
pub fn build_swap_body(
    _cfg: &SwapConfig,
    quote: &serde_json::Value,
    user_public_key: &str,
) -> serde_json::Value {
    serde_json::json!({
        "quoteResponse": quote,
        "userPublicKey": user_public_key,
        "wrapAndUnwrapSol": true,
        "asLegacyTransaction": true,
    })
}

/// Build swap body using raw quote JSON string to preserve float precision.
/// Jupiter is sensitive to JSON structure — re-serialization via serde can
/// change float precision and cause V0 routing instead of legacy.
pub fn build_swap_body_raw(quote_json: &str, user_public_key: &str) -> String {
    format!(
        r#"{{ "quoteResponse": {}, "userPublicKey": "{}", "wrapAndUnwrapSol": true, "asLegacyTransaction": true }}"#,
        quote_json, user_public_key
    )
}

/// Extract swapTransaction from Jupiter /swap response.
pub fn extract_swap_transaction(raw: &serde_json::Value) -> Result<String, String> {
    raw.get("swapTransaction")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            let err = raw
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("no swapTransaction in response");
            format!("Jupiter swap failed: {err}")
        })
}

// ── Wire format helpers ──────────────────────────────────────────────
//
// These handle Solana bincode transaction serialization without depending
// on the solana-sdk (which is huge and doesn't compile to wasm32-wasip2).
//
// Bincode legacy tx format:
//   [0x00 prefix][compact_u32 num_sigs][64 bytes per sig][Message bytes]
// Unsigned: [0x00][0x01][64 zero bytes][message bytes]
// Message starts at byte 66.

/// Decode base64 to bytes.
pub fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    // Standard base64 (no whitespace)
    use std::io::Read;
    let mut buf = Vec::new();
    let engine = base64::engine::general_purpose::STANDARD;
    let mut decoder = base64::read::DecoderReader::new(s.as_bytes(), &engine);
    decoder
        .read_to_end(&mut buf)
        .map_err(|e| format!("base64 decode error: {e}"))?;
    Ok(buf)
}

/// Decode base58 to bytes.
pub fn decode_base58(s: &str) -> Result<Vec<u8>, String> {
    bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("base58 decode error: {e}"))
}

/// Encode bytes to base64.
pub fn encode_base64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Parse the end offset of a CompiledMessage within a MessageV0 wire buffer.
///
/// CompiledMessage layout:
///   [0] num_required_signatures
///   [1] num_readonly_signed_accounts
///   [2] num_readonly_unsigned_accounts
///   [3..] compact_u32(num_account_keys)
///   [..] account_keys (32 bytes each)
///   [..] recent_blockhash (32 bytes)
///   [..] compact_u32(num_instructions)
///   [..] instructions (each: compact_u32(num_acct_indexes) + acct_indexes + u8(prog_idx) + compact_u32(data_len) + data)
///
/// Returns the byte offset where the CompiledMessage ends (ALT data begins).
#[cfg(not(target_arch = "wasm32"))]
pub fn parse_compiled_message_end(buf: &[u8]) -> Result<usize, String> {
    if buf.len() < 4 {
        return Err("CompiledMessage too short".to_string());
    }

    // Header: 3 bytes
    let header_end = 3;

    // num_account_keys (compact_u32)
    let (num_keys, keys_cusize) = compact_u32_at(buf, header_end)?;
    let keys_start = header_end + keys_cusize;

    // Account keys: num_keys * 32
    let bh_offset = keys_start + num_keys * 32;

    // Blockhash: 32 bytes
    let ix_offset = bh_offset + 32;

    // num_instructions (compact_u32)
    let (num_ix, ix_cusize) = compact_u32_at(buf, ix_offset)?;
    let mut offset = ix_offset + ix_cusize;

    // Parse each instruction
    for _ in 0..num_ix {
        // num_account_indexes (compact_u32)
        let (num_ai, ai_cusize) = compact_u32_at(buf, offset)?;
        offset += ai_cusize + num_ai;

        // program_id_index (u8)
        offset += 1;

        // data length (compact_u32)
        let (data_len, data_cusize) = compact_u32_at(buf, offset)?;
        offset += data_cusize + data_len;
    }

    Ok(offset)
}

#[cfg(not(target_arch = "wasm32"))]
/// Read a compact_u32 starting at `pos` in `buf`.
/// Returns (value, bytes_consumed).
pub fn compact_u32_at(buf: &[u8], pos: usize) -> Result<(usize, usize), String> {
    if buf.len() <= pos {
        return Err("buffer too short for compact_u32".to_string());
    }
    let byte = buf[pos];
    if byte < 0x80 {
        Ok((byte as usize, 1))
    } else if buf.len() > pos + 2 && byte < 0xC0 {
        // 2-byte: 10xxxxxx 1xxxxxxx
        let val = ((byte as usize & 0x3F) << 8) | (buf[pos + 1] as usize & 0x7F);
        Ok((val, 2))
    } else if buf.len() > pos + 4 && byte < 0xE0 {
        // 3-byte
        let val = ((byte as usize & 0x1F) << 24)
            | ((buf[pos + 1] as usize & 0x7F) << 16)
            | ((buf[pos + 2] as usize & 0x7F) << 8)
            | (buf[pos + 3] as usize & 0x7F);
        Ok((val, 4))
    } else if buf.len() > pos + 5 {
        // 5-byte
        let val = ((byte as usize & 0x0F) << 56)
            | ((buf[pos + 1] as usize & 0x7F) << 48)
            | ((buf[pos + 2] as usize & 0x7F) << 40)
            | ((buf[pos + 3] as usize & 0x7F) << 32)
            | ((buf[pos + 4] as usize & 0x7F) << 24)
            | ((buf[pos + 5] as usize & 0x7F) << 16);
        Ok((val, 6))
    } else {
        Err(format!("unsupported compact_u32 at pos {pos}"))
    }
}

/// Detect transaction version from first byte.
pub fn tx_version(tx_bytes: &[u8]) -> u8 {
    tx_bytes.first().copied().unwrap_or(0xFF)
}

/// Extract message bytes from a bincode-encoded Solana transaction.
///
/// For legacy transactions: byte 0 = 0x00, bytes 1-2 = compact_u32 num_sigs (always 1),
/// bytes 3-66 = 64 bytes of signature, bytes 67+ = Message bytes.
///
/// Returns the Message portion that validators verify signatures against.
pub fn extract_message_from_tx(tx_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if tx_bytes.is_empty() {
        return Err("empty transaction".to_string());
    }

    let prefix = tx_bytes[0];
    match prefix {
        // Legacy transaction: byte[0]=0x00
        0x00 => {
            if tx_bytes.len() < 67 {
                return Err(format!(
                    "legacy tx too short ({} bytes, need at least 67)",
                    tx_bytes.len()
                ));
            }
            // byte[0] = 0x00 (legacy prefix)
            // byte[1] = 0x01 (compact_u32: num_sigs = 1)
            // byte[2..66] = 64 bytes of signature (zeros for unsigned)
            // byte[66..] = Message bytes
            Ok(tx_bytes[66..].to_vec())
        }
        #[cfg(not(target_arch = "wasm32"))]
        // V0 transaction (Jupiter/solders format): byte[0]=0x01
        // Layout: [0x01 prefix][64 bytes sig slot][CompiledMessage][ALT data]
        // No explicit num_sigs byte — the sig slot is always 64 bytes.
        // CompiledMessage starts at byte 65.
        0x01 => {
            if tx_bytes.len() < 66 {
                return Err(format!(
                    "V0 tx too short ({} bytes, need at least 66)",
                    tx_bytes.len()
                ));
            }
            // Take everything from byte 65 to end. This is the message blob that
            // OutLayer signs. We don't need to parse instruction boundaries —
            // only the blockhash offset (handled by replace_blockhash_in_message).
            let msg = tx_bytes[65..].to_vec();
            if msg.len() > 1232 {
                return Err(format!(
                    "V0 message ({} bytes) exceeds OutLayer 1232-byte limit",
                    msg.len()
                ));
            }
            Ok(msg)
        }
        other => Err(format!(
            "Unknown transaction prefix 0x{other:02x}. Expected 0x00 (legacy) or 0x01 (V0)."
        )),
    }
}

/// Assemble a signed transaction by replacing the zero signature slot with the real one.
///
/// Takes the original unsigned tx bytes and a base58 signature string.
/// Returns a new byte array with the signature inserted.
pub fn assemble_signed_tx(tx_bytes: &[u8], sig_base58: &str) -> Result<Vec<u8>, String> {
    let mut out = tx_bytes.to_vec();
    if out.is_empty() {
        return Err("empty transaction".to_string());
    }

    // Decode base58 signature to 64 bytes
    let sig_bytes = bs58::decode(sig_base58)
        .into_vec()
        .map_err(|e| format!("invalid base58 signature: {e}"))?;

    if sig_bytes.len() != 64 {
        return Err(format!(
            "expected 64-byte signature, got {}",
            sig_bytes.len()
        ));
    }

    // Find sig slot based on transaction version prefix
    match out[0] {
        // Legacy: [0x00 prefix][compact_u32 num_sigs=0x01][64 bytes sig][message bytes]
        0x00 => {
            if out.len() < 66 {
                return Err("legacy tx too short for signature slot".to_string());
            }
            out[2..66].copy_from_slice(&sig_bytes);
        }
        #[cfg(not(target_arch = "wasm32"))]
        // V0 (Jupiter/solders format): [0x01][64B sig][CompiledMessage][ALT?]
        // Place 64-byte signature at bytes [1:65].
        0x01 => {
            if out.len() < 65 {
                return Err("V0 tx too short for signature slot".to_string());
            }
            out[1..65].copy_from_slice(&sig_bytes);
        }
        other => return Err(format!("unsupported tx prefix 0x{other:02x}")),
    }

    Ok(out)
}

/// Replace blockhash in legacy Solana message bytes with a fresh one.
///
/// Legacy Message bincode layout:
///   [0..2]  header (3 bytes: num_required_sigs, num_readonly_signed, num_readonly_unsigned)
///   [2..]   compact_u32 num_account_keys
///   [2+N..] 32 bytes per account key
///   [2+N+32*num_keys..] 32 bytes recent_blockhash
///
/// The blockhash offset depends on compact_u32 encoding of num_keys.
pub fn replace_blockhash_in_message(
    message_bytes: &[u8],
    new_blockhash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut out = message_bytes.to_vec();
    if out.len() < 36 {
        return Err("message too short to contain blockhash".to_string());
    }

    // Solana legacy Message bincode layout:
    //   [0]      num_required_signatures (u8)
    //   [1]      num_readonly_signed_accounts (u8)
    //   [2]      num_readonly_unsigned_accounts (u8)
    //   [3..]    compact_u32 num_account_keys
    //   [3+N..]  32 bytes per account key
    //   [3+N+32*num_keys..] 32 bytes recent_blockhash
    //
    // The compact_u32 encoding of num_keys starts at byte 3.
    let (num_keys, num_keys_size) = if out[3] < 0x80 {
        (out[3] as usize, 1)
    } else if out.len() > 4 && (out[3] & 0x7f) < 0x80 {
        (usize::from(out[3] & 0x7f) | (usize::from(out[4]) << 7), 2)
    } else {
        return Err("compact_u32 num_keys too large".to_string());
    };

    // keys_start = header(3) + compact_u32(num_keys_size)
    let keys_start = 3 + num_keys_size;
    // blockhash comes after all keys
    let bh_offset = keys_start + num_keys * 32;
    if out.len() < bh_offset + 32 {
        return Err(format!(
            "message too short for {} keys (need at least {} bytes, have {})",
            num_keys,
            bh_offset + 32,
            out.len()
        ));
    }

    out[bh_offset..bh_offset + 32].copy_from_slice(new_blockhash);
    Ok(out)
}

/// Broadcast a signed transaction to the configured Solana RPC.
/// Returns the RPC response (signature or error).
pub fn broadcast_tx(cfg: &SwapConfig, signed_tx_base64: &str) -> Result<String, String> {
    // In WASM mode, this would use wasi:http POST. For now, return a placeholder.
    // The host or caller should handle the actual broadcast.
    Err(format!(
        "Broadcast not implemented in WASM (RPC: {}). Tx: {}... ({} bytes). \
         Host must broadcast via sendTransaction with encoding=base64.",
        cfg.solana_rpc,
        &signed_tx_base64[..20.min(signed_tx_base64.len())],
        signed_tx_base64.len()
    ))
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Shorten a mint address for display: "So11111111111111111111111111111111111111112" → "So1111..."
pub fn mint_short(mint: &str) -> &str {
    if mint.len() > 12 {
        &mint[..8]
    } else {
        mint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_config() -> SwapConfig {
        SwapConfig::from_section(&HashMap::new())
    }

    fn config_with(pairs: &[(&str, &str)]) -> SwapConfig {
        let section: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        SwapConfig::from_section(&section)
    }

    #[test]
    fn empty_config_has_safe_defaults() {
        let cfg = empty_config();
        assert_eq!(cfg.swap_api, "https://public.jupiterapi.com");
        assert_eq!(cfg.price_api, "https://api.jup.ag/price/v3");
        assert_eq!(cfg.outlayer_api, "https://api.outlayer.fastnear.com");
        assert!(cfg.jupiter_api_key.is_empty());
        assert!(!cfg.has_jupiter_key());
        assert!(cfg.outlayer_api_key.is_empty());
        assert_eq!(cfg.max_slippage_bps, 50);
        assert!(cfg.allowed_mints.is_empty());
        assert_eq!(cfg.daily_spend_cap_usd, 500.0);
    }

    #[test]
    fn config_overrides_from_section() {
        let cfg = config_with(&[
            ("max_slippage_bps", "100"),
            ("daily_spend_cap_usd", "1000"),
            (
                "allowed_mints",
                "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            ),
            ("jupiter_api_key", "test_key"),
        ]);
        assert_eq!(cfg.max_slippage_bps, 100);
        assert_eq!(cfg.daily_spend_cap_usd, 1000.0);
        assert_eq!(cfg.allowed_mints.len(), 2);
        assert!(cfg.has_jupiter_key());
    }

    #[test]
    fn empty_allowlist_allows_everything() {
        let cfg = empty_config();
        assert!(is_mint_allowed(&cfg, "any_random_mint_address"));
    }

    #[test]
    fn non_empty_allowlist_blocks_unlisted_mints() {
        let cfg = config_with(&[("allowed_mints", SOL_MINT)]);
        assert!(is_mint_allowed(&cfg, SOL_MINT));
        assert!(!is_mint_allowed(&cfg, "random_bad_mint"));
    }

    #[test]
    fn enforce_allowlist_passes_for_allowed() {
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let cfg = config_with(&[(
            "allowed_mints",
            "So11111111111111111111111111111111111111112,EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        )]);
        assert!(enforce_mint_allowlist(&cfg, SOL_MINT, usdc).is_ok());
    }

    #[test]
    fn enforce_allowlist_blocks_bad_mint() {
        let bad = "9xyzFAKEtokenMintAddress";
        let cfg = config_with(&[("allowed_mints", SOL_MINT)]);
        let result = enforce_mint_allowlist(&cfg, SOL_MINT, bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowlist"));
    }

    // ── Price V3 ──

    #[test]
    fn build_price_url_uses_v3() {
        let cfg = empty_config();
        let url = build_price_url(&cfg, &[SOL_MINT, USDC_MINT]);
        assert!(url.contains("price/v3"));
        assert!(url.contains("ids="));
        assert!(url.contains("So1111"));
        assert!(url.contains("EPjFWdd"));
    }

    #[test]
    fn shape_price_v3_response_compact() {
        let raw = serde_json::json!({
            "So11111111111111111111111111111111111111112": {
                "usdPrice": 143.27,
                "decimals": 9,
                "priceChange24h": 1.29
            },
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {
                "usdPrice": 0.9998,
                "decimals": 6,
                "priceChange24h": -0.15
            }
        });
        let out = shape_price_response(&raw);
        assert!(out.contains("$143.27"));
        assert!(out.contains("+1.29%"));
        assert!(out.contains("$1.00"));
        assert!(out.contains("-0.15%"));
        assert!(out.len() < 300);
    }

    #[test]
    fn shape_price_v3_empty_returns_message() {
        let raw = serde_json::json!({});
        let out = shape_price_response(&raw);
        assert_eq!(out, "No prices found.");
    }

    // ── Swap /quote ──

    #[test]
    fn build_quote_url_uses_v1() {
        let cfg = empty_config();
        let url = build_quote_url(&cfg, SOL_MINT, USDC_MINT, 100000000, 50);
        assert!(url.contains("/quote"));
        assert!(url.contains("inputMint=So1111"));
        assert!(url.contains("outputMint=EPjFWdd"));
        assert!(url.contains("amount=100000000"));
        assert!(url.contains("slippageBps=50"));
        assert!(url.contains("asLegacyTransaction=true"));
    }

    #[test]
    fn build_quote_url_clamps_slippage() {
        let cfg = config_with(&[("max_slippage_bps", "50")]);
        let url = build_quote_url(&cfg, SOL_MINT, USDC_MINT, 1000000, 500);
        assert!(url.contains("slippageBps=50"));
    }

    #[test]
    fn build_swap_body_structure() {
        let quote = serde_json::json!({ "inAmount": "100000", "outAmount": "50000" });
        let body = build_swap_body(&empty_config(), &quote, "my_wallet");
        assert_eq!(body["quoteResponse"]["inAmount"], "100000");
        assert_eq!(body["userPublicKey"], "my_wallet");
        assert_eq!(body["wrapAndUnwrapSol"], true);
        assert_eq!(body["asLegacyTransaction"], true);
    }

    #[test]
    fn shape_quote_response_compact() {
        let raw = serde_json::json!({
            "inAmount": "100000000",
            "outAmount": "14285714300",
            "priceImpactPct": 0.001,
            "swapMode": "ExactIn"
        });
        let out = shape_quote_response(&raw);
        assert!(out.contains("100000000"));
        assert!(out.contains("14285714300"));
        assert!(out.contains("0.001"));
        assert!(out.contains("ExactIn"));
        assert!(out.len() < 300);
    }

    #[test]
    fn extract_swap_transaction_success() {
        let raw = serde_json::json!({
            "swapTransaction": "aGVsbG8gd29ybGQ="
        });
        assert_eq!(extract_swap_transaction(&raw).unwrap(), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn extract_swap_transaction_null_fails() {
        let raw = serde_json::json!({
            "swapTransaction": null,
            "error": "insufficient liquidity"
        });
        assert!(extract_swap_transaction(&raw).is_err());
    }

    // ── OutLayer ──

    #[test]
    fn outlayer_address_url_has_solana_chain() {
        let cfg = empty_config();
        let url = build_outlayer_address_url(&cfg);
        assert!(url.contains("/wallet/v1/address"));
        assert!(url.contains("chain=solana"));
    }

    #[test]
    fn outlayer_balance_url_includes_token() {
        let cfg = empty_config();
        let url = build_outlayer_balance_url(&cfg, USDC_MINT);
        assert!(url.contains("EPjFWdd"));
        assert!(url.contains("chain=solana"));
    }

    #[test]
    fn outlayer_solana_sign_body_serializes() {
        let body = build_outlayer_solana_sign_body("dGVzdA==");
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(serialized.contains("\"chain\":\"solana\""));
        assert!(serialized.contains("\"unsigned_tx\":\"dGVzdA==\""));
        assert!(serialized.len() < 200);
    }

    #[test]
    fn outlayer_sign_response_shaping() {
        let raw = serde_json::json!({
            "signature": "5Kt8abc123sig",
            "chain": "solana",
            "wallet_id": "450290fb-a7ae-4744-8251-61e29ba12e15"
        });
        let out = shape_outlayer_sign_response(&raw);
        assert!(out.contains("450290fb"));
        assert!(out.contains("5Kt8abc123sig"));
    }

    // ── Blockhash replacement ──

    #[test]
    fn decode_base58_roundtrip() {
        let original = vec![0x01, 0x02, 0x03, 0x04];
        let encoded = bs58::encode(&original).into_string();
        let decoded = decode_base58(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn replace_blockhash_small_keys() {
        // Build a fake legacy message: 3-byte header + compact_u32(1) + 1 key + blockhash + some data
        let mut msg = vec![0x01, 0x00, 0x00]; // header
        msg.push(0x01); // compact_u32: 1 key
        msg.extend_from_slice(&[0xAA; 32]); // key
        let old_bh_pos = msg.len();
        msg.extend_from_slice(&[0xBB; 32]); // old blockhash
        msg.extend_from_slice(&[0xCC; 32]); // some ix data

        let new_bh = [0xDD; 32];
        let result = replace_blockhash_in_message(&msg, &new_bh).unwrap();
        assert_eq!(&result[old_bh_pos..old_bh_pos + 32], &new_bh[..]);
        // Other bytes unchanged
        assert_eq!(&result[4..36], &[0xAA; 32]); // key unchanged
    }

    #[test]
    fn replace_blockhash_many_keys() {
        // compact_u32 for 22 keys = 0x16 (< 0x80, single byte)
        let num_keys: u8 = 22;
        let mut msg = vec![0x01, 0x00, 0x00]; // header
        msg.push(num_keys);
        for _ in 0..num_keys {
            msg.extend_from_slice(&[0xAA; 32]);
        }
        let bh_offset = msg.len();
        msg.extend_from_slice(&[0xBB; 32]); // old blockhash

        let new_bh = [0xEE; 32];
        let result = replace_blockhash_in_message(&msg, &new_bh).unwrap();
        assert_eq!(&result[bh_offset..bh_offset + 32], &new_bh[..]);
    }

    #[test]
    fn replace_blockhash_too_short() {
        let msg = vec![0x01, 0x00];
        let bh = [0u8; 32];
        assert!(replace_blockhash_in_message(&msg, &bh).is_err());
    }

    // ── Helpers ──

    #[test]
    fn mint_short_truncates_long_addresses() {
        assert_eq!(mint_short(USDC_MINT), "EPjFWdd5");
    }

    #[test]
    fn mint_short_preserves_short_addresses() {
        assert_eq!(mint_short("short"), "short");
    }

    #[test]
    fn well_known_mints_are_correct() {
        assert!(SOL_MINT.starts_with("So1111"));
        assert!(USDC_MINT.starts_with("EPjFWdd"));
        // Standard wrapped SOL mint (43 chars)
        assert_eq!(SOL_MINT.len(), 43);
        // Standard USDC mint (44 chars)
        assert_eq!(USDC_MINT.len(), 44);
    }
}
