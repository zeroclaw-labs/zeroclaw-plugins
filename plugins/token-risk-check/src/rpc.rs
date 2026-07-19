//! Pure Solana JSON-RPC helpers + SPL mint account decode (no network).

use crate::risk::MintFacts;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};

pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Hosts allowed for live RPC (fail-closed allowlist).
pub fn rpc_url_allowed(url: &str) -> bool {
    let u = url.trim().to_ascii_lowercase();
    if !u.starts_with("https://") {
        return false;
    }
    u.contains("api.mainnet-beta.solana.com")
        || u.contains("api.devnet.solana.com")
        || u.contains("api.testnet.solana.com")
        || u.contains("helius-rpc.com")
        || u.contains("helius.xyz")
        || u.contains("rpc.ankr.com/solana")
        || u.contains("solana-mainnet.g.alchemy.com")
}

pub fn build_get_account_info_body(mint: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            mint,
            { "encoding": "base64", "commitment": "confirmed" }
        ]
    })
    .to_string()
}

/// Parse `getAccountInfo` JSON body into mint facts.
pub fn mint_facts_from_rpc_json(mint: &str, response_body: &str) -> Result<MintFacts, String> {
    let v: Value = serde_json::from_str(response_body).map_err(|e| format!("rpc_json: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("rpc_error: {err}"));
    }
    let value = v
        .pointer("/result/value")
        .ok_or_else(|| "rpc_missing_result_value".to_string())?;
    if value.is_null() {
        return Err("mint_account_not_found".into());
    }
    let owner = value
        .get("owner")
        .and_then(|o| o.as_str())
        .ok_or_else(|| "rpc_missing_owner".to_string())?;
    let data0 = value
        .pointer("/data/0")
        .and_then(|d| d.as_str())
        .ok_or_else(|| "rpc_missing_data".to_string())?;
    decode_mint_account(mint, owner, data0)
}

pub fn decode_mint_account(mint: &str, owner: &str, data_b64: &str) -> Result<MintFacts, String> {
    let raw = B64
        .decode(data_b64.trim())
        .map_err(|e| format!("base64: {e}"))?;
    if raw.len() < 82 {
        return Err(format!("mint_data_too_short:{}", raw.len()));
    }

    let mint_authority = decode_coption_pubkey(&raw[0..36]);
    let supply = u64::from_le_bytes(raw[36..44].try_into().unwrap());
    let decimals = raw[44];
    let freeze_authority = decode_coption_pubkey(&raw[46..82]);

    let is_token_2022 = owner == TOKEN_2022_PROGRAM;
    let mut permanent_delegate = false;
    let mut transfer_hook_or_fee = false;

    if is_token_2022 && raw.len() > 82 {
        // Heuristic TLV scan (Token-2022 extension type ids).
        // 9 = Transfer Fee Config, 14 = Transfer Hook, 12 = Permanent Delegate (common ids).
        let tlv = &raw[82..];
        let mut i = 0usize;
        while i + 4 <= tlv.len() {
            let ext_type = u16::from_le_bytes([tlv[i], tlv[i + 1]]);
            let ext_len = u16::from_le_bytes([tlv[i + 2], tlv[i + 3]]) as usize;
            i += 4;
            if i + ext_len > tlv.len() {
                break;
            }
            match ext_type {
                12 => permanent_delegate = true,
                9 | 14 => transfer_hook_or_fee = true,
                _ => {}
            }
            i += ext_len;
        }
        if raw.len() > 165 && !transfer_hook_or_fee && !permanent_delegate {
            // Long account without parsed flags — still caution.
            transfer_hook_or_fee = true;
        }
    }

    if owner != TOKEN_PROGRAM && owner != TOKEN_2022_PROGRAM {
        return Err(format!("unexpected_mint_owner:{owner}"));
    }

    Ok(MintFacts {
        mint: mint.to_string(),
        mint_authority,
        freeze_authority,
        supply: Some(supply),
        decimals: Some(decimals),
        permanent_delegate,
        transfer_hook_or_fee,
        is_token_2022,
    })
}

fn decode_coption_pubkey(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 36 {
        return None;
    }
    let tag = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if tag == 0 {
        return None;
    }
    if tag != 1 {
        return None;
    }
    Some(bs58::encode(&bytes[4..36]).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_http_rpc() {
        assert!(!rpc_url_allowed("http://evil.example/rpc"));
    }

    #[test]
    fn allows_public_solana() {
        assert!(rpc_url_allowed(DEFAULT_RPC_URL));
    }

    #[test]
    fn builds_rpc_body() {
        let b = build_get_account_info_body("So11111111111111111111111111111111111111112");
        assert!(b.contains("getAccountInfo"));
        assert!(b.contains("So11111111111111111111111111111111111111112"));
    }
}
