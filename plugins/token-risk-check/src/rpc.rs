use serde_json::Value;

pub trait HttpClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

pub struct AccountInfo {
    pub data: Vec<u8>,
    pub owner: [u8; 32],
    pub executable: bool,
    pub slot: u64,
}

pub fn fetch_account_info(
    client: &dyn HttpClient,
    rpc_url: &str,
    pubkey: &str,
) -> Result<AccountInfo, String> {
    let decoded = bs58::decode(pubkey)
        .into_vec()
        .map_err(|e| format!("Invalid account address: {}", e))?;
    if decoded.len() != 32 {
        return Err("Invalid account address: must be exactly 32 bytes".to_string());
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            pubkey,
            { "encoding": "base64" }
        ]
    })
    .to_string();

    let res_str = client.post_json(rpc_url, &body)?;
    let res_json: Value =
        serde_json::from_str(&res_str).map_err(|e| format!("Failed to parse RPC response: {}", e))?;

    if res_json.get("error").is_some() {
        return Err(format!("RPC error: {:?}", res_json["error"]));
    }

    let result_obj = res_json
        .get("result")
        .ok_or_else(|| "result field not found".to_string())?;

    let slot = result_obj
        .get("context")
        .and_then(|c| c.get("slot"))
        .and_then(|s| s.as_u64())
        .ok_or_else(|| "Missing or malformed slot in context".to_string())?;

    let value = result_obj
        .get("value")
        .ok_or_else(|| "account not found".to_string())?;

    if value.is_null() {
        return Err("account not found".to_string());
    }

    let executable = value
        .get("executable")
        .and_then(|e| e.as_bool())
        .ok_or_else(|| "Missing or malformed executable field".to_string())?;

    let owner_str = value
        .get("owner")
        .and_then(|o| o.as_str())
        .ok_or_else(|| "Missing or malformed owner field".to_string())?;

    let mut owner = [0u8; 32];
    let decoded_owner = bs58::decode(owner_str)
        .into_vec()
        .map_err(|e| format!("Failed to decode owner: {}", e))?;
    if decoded_owner.len() != 32 {
        return Err("Owner pubkey is not 32 bytes".to_string());
    }
    owner.copy_from_slice(&decoded_owner);

    let data_arr = value
        .get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| "Missing or malformed data field in account info".to_string())?;

    let base64_str = data_arr
        .first()
        .and_then(|s| s.as_str())
        .ok_or_else(|| "Missing or malformed base64 string in data array".to_string())?;

    use base64::{engine::general_purpose, Engine as _};
    let data = general_purpose::STANDARD
        .decode(base64_str)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    Ok(AccountInfo {
        data,
        owner,
        executable,
        slot,
    })
}

pub fn fetch_mint_account(
    client: &dyn HttpClient,
    rpc_url: &str,
    mint: &str,
) -> Result<(Vec<u8>, u64), String> {
    fetch_account_info(client, rpc_url, mint).map(|info| (info.data, info.slot))
}
pub fn fetch_largest_accounts(
    client: &dyn HttpClient,
    rpc_url: &str,
    mint: &str,
) -> Result<(Vec<(String, u128)>, u64), String> {
    let decoded = bs58::decode(mint)
        .into_vec()
        .map_err(|e| format!("Invalid account address: {}", e))?;
    if decoded.len() != 32 {
        return Err("Invalid account address: must be exactly 32 bytes".to_string());
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenLargestAccounts",
        "params": [mint]
    })
    .to_string();

    let res_str = client.post_json(rpc_url, &body)?;
    let res_json: Value =
        serde_json::from_str(&res_str).map_err(|e| format!("Failed to parse RPC response: {}", e))?;

    if res_json.get("error").is_some() {
        return Err(format!("RPC error: {:?}", res_json["error"]));
    }

    let result_obj = res_json
        .get("result")
        .ok_or_else(|| "result field not found".to_string())?;

    let slot = result_obj
        .get("context")
        .and_then(|c| c.get("slot"))
        .and_then(|s| s.as_u64())
        .ok_or_else(|| "Missing or malformed slot in context".to_string())?;

    let value_arr = result_obj
        .get("value")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing or malformed value array in getTokenLargestAccounts".to_string())?;

    let mut largest = Vec::new();
    for (i, entry) in value_arr.iter().enumerate().take(10) {
        let address = entry
            .get("address")
            .and_then(|a| a.as_str())
            .ok_or_else(|| format!("Missing or malformed address at index {}", i))?;

        let amount_str = entry
            .get("amount")
            .and_then(|a| a.as_str())
            .ok_or_else(|| format!("Missing or malformed amount at index {}", i))?;

        let amount: u128 = amount_str
            .parse()
            .map_err(|_| format!("Failed to parse amount as u128 at index {}", i))?;

        largest.push((address.to_string(), amount));
    }

    Ok((largest, slot))
}

#[derive(Debug, PartialEq)]
pub enum SlotConsistency {
    Exact,
    BoundedForward(u64),
    Reversed,
    ExcessiveSkew,
}

// 25 slots represents roughly 10-12 seconds on mainnet. Two sequential RPC calls
// should easily complete within this window under normal latency. If skew exceeds
// this, the data is dangerously non-atomic (e.g., node falling behind).
pub const MAX_FORWARD_SLOT_SKEW: u64 = 25;

pub fn check_slot_consistency(mint_slot: u64, largest_accounts_slot: u64) -> SlotConsistency {
    match largest_accounts_slot.checked_sub(mint_slot) {
        None => SlotConsistency::Reversed, // largest_accounts_slot < mint_slot - nonsensical
        Some(0) => SlotConsistency::Exact,
        Some(skew) if skew <= MAX_FORWARD_SLOT_SKEW => SlotConsistency::BoundedForward(skew),
        Some(_) => SlotConsistency::ExcessiveSkew,
    }
}
