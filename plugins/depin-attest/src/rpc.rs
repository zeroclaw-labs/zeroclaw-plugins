use serde_json::Value;

pub trait HttpClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

pub struct NonceData {
    pub nonce_hash: [u8; 32],
    pub authority: [u8; 32],
}

pub fn fetch_nonce_account(
    client: &dyn HttpClient,
    rpc_url: &str,
    nonce_account_b58: &str,
) -> Result<NonceData, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["{}",{{"encoding":"base64","commitment":"confirmed"}}]}}"#,
        nonce_account_b58
    );
    let resp_str = client.post_json(rpc_url, &body)?;
    
    let resp: Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Invalid JSON response: {}", e))?;
        
    if let Some(err) = resp.get("error") {
        return Err(format!("RPC error: {}", err));
    }
    
    let result = resp.get("result")
        .ok_or_else(|| "Missing 'result' field in response".to_string())?;
        
    if result.is_null() {
        return Err("Result is null".to_string());
    }
    
    let value = result.get("value")
        .ok_or_else(|| "Missing 'result.value' field".to_string())?;
        
    if value.is_null() {
        return Err("Nonce account does not exist (value is null)".to_string());
    }
    
    let data_array = value.get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| "Missing or invalid 'data' field".to_string())?;
        
    if data_array.is_empty() {
        return Err("Empty 'data' array".to_string());
    }
    
    let base64_data = data_array[0].as_str()
        .ok_or_else(|| "Data is not a string".to_string())?;
        
    use base64::{engine::general_purpose, Engine as _};
    let data_bytes = general_purpose::STANDARD.decode(base64_data)
        .map_err(|e| format!("Failed to base64 decode account data: {}", e))?;
        
    if data_bytes.len() < 80 {
        return Err(format!("Nonce account data too short: {} bytes, expected >= 80", data_bytes.len()));
    }
    
    let version = u32::from_le_bytes(data_bytes[0..4].try_into().unwrap());
    if version != 1 {
        return Err(format!("Unsupported nonce account version: expected 1, got {}", version));
    }
    
    let state = u32::from_le_bytes(data_bytes[4..8].try_into().unwrap());
    if state != 1 { // 1 = Initialized
        return Err(format!("Nonce account is not initialized (state={})", state));
    }
    
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&data_bytes[8..40]);
    
    let mut nonce_hash = [0u8; 32];
    nonce_hash.copy_from_slice(&data_bytes[40..72]);
    
    Ok(NonceData {
        nonce_hash,
        authority,
    })
}


