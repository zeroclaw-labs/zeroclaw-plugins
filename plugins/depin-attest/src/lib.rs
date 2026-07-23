pub mod provenance;
pub mod reading;
pub mod memo;
pub mod tx;
pub mod rpc;
pub mod nonce;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::reading::{validate_reading, SensorReading};
use crate::provenance::verify_provenance;
use crate::rpc::HttpClient;
use crate::memo::build_memo_instruction;
use crate::tx::{build_unsigned_v0_tx, to_base64};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    pub reading: SensorReading,
    pub signature_hex: String,
}

#[derive(Serialize, Debug)]
pub struct OrchestrationOutput {
    pub tx_b64: String,
    pub nonce_account: String,
    pub fee_payer: String,
    pub nonce_authority: String,
    pub required_signatures: String,
    pub memo_summary: String,
}

pub fn orchestrate_attestation(
    args_json: &str,
    client: &dyn HttpClient,
    current_timestamp: i64,
) -> Result<OrchestrationOutput, String> {
    // 1. Manual __config split
    let mut raw_val: Value = serde_json::from_str(args_json)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let config_val = raw_val
        .as_object_mut()
        .and_then(|map| map.remove("__config"))
        .unwrap_or(Value::Null);

    let config: std::collections::HashMap<String, String> =
        serde_json::from_value(config_val).unwrap_or_default();

    // 2. Deserialize args
    let args: ExecuteArgs = serde_json::from_value(raw_val)
        .map_err(|e| format!("Invalid arguments: {}", e))?;

    // Extract and resolve config keys
    let fee_payer_b58 = config.get("fee_payer")
        .map(|s| s.as_str())
        .ok_or_else(|| "Missing 'fee_payer' in config".to_string())?;

    let nonce_account_b58 = config.get("nonce_account")
        .map(|s| s.as_str())
        .ok_or_else(|| "Missing 'nonce_account' in config".to_string())?;

    let nonce_authority_b58 = config.get("nonce_authority")
        .map(|s| s.as_str())
        .unwrap_or(fee_payer_b58);

    let decoded_fee_payer = bs58::decode(fee_payer_b58).into_vec()
        .map_err(|e| format!("Invalid base58 in fee_payer: {}", e))?;
    if decoded_fee_payer.len() != 32 {
        return Err(format!("fee_payer decoded to {} bytes, expected 32", decoded_fee_payer.len()));
    }
    let mut fee_payer = [0u8; 32];
    fee_payer.copy_from_slice(&decoded_fee_payer);

    let decoded_nonce_account = bs58::decode(nonce_account_b58).into_vec()
        .map_err(|e| format!("Invalid base58 in nonce_account: {}", e))?;
    if decoded_nonce_account.len() != 32 {
        return Err(format!("nonce_account decoded to {} bytes, expected 32", decoded_nonce_account.len()));
    }
    let mut nonce_account = [0u8; 32];
    nonce_account.copy_from_slice(&decoded_nonce_account);

    let decoded_nonce_authority = bs58::decode(nonce_authority_b58).into_vec()
        .map_err(|e| format!("Invalid base58 in nonce_authority: {}", e))?;
    if decoded_nonce_authority.len() != 32 {
        return Err(format!("nonce_authority decoded to {} bytes, expected 32", decoded_nonce_authority.len()));
    }
    let mut nonce_authority = [0u8; 32];
    nonce_authority.copy_from_slice(&decoded_nonce_authority);

    // 3. validate_reading
    validate_reading(&args.reading)
        .map_err(|e| format!("Invalid reading: {}", e))?;

    // 4. Decode signature and device pubkey
    // Intent: simple devices share one key for all sensors (global fallback); 
    // complex gateways can issue distinct per-sensor keys for granular revocation.
    let pubkey_key = format!("{}_pubkey", args.reading.sensor_id);
    let pubkey_hex = config.get(&pubkey_key)
        .or_else(|| config.get("device_pubkey"))
        .map(|s| s.as_str())
        .ok_or_else(|| "Missing device_pubkey in config".to_string())?;

    if pubkey_hex.len() != 64 {
        return Err("Config device_pubkey must be 64 hex characters".to_string());
    }

    let mut pubkey = [0u8; 32];
    for (i, byte) in pubkey.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&pubkey_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid hex in device_pubkey".to_string())?;
    }

    if args.signature_hex.len() != 128 {
        return Err("signature_hex must be 128 hex characters".to_string());
    }

    let mut sig = [0u8; 64];
    for (i, byte) in sig.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args.signature_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid hex in signature_hex".to_string())?;
    }

    // 5. Verify provenance (must be BEFORE RPC call)
    // We sign an explicit pipe-delimited string, NOT raw JSON, to guarantee byte-for-byte 
    // exactness across any device language (C, Python, etc.) avoiding JSON formatting quirks.
    let message_str = format!("{}|{}|{}|{}", args.reading.sensor_id, args.reading.value_str, args.reading.unit, args.reading.timestamp);
    let message = message_str.as_bytes();

    verify_provenance(&pubkey, message, &sig, args.reading.timestamp, current_timestamp)
        .map_err(|e| format!("Provenance verification failed: {}", e))?;

    // 6. Fetch RPC Nonce Account
    let rpc_url = config.get("rpc_url")
        .map(|s| s.as_str())
        .unwrap_or("https://api.mainnet-beta.solana.com");
        
    let nonce_data = crate::rpc::fetch_nonce_account(client, rpc_url, nonce_account_b58)?;
    if nonce_data.authority != nonce_authority {
        return Err("On-chain nonce authority does not match configured nonce_authority".to_string());
    }

    // 7. Derive nonce string for memo
    let nonce_account_short = if nonce_account_b58.len() >= 8 {
        &nonce_account_b58[..8]
    } else {
        nonce_account_b58
    };

    // 8. Build memo text and transaction
    let memo_text = format!(
        "zc-depin|{}|{}|{}|{}|n:{}",
        args.reading.sensor_id, args.reading.value_str, args.reading.unit, args.reading.timestamp, nonce_account_short
    );
    let memo_ix = build_memo_instruction(&memo_text)?;
    let advance_nonce_ix = crate::nonce::build_advance_nonce_instruction(&nonce_account, &nonce_authority);
    
    let tx_bytes = build_unsigned_v0_tx(&fee_payer, &nonce_data.nonce_hash, &[advance_nonce_ix, memo_ix])?;

    // 9. Base64 encode and output
    let tx_b64 = to_base64(&tx_bytes);

    let required_signatures = if fee_payer == nonce_authority {
        "fee_payer".to_string()
    } else {
        "fee_payer, nonce_authority".to_string()
    };

    Ok(OrchestrationOutput {
        tx_b64,
        nonce_account: nonce_account_b58.to_string(),
        fee_payer: fee_payer_b58.to_string(),
        nonce_authority: nonce_authority_b58.to_string(),
        required_signatures,
        memo_summary: memo_text,
    })
}

#[cfg(target_family = "wasm")]
mod shim {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use crate::rpc::HttpClient;
    use std::time::SystemTime;
    
    struct WakiClient;
    impl HttpClient for WakiClient {
        fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
            let resp = waki::Client::new()
                .post(url)
                .header("Content-Type", "application/json")
                .body(body.as_bytes())
                .send()
                .map_err(|e| format!("HTTP send error: {}", e))?;
                
            if resp.status_code() < 200 || resp.status_code() >= 300 {
                return Err(format!("HTTP error status: {}", resp.status_code()));
            }
            
            let body_bytes = resp.body().map_err(|_| "Failed to read response body".to_string())?;
            String::from_utf8(body_bytes).map_err(|e| format!("Invalid UTF-8 in response: {}", e))
        }
    }

    struct DepinAttestPlugin;

    impl PluginInfo for DepinAttestPlugin {
        fn plugin_name() -> String {
            "depin-attest".to_string()
        }

        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for DepinAttestPlugin {
        fn name() -> String {
            "depin-attest".to_string()
        }

        fn description() -> String {
            "Verify Ed25519 signatures of DePIN sensor readings and prepare a transaction.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "reading": {
                        "type": "object",
                        "description": "The sensor reading data",
                        "properties": {
                            "sensor_id": { "type": "string" },
                            "value_str": { "type": "string" },
                            "unit": { "type": "string" },
                            "timestamp": { "type": "integer" }
                        },
                        "required": ["sensor_id", "value_str", "unit", "timestamp"]
                    },
                    "signature_hex": {
                        "type": "string",
                        "description": "Hex-encoded 64-byte Ed25519 signature."
                    }
                },
                "required": ["reading", "signature_hex"]
            })
            .to_string()
        }

        fn execute(args_json: String) -> Result<ToolResult, String> {
            let start = std::time::Instant::now();
            let finish = |success: bool, output: String, error: Option<String>| -> Result<ToolResult, String> {
                // 10. Exactly one log_record call per execute
                let mut attrs = std::collections::HashMap::new();
                attrs.insert("args_len".to_string(), args_json.len().to_string());
                
                let outcome = if success { 
                    zeroclaw::plugin::logging::PluginOutcome::Success 
                } else { 
                    zeroclaw::plugin::logging::PluginOutcome::Failure 
                };
                
                let msg = error.clone().unwrap_or_else(|| "Attestation successful".to_string());
                
                zeroclaw::plugin::logging::log_record(
                    zeroclaw::plugin::logging::LogLevel::Info,
                    &zeroclaw::plugin::logging::PluginEvent {
                        function_name: "execute".to_string(),
                        action: zeroclaw::plugin::logging::PluginAction::Complete,
                        outcome: Some(outcome),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                        attrs: Some(serde_json::to_string(&attrs).unwrap_or_default()),
                        message: msg,
                    }
                );
                
                Ok(ToolResult {
                    success,
                    output,
                    error,
                })
            };

            let current_ts = match SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(_) => return finish(false, "".to_string(), Some("System time error".to_string())),
            };
            
            let client = WakiClient;
            match crate::orchestrate_attestation(&args_json, &client, current_ts) {
                Ok(output) => {
                    match serde_json::to_string(&output) {
                        Ok(out_json) => finish(true, out_json, None),
                        Err(e) => finish(false, "".to_string(), Some(format!("Failed to serialize output: {}", e))),
                    }
                },
                Err(e) => finish(false, "".to_string(), Some(e)),
            }
        }
    }

    export!(DepinAttestPlugin);
}
