use depin_attest::{orchestrate_attestation, rpc::HttpClient};
use depin_attest::reading::SensorReading;
use depin_attest::provenance::MAX_STALENESS_SECS;
use ed25519_dalek::{Signer, SigningKey};

struct PanicIfCalledClient;
impl HttpClient for PanicIfCalledClient {
    fn post_json(&self, _: &str, _: &str) -> Result<String, String> {
        panic!("RPC should never be called for an unverified reading");
    }
}

struct ValidNonceClient {
    authority: [u8; 32],
    state: u32,
    truncate: bool,
}

impl HttpClient for ValidNonceClient {
    fn post_json(&self, _: &str, _: &str) -> Result<String, String> {
        let mut data = vec![0u8; 80];
        data[0] = 1;
        let state_bytes = self.state.to_le_bytes();
        data[4..8].copy_from_slice(&state_bytes);
        data[8..40].copy_from_slice(&self.authority);
        
        if self.truncate {
            data.truncate(79);
        }
        
        use base64::{engine::general_purpose, Engine as _};
        let b64 = general_purpose::STANDARD.encode(&data);
        Ok(format!(r#"{{"jsonrpc": "2.0", "result": {{"value": {{"data": ["{}"]}}}}, "id": 1}}"#, b64))
    }
}

fn generate_test_payload(reading: &SensorReading, tamper_sig: bool) -> (String, String) {
    let secret = [1u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let message_str = format!("{}|{}|{}|{}", reading.sensor_id, reading.value_str, reading.unit, reading.timestamp);
    let message = message_str.as_bytes();
    let mut signature = signing_key.sign(message).to_bytes();
    
    if tamper_sig {
        signature[0] ^= 0xff; // Invalidate signature
    }
    
    let sig_hex = hex::encode(signature);
    
    (pk_hex, sig_hex)
}

#[test]
fn test_bad_signature_never_reaches_rpc() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    
    let (pk_hex, sig_hex) = generate_test_payload(&reading, true); // tampered

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111",
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = PanicIfCalledClient;
    let res = orchestrate_attestation(&args_json, &client, 1000000);
    
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Invalid signature"));
}

#[test]
fn test_stale_reading_never_reaches_rpc() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false); // valid signature

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111",
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = PanicIfCalledClient;
    
    // Simulate current time being exactly MAX_STALENESS_SECS + 1 after the reading timestamp
    let current_ts = 1000000 + MAX_STALENESS_SECS + 1;
    let res = orchestrate_attestation(&args_json, &client, current_ts);
    let err = res.unwrap_err();
    assert!(err.contains("too stale"), "Expected 'too stale', got {:?}", err);
}

#[test]
fn test_valid_reading_does_reach_rpc() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false); // valid signature

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111", // Decodes to [0u8; 32]
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = ValidNonceClient {
        authority: [0u8; 32], // Matches fee_payer
        state: 1,
        truncate: false,
    };
    
    // current time exactly matches reading time (0 staleness)
    let current_ts = 1000000;
    let res = orchestrate_attestation(&args_json, &client, current_ts);
    
    assert!(res.is_ok(), "Expected OK, got {:?}", res);
    let output = res.unwrap();
    assert_eq!(output.nonce_account, "11111111111111111111111111111111");
    assert_eq!(output.fee_payer, "11111111111111111111111111111111");
    assert_eq!(output.nonce_authority, "11111111111111111111111111111111");
    assert_eq!(output.required_signatures, "fee_payer");
    assert!(output.memo_summary.starts_with("zc-depin|device_123"));
}

#[test]
fn test_uninitialized_nonce_account() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false);

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111",
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = ValidNonceClient {
        authority: [0u8; 32],
        state: 0, // Uninitialized
        truncate: false,
    };
    
    let res = orchestrate_attestation(&args_json, &client, 1000000);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("not initialized"));
}

#[test]
fn test_truncated_nonce_account() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false);

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111",
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = ValidNonceClient {
        authority: [0u8; 32],
        state: 1,
        truncate: true, // 79 bytes
    };
    
    let res = orchestrate_attestation(&args_json, &client, 1000000);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("too short"));
}

#[test]
fn test_nonce_authority_mismatch() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false);

    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111", // Decodes to [0u8; 32]
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = ValidNonceClient {
        authority: [1u8; 32], // Mismatch!
        state: 1,
        truncate: false,
    };
    
    let res = orchestrate_attestation(&args_json, &client, 1000000);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("does not match configured nonce_authority"));
}

#[test]
fn test_missing_config_errors() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false);

    let client = ValidNonceClient {
        authority: [0u8; 32],
        state: 1,
        truncate: false,
    };

    // Missing fee_payer
    let args_no_fee_payer = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();
    assert!(orchestrate_attestation(&args_no_fee_payer, &client, 1000000).unwrap_err().contains("Missing 'fee_payer'"));

    // Missing device_pubkey (and no per-sensor fallback)
    let args_no_pubkey = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "fee_payer": "11111111111111111111111111111111",
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();
    assert!(orchestrate_attestation(&args_no_pubkey, &client, 1000000).unwrap_err().contains("Missing device_pubkey"));
    
    // Missing nonce_account
    let args_no_nonce = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111"
        }
    }).to_string();
    assert!(orchestrate_attestation(&args_no_nonce, &client, 1000000).unwrap_err().contains("Missing 'nonce_account'"));
}

#[test]
fn test_per_sensor_pubkey_path() {
    let reading = SensorReading {
        sensor_id: "device_123".to_string(),
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    let (pk_hex, sig_hex) = generate_test_payload(&reading, false);

    // Note: missing device_pubkey, but has device_123_pubkey
    let args_json = serde_json::json!({
        "reading": reading,
        "signature_hex": sig_hex,
        "__config": {
            "device_123_pubkey": pk_hex,
            "fee_payer": "11111111111111111111111111111111",
            "nonce_account": "11111111111111111111111111111111"
        }
    }).to_string();

    let client = ValidNonceClient {
        authority: [0u8; 32],
        state: 1,
        truncate: false,
    };
    
    let res = orchestrate_attestation(&args_json, &client, 1000000);
    assert!(res.is_ok(), "Expected OK, got {:?}", res);
}

#[test]
fn test_sensor_id_character_restrictions() {
    let mut reading = SensorReading {
        sensor_id: "device!123".to_string(), // Invalid !
        value_str: "42.5".to_string(),
        unit: "celsius".to_string(),
        timestamp: 1000000,
    };
    
    let err = depin_attest::reading::validate_reading(&reading).unwrap_err();
    assert!(err.contains("alphanumeric characters, underscores, and hyphens"));
    
    reading.sensor_id = "device_123-abc".to_string(); // Valid
    assert!(depin_attest::reading::validate_reading(&reading).is_ok());
}
