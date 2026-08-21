use base64::Engine;
use serde_json::json;
use solana_tx_audit::*;

fn key(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

fn compact(n: usize, out: &mut Vec<u8>) {
    out.push(n as u8);
}

fn transfer_tx(recipient: &str) -> String {
    let signer = key(1);
    let mut b = Vec::new();
    compact(1, &mut b);
    b.extend([0u8; 64]);
    b.extend([1, 0, 1]);
    compact(3, &mut b);
    for a in [&signer, recipient, SYSTEM_PROGRAM] {
        b.extend(bs58::decode(a).into_vec().unwrap());
    }
    b.extend([9u8; 32]);
    compact(1, &mut b);
    b.push(2);
    compact(2, &mut b);
    b.extend([0, 1]);
    let mut data = Vec::new();
    data.extend(2u32.to_le_bytes());
    data.extend(1u64.to_le_bytes());
    compact(data.len(), &mut b);
    b.extend(data);
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[test]
fn plugin_crate_reexports_audit_core() {
    let recipient = key(2);
    let args = json!({
        "transaction_base64": transfer_tx(&recipient),
        "declared_intent": {"action": "transfer", "expected_recipient": recipient},
        "options": {"simulate": false}
    });
    let out = audit_json(&args.to_string(), None).unwrap();
    assert!(out.contains("\"verdict\":\"GREEN\""));
}

#[test]
fn parameters_schema_is_valid_json() {
    let schema: serde_json::Value = serde_json::from_str(&parameters_schema_json()).unwrap();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("transaction_base64")));
}
