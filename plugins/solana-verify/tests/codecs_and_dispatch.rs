//! Encoding helpers and the JSON tool dispatch.
//!
//! These are the plugin's trust boundary: an agent passes attacker-influenced
//! strings straight in, so every malformed input must produce a clean error
//! rather than a panic or a wrong-but-plausible value.

use serde_json::json;
use solana_verify::handler;
use solana_verify::verify::*;

// ── hex ─────────────────────────────────────────────────────────────────────

#[test]
fn hex_roundtrips() {
    let b = [0x00u8, 0x01, 0x7f, 0x80, 0xff];
    assert_eq!(from_hex(&to_hex(&b)).unwrap(), b);
}

#[test]
fn hex_accepts_0x_prefix() {
    assert_eq!(from_hex("0xdeadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn hex_accepts_uppercase() {
    assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn hex_accepts_empty_string() {
    assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
}

#[test]
fn hex_rejects_odd_length() {
    assert!(from_hex("abc").is_err());
}

#[test]
fn hex_rejects_non_hex_characters() {
    assert!(from_hex("zz").is_err());
    assert!(from_hex("12g4").is_err());
}

#[test]
fn to_hex_is_lowercase_and_zero_padded() {
    assert_eq!(to_hex(&[0x0a, 0xb0]), "0ab0");
}

#[test]
fn hex32_accepts_exactly_32_bytes() {
    let s = to_hex(&[7u8; 32]);
    assert_eq!(hex32(&s).unwrap(), [7u8; 32]);
}

#[test]
fn hex32_rejects_short_and_long_input() {
    assert!(hex32(&to_hex(&[1u8; 31])).is_err());
    assert!(hex32(&to_hex(&[1u8; 33])).is_err());
}

#[test]
fn hex32_rejects_garbage() {
    assert!(hex32("not-hex").is_err());
}

// ── base58 ──────────────────────────────────────────────────────────────────

#[test]
fn base58_roundtrips() {
    let b = [3u8; 32];
    assert_eq!(b58_decode(&b58_encode(&b)).unwrap(), b);
}

#[test]
fn base58_decodes_the_system_program_id_to_32_zero_bytes() {
    // The System Program is all-zero bytes; a good sanity anchor for the codec.
    assert_eq!(b58_32("11111111111111111111111111111111").unwrap(), [0u8; 32]);
}

#[test]
fn base58_rejects_ambiguous_characters() {
    // 0, O, I and l are not in the base58 alphabet.
    for bad in ["0000", "OOOO", "IIII", "llll"] {
        assert!(b58_decode(bad).is_err(), "{bad} must be rejected");
    }
}

#[test]
fn base58_rejects_non_alphanumeric() {
    assert!(b58_decode("hello world!").is_err());
}

#[test]
fn b58_32_rejects_wrong_length() {
    assert!(b58_32(&b58_encode(&[1u8; 31])).is_err());
    assert!(b58_32(&b58_encode(&[1u8; 33])).is_err());
}

#[test]
fn b58_32_accepts_a_real_solana_pubkey() {
    let pk = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let raw = b58_32(pk).unwrap();
    assert_eq!(b58_encode(&raw), pk);
}

#[test]
fn base58_and_hex_describe_the_same_bytes() {
    let pk = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let raw = b58_32(pk).unwrap();
    assert_eq!(hex32(&to_hex(&raw)).unwrap(), raw);
}

// ── JSON dispatch ───────────────────────────────────────────────────────────

#[test]
fn dispatch_rejects_malformed_json() {
    let (out, ok) = handler::run("{not json");
    assert!(!ok);
    assert!(out.contains("invalid JSON"));
}

#[test]
fn dispatch_rejects_missing_op() {
    let (out, ok) = handler::run(&json!({"leaf": "00"}).to_string());
    assert!(!ok);
    assert!(out.contains("missing 'op'"));
}

#[test]
fn dispatch_rejects_unknown_op() {
    let (out, ok) = handler::run(&json!({"op": "drain_wallet"}).to_string());
    assert!(!ok);
    assert!(out.contains("unknown op"));
}

#[test]
fn merkle_verify_op_reports_a_true_verdict() {
    let leaf = keccak256(b"a");
    let sib = keccak256(b"b");
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&leaf);
    buf[32..].copy_from_slice(&sib);
    let root = keccak256(&buf);
    let args = json!({
        "op": "merkle_verify",
        "leaf": to_hex(&leaf),
        "root": to_hex(&root),
        "proof": [{"hash": to_hex(&sib), "right": true}]
    })
    .to_string();
    let (out, ok) = handler::run(&args);
    assert!(ok);
    assert!(out.contains("\"valid\":true"));
    assert!(out.contains("\"depth\":1"));
    assert!(out.contains("keccak256"));
}

#[test]
fn merkle_verify_op_reports_a_false_verdict_as_a_successful_call() {
    // A forged proof is not an *error* — it's a successful tool call with a
    // truthful "valid: false". Agents must be able to tell those apart.
    let args = json!({
        "op": "merkle_verify",
        "leaf": to_hex(&[0u8; 32]),
        "root": to_hex(&[0xde; 32]),
        "proof": []
    })
    .to_string();
    let (out, ok) = handler::run(&args);
    assert!(ok, "a truthful negative verdict is a successful call");
    assert!(out.contains("\"valid\":false"));
}

#[test]
fn merkle_verify_op_rejects_a_bad_leaf_encoding() {
    let args = json!({"op": "merkle_verify", "leaf": "xyz", "root": to_hex(&[0u8; 32])}).to_string();
    let (_out, ok) = handler::run(&args);
    assert!(!ok);
}

#[test]
fn merkle_verify_op_rejects_a_malformed_proof_node() {
    let args = json!({
        "op": "merkle_verify",
        "leaf": to_hex(&[0u8; 32]),
        "root": to_hex(&[0u8; 32]),
        "proof": [{"hash": "not-hex", "right": true}]
    })
    .to_string();
    let (out, ok) = handler::run(&args);
    assert!(!ok);
    assert!(out.contains("proof node"));
}

#[test]
fn merkle_verify_op_defaults_a_missing_side_flag_to_left() {
    // `right` is #[serde(default)] = false; the verdict must reflect that, not error.
    let leaf = keccak256(b"a");
    let sib = keccak256(b"b");
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&sib);
    buf[32..].copy_from_slice(&leaf);
    let root = keccak256(&buf);
    let args = json!({
        "op": "merkle_verify",
        "leaf": to_hex(&leaf),
        "root": to_hex(&root),
        "proof": [{"hash": to_hex(&sib)}]
    })
    .to_string();
    let (out, ok) = handler::run(&args);
    assert!(ok);
    assert!(out.contains("\"valid\":true"));
}

#[test]
fn pubkey_decode_op_returns_raw_bytes() {
    let args = json!({"op": "pubkey_decode", "pubkey": "11111111111111111111111111111111"}).to_string();
    let (out, ok) = handler::run(&args);
    assert!(ok);
    assert!(out.contains(&to_hex(&[0u8; 32])));
}

#[test]
fn pubkey_decode_op_accepts_hex_as_well_as_base58() {
    let args = json!({"op": "pubkey_decode", "pubkey": to_hex(&[9u8; 32])}).to_string();
    let (out, ok) = handler::run(&args);
    assert!(ok);
    assert!(out.contains(&to_hex(&[9u8; 32])));
}

#[test]
fn pubkey_decode_op_rejects_a_short_key() {
    let args = json!({"op": "pubkey_decode", "pubkey": "abc"}).to_string();
    let (_out, ok) = handler::run(&args);
    assert!(!ok);
}

#[test]
fn pubkey_encode_op_roundtrips_with_decode() {
    let raw = to_hex(&[5u8; 32]);
    let (enc_out, ok) = handler::run(&json!({"op": "pubkey_encode", "bytes": raw}).to_string());
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&enc_out).unwrap();
    let pk = v["pubkey"].as_str().unwrap().to_string();
    let (dec_out, ok2) = handler::run(&json!({"op": "pubkey_decode", "pubkey": pk}).to_string());
    assert!(ok2);
    assert!(dec_out.contains(&raw));
}

#[test]
fn pubkey_encode_op_rejects_wrong_byte_count() {
    let (_out, ok) = handler::run(&json!({"op": "pubkey_encode", "bytes": to_hex(&[1u8; 31])}).to_string());
    assert!(!ok);
}

#[test]
fn ed25519_op_rejects_a_wrong_length_signature() {
    let args = json!({
        "op": "ed25519_verify",
        "pubkey": b58_encode(&[1u8; 32]),
        "message": to_hex(b"hi"),
        "signature": to_hex(&[0u8; 63])
    })
    .to_string();
    let (out, ok) = handler::run(&args);
    assert!(!ok);
    assert!(out.contains("64 bytes"));
}

#[test]
fn ed25519_op_reports_false_for_an_unverifiable_signature() {
    let args = json!({
        "op": "ed25519_verify",
        "pubkey": b58_encode(&[0u8; 32]),
        "message": to_hex(b"hi"),
        "signature": to_hex(&[0u8; 64])
    })
    .to_string();
    let (out, ok) = handler::run(&args);
    assert!(ok);
    assert!(out.contains("\"valid\":false"));
}

#[test]
fn schema_advertises_every_supported_op() {
    for op in ["merkle_verify", "ed25519_verify", "pubkey_decode", "pubkey_encode"] {
        assert!(handler::SCHEMA.contains(op), "schema must document {op}");
    }
}

#[test]
fn schema_is_valid_json() {
    let v: serde_json::Value = serde_json::from_str(handler::SCHEMA).expect("schema must parse");
    assert_eq!(v["type"], "object");
    assert!(v["required"].as_array().unwrap().contains(&json!("op")));
}
