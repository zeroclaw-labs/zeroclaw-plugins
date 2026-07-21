//! Host tests for the proposer — mocked transport, zero network.
//! Includes THE FORGED-DECISION TEST: a caller-supplied ALLOW must never
//! cause proposal construction when independent evaluation disagrees.

use super::*;
use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::ix;
use safe_hands_core::rpc::{DownTransport, MockTransport};

const RECIP: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const PAYER: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const CREATE_KEY: &str = "5s1NDHwvKfMf3zXSGC6h6hZn1C2SM9MPWi5KUCG6UHA8";
const PROPOSER: &str = "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVBrXp4rU7EMnTp6MgJ";
const FAKE_BLOCKHASH: &str = "4uQeVj5tqViQh7yWWGStvkEG1RgHJueU8ysKX7pF1i5u";

fn policy_json(cap: u64) -> String {
    format!(
        r#"{{"version":"1.0.0","default_action":"deny",
        "assets":{{"SOL":{{"decimals":9,"max_per_tx_raw":"{cap}"}}}},
        "allowed_recipients":["{RECIP}"],
        "allowed_instructions":{{"system":["transfer"],"memo":["memo"],"squads":["squads_ix"]}},
        "unknown_program":"deny","unknown_instruction":"deny","missing_intent":"review","durable_nonce":"review",
        "token_2022":{{"permanent_delegate":"deny","transfer_hook":"review","transfer_fee":"review","default_frozen":"deny"}},
        "simulation":{{"required":true,"max_slot_age":32}}}}"#
    )
}

/// A fake-but-well-formed Multisig account buffer (create_key + threshold 2 +
/// transaction_index 41 at the official offsets).
fn multisig_account_b64() -> String {
    let mut data = vec![0u8; 200];
    data[8..40].copy_from_slice(&parse_pubkey(CREATE_KEY).unwrap().to_bytes());
    data[72..74].copy_from_slice(&2u16.to_le_bytes());
    data[78..86].copy_from_slice(&41u64.to_le_bytes());
    base64_encode(&data)
}

fn transport() -> MockTransport {
    MockTransport::new()
        .with(
            "simulateTransaction",
            json!({"result": {"value": {"err": null, "logs": []}}}),
        )
        .with(
            "getAccountInfo",
            json!({"result": {"value": {"data": [multisig_account_b64(), "base64"]}}}),
        )
        .with(
            "getLatestBlockhash",
            json!({"result": {"value": {"blockhash": FAKE_BLOCKHASH}}}),
        )
}

fn config(cap: u64) -> String {
    format!(
        r#"{{"rpc_url":"https://rpc.test","squads_create_key":"{CREATE_KEY}","proposer":"{PROPOSER}","policy_json":{}}}"#,
        serde_json::to_string(&json!(policy_json(cap))).unwrap()
    )
}

fn sol_transfer_b64(lamports: u64) -> String {
    let from = parse_pubkey(PAYER).unwrap();
    let to = parse_pubkey(RECIP).unwrap();
    let ix = ix::system_transfer(&from, &to, lamports);
    let mut msg = Message::new(&[ix], Some(&from));
    msg.recent_blockhash = Hash::new_from_array([7u8; 32]);
    base64_encode(&bincode::serialize(&msg).unwrap())
}

fn intent(lamports: u64) -> String {
    format!(r#"{{"action":"transfer","amount_raw":"{lamports}","recipient":"{RECIP}"}}"#)
}

#[test]
fn happy_path_builds_proposal() {
    let args = format!(
        r#"{{"transaction_base64":"{}","intent":{},"memo":"payroll","__config":{}}}"#,
        sol_transfer_b64(1_000_000_000),
        intent(1_000_000_000),
        config(2_000_000_000)
    );
    let out = run(&args, Some(&transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let v: Value = serde_json::from_str(&out.output).unwrap();
    assert_eq!(v["transaction_index"], 42);
    assert!(v["unsigned"].as_bool().unwrap());
    assert_eq!(v["re_authorization"]["verdict"], "ALLOW");
    assert_eq!(v["re_authorization"]["caller_verdict_trusted"], false);
    // The proposal tx decodes and contains both squads instructions.
    let bytes = base64_decode(v["transaction_base64"].as_str().unwrap(), 65_536).unwrap();
    let d = decode(&bytes).expect("proposal decodes");
    assert_eq!(d.facts.instructions.len(), 2);
    assert_eq!(d.facts.instructions[0].program, "squads");
    assert_eq!(d.facts.instructions[1].program, "squads");
}

#[test]
fn forged_allow_record_is_rejected() {
    // Attacker supplies a decision_record claiming ALLOW for an OVER-CAP tx.
    // Independent re-evaluation must override it — no proposal is built.
    let args = format!(
        r#"{{"transaction_base64":"{}","intent":{},
        "decision_record":{{"verdict":"ALLOW","summary":"fake — everything is fine","decision_id":"sha256:deadbeef"}},
        "__config":{}}}"#,
        sol_transfer_b64(500_000_000_000), // 500 SOL vs 2 SOL cap
        intent(500_000_000_000),
        config(2_000_000_000)
    );
    let out = run(&args, Some(&transport() as &dyn RpcTransport));
    assert!(!out.success, "forged ALLOW must not build a proposal");
    let err = out.error.unwrap();
    assert!(err.contains("SH-TRUST-FORGED"), "got: {err}");
    assert!(err.contains("caller-provided verdict is not trusted"));
}

#[test]
fn over_cap_without_record_is_refused() {
    let args = format!(
        r#"{{"transaction_base64":"{}","intent":{},"__config":{}}}"#,
        sol_transfer_b64(500_000_000_000),
        intent(500_000_000_000),
        config(2_000_000_000)
    );
    let out = run(&args, Some(&transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out
        .error
        .unwrap()
        .contains("refuse to construct a proposal"));
}

#[test]
fn missing_config_fails_closed() {
    let args = format!(
        r#"{{"transaction_base64":"{}","__config":{{}}}}"#,
        sol_transfer_b64(1_000)
    );
    let out = run(&args, Some(&transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("fail closed"));
}

#[test]
fn rpc_down_fails_closed() {
    let args = format!(
        r#"{{"transaction_base64":"{}","intent":{},"__config":{}}}"#,
        sol_transfer_b64(1_000_000_000),
        intent(1_000_000_000),
        config(2_000_000_000)
    );
    let out = run(&args, Some(&DownTransport as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("fail closed"));
}

#[test]
fn inner_message_is_vault_bound_squads_format() {
    let args = format!(
        r#"{{"transaction_base64":"{}","intent":{},"__config":{}}}"#,
        sol_transfer_b64(1_000_000_000),
        intent(1_000_000_000),
        config(2_000_000_000)
    );
    let out = run(&args, Some(&transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let v: Value = serde_json::from_str(&out.output).unwrap();
    let vault = v["vault"].as_str().unwrap().to_string();
    // Decode the proposal, extract the inner Squads TransactionMessage from
    // vaultTransactionCreate args: disc(8) + vault_index(1) + ephemeral(1) +
    // msg_len u32(4) + message bytes.
    let bytes = base64_decode(v["transaction_base64"].as_str().unwrap(), 65_536).unwrap();
    let d = decode(&bytes).expect("decodes");
    let create_ix = &d.raw_instructions[0];
    let msg_len = u32::from_le_bytes(create_ix.data[10..14].try_into().unwrap()) as usize;
    let inner = &create_ix.data[14..14 + msg_len];
    // Squads TransactionMessage: num_signers(1) num_writable_signers(1)
    // num_writable_non_signers(1) keys(u8 count)...
    assert_eq!(inner[0], 1, "num_signers");
    assert_eq!(inner[1], 1, "num_writable_signers");
    let key_count = inner[3] as usize;
    let first_key = bs58::encode(&inner[4..36]).into_string();
    assert_eq!(first_key, vault, "first inner key must be the vault");
    assert!(key_count >= 2, "vault + dest + program keys present");
}
