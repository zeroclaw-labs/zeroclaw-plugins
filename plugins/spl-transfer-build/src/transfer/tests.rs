//! Host tests for the transfer builder — mocked transport, zero network.

use super::*;
use safe_hands_core::crypto::parse_pubkey;
use safe_hands_core::rpc::MockTransport;

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIP: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const PAYER: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const FAKE_BLOCKHASH: &str = "4uQeVj5tqViQh7yWWGStvkEG1RgHJueU8ysKX7pF1i5u";

fn policy_json() -> String {
    format!(
        r#"{{"version":"1.0.0","default_action":"deny",
        "assets":{{"SOL":{{"decimals":9,"max_per_tx_raw":"2000000000"}},"{USDC}":{{"decimals":6,"max_per_tx_raw":"25000000"}}}},
        "allowed_recipients":["{RECIP}"],
        "allowed_instructions":{{"system":["transfer"],"spl_token":["transfer","transfer_checked"],"associated_token":["create_idempotent"],"memo":["memo"]}},
        "unknown_program":"deny","unknown_instruction":"deny","missing_intent":"review","durable_nonce":"review",
        "token_2022":{{"permanent_delegate":"deny","transfer_hook":"review","transfer_fee":"review","default_frozen":"deny"}},
        "simulation":{{"required":true,"max_slot_age":32}}}}"#
    )
}

fn mint_account_b64(decimals: u8) -> String {
    let mut data = [0u8; 82];
    data[44] = decimals;
    base64_encode(&data)
}

fn devnet_transport() -> MockTransport {
    MockTransport::new()
        .with(
            "getLatestBlockhash",
            json!({"result": {"value": {"blockhash": FAKE_BLOCKHASH}}}),
        )
        .with(
            "getAccountInfo",
            json!({"result": {"value": {"data": [mint_account_b64(6), "base64"]}}}),
        )
}

fn config() -> String {
    format!(
        r#"{{"rpc_url":"https://rpc.test","fee_payer":"{PAYER}","policy_json":{}}}"#,
        serde_json::to_string(&json!(policy_json())).unwrap()
    )
}

#[test]
fn sol_transfer_builds_and_decodes() {
    let args = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"1000000000","__config":{}}}"#,
        config()
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let v: Value = serde_json::from_str(&out.output).unwrap();
    let tx_b64 = v["transaction_base64"].as_str().unwrap();
    let bytes = safe_hands_core::codec::base64_decode(tx_b64, 4096).unwrap();
    let d = decode(&bytes).expect("decodes");
    assert_eq!(d.facts.transfers.len(), 1);
    assert_eq!(d.facts.transfers[0].recipient, RECIP);
    assert_eq!(d.facts.transfers[0].amount_raw, 1_000_000_000);
    assert!(d.facts.transfers[0].mint.is_none());
    assert_eq!(v["intent"]["action"], "transfer");
    assert!(v["unsigned"].as_bool().unwrap());
}

#[test]
fn usdc_transfer_has_ata_and_transfer_checked() {
    let args = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"25000000","mint":"{USDC}","memo":"invoice-412","__config":{}}}"#,
        config()
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let v: Value = serde_json::from_str(&out.output).unwrap();
    let tx_b64 = v["transaction_base64"].as_str().unwrap();
    let bytes = safe_hands_core::codec::base64_decode(tx_b64, 4096).unwrap();
    let d = decode(&bytes).expect("decodes");
    assert_eq!(
        d.facts.instructions.len(),
        3,
        "ATA create + transferChecked + memo"
    );
    assert_eq!(d.facts.instructions[0].program, "associated_token");
    assert_eq!(
        d.facts.instructions[1].name.as_deref(),
        Some("transfer_checked")
    );
    let tr = &d.facts.transfers[0];
    assert_eq!(tr.mint.as_deref(), Some(USDC));
    assert_eq!(tr.amount_raw, 25_000_000);
    // destination is the recipient's ATA
    let expected_ata = ata_address(
        &parse_pubkey(RECIP).unwrap(),
        &ix::spl_token_program(),
        &parse_pubkey(USDC).unwrap(),
    );
    assert_eq!(tr.recipient, expected_ata.to_string());
    assert_eq!(v["intent"]["memo"], "invoice-412");
}

#[test]
fn missing_fee_payer_is_error() {
    let args = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"1000","__config":{{"rpc_url":"https://rpc.test"}}}}"#
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("fee_payer"));
}

#[test]
fn builder_refuses_over_cap_transfer() {
    let args = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"500000000","mint":"{USDC}","__config":{}}}"#,
        config()
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(!out.success, "builder must refuse what policy denies");
    assert!(out.error.unwrap().contains("violates the operator policy"));
}

#[test]
fn bad_inputs_error() {
    let t = devnet_transport();
    let bad_recip = format!(
        r#"{{"recipient":"nope","amount_raw":"1000","__config":{}}}"#,
        config()
    );
    assert!(!run(&bad_recip, Some(&t as &dyn RpcTransport)).success);
    let bad_amount = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"0","__config":{}}}"#,
        config()
    );
    assert!(!run(&bad_amount, Some(&t as &dyn RpcTransport)).success);
    let huge_memo = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"1000","memo":"{}","__config":{}}}"#,
        "x".repeat(600),
        config()
    );
    assert!(!run(&huge_memo, Some(&t as &dyn RpcTransport)).success);
}

/// THE SUITE INVARIANT: anything the builder emits must authorize ALLOW under
/// the same policy (roundtrip through the authorizer's own flow logic).
#[test]
fn build_then_authorize_roundtrip_allows() {
    use safe_hands_core::decode::decode as _;
    let args = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"25000000","mint":"{USDC}","memo":"invoice-412","__config":{}}}"#,
        config()
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let v: Value = serde_json::from_str(&out.output).unwrap();

    // Feed the built tx + intent into the authorizer's core evaluation path.
    let tx_b64 = v["transaction_base64"].as_str().unwrap();
    let bytes = safe_hands_core::codec::base64_decode(tx_b64, 4096).unwrap();
    let d = decode(&bytes).expect("decodes");
    let mut facts = d.facts.clone();
    facts.simulation_ok = true;
    facts.intent = Some(Intent {
        action: "spl_transfer".into(),
        mint: Some(USDC.into()),
        amount_raw: "25000000".into(),
        recipient: RECIP.into(),
    });
    let policy =
        policy_from_config(&serde_json::from_str::<HashMap<String, String>>(&config()).unwrap())
            .unwrap();
    let report = evaluate(&policy, &facts);
    assert_eq!(
        report.verdict,
        Verdict::Allow,
        "reasons: {:?}",
        report.reason_codes
    );
}
