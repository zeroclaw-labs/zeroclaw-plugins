//! Host tests for the transfer builder — mocked transport, zero network.

use super::*;
use safe_hands_core::codec::{base64_encode, shortvec_decode};
use safe_hands_core::crypto::{parse_pubkey, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
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

fn mint_account_b64(decimals: u8, initialized: bool, length: usize) -> String {
    let mut data = vec![0u8; length];
    if length > 45 {
        data[44] = decimals;
        data[45] = u8::from(initialized);
    }
    safe_hands_core::codec::base64_encode(&data)
}

fn transport_with_mint(owner: &str, data: String) -> MockTransport {
    MockTransport::new()
        .with(
            "getLatestBlockhash",
            json!({"result": {"value": {"blockhash": FAKE_BLOCKHASH}}}),
        )
        .with(
            "getAccountInfo",
            json!({"result": {"value": {"owner": owner, "data": [data, "base64"]}}}),
        )
}

fn devnet_transport() -> MockTransport {
    transport_with_mint(TOKEN_PROGRAM, mint_account_b64(6, true, 82))
}

fn config_with_policy(policy: &str) -> String {
    format!(
        r#"{{"rpc_url":"https://rpc.test","fee_payer":"{PAYER}","policy_json":{}}}"#,
        serde_json::to_string(&json!(policy)).unwrap()
    )
}

fn config() -> String {
    config_with_policy(&policy_json())
}

fn spl_args(extra: &str, config: &str) -> String {
    format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"25000000","mint":"{USDC}"{extra},"__config":{config}}}"#
    )
}

// ── Durable nonce ───────────────────────────────────────────────────────────
//
// A recent blockhash dies in about ninety seconds, which is shorter than a
// human takes to approve a refund. These cover the mode that survives it.

const NONCE_ACCOUNT: &str = "So11111111111111111111111111111111111111112";
const NONCE_VALUE: &str = "6vJ8ZfBEYW4mYq8pFbYRhFdMkPHkKFcCq5dEo7QGF9Wr";

/// An 80-byte System nonce account: version 1, Initialized, given authority.
fn nonce_transport(authority: &str, nonce: &str) -> MockTransport {
    let mut data = vec![0u8; 80];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..8].copy_from_slice(&1u32.to_le_bytes());
    data[8..40].copy_from_slice(&bs58::decode(authority).into_vec().unwrap());
    data[40..72].copy_from_slice(&bs58::decode(nonce).into_vec().unwrap());
    MockTransport::new()
        .with(
            "getLatestBlockhash",
            json!({"result": {"value": {"blockhash": FAKE_BLOCKHASH}}}),
        )
        .with(
            "getAccountInfo",
            json!({"result": {"value": {
                "owner": safe_hands_core::crypto::SYSTEM_PROGRAM,
                "data": [base64_encode(&data), "base64"]
            }}}),
        )
}

/// Durable mode needs two independent operator opt-ins: `advance_nonce` in the
/// system instruction allowlist, and this exact nonce account in
/// `allowed_nonce_accounts`. Either one missing refuses the build.
fn nonce_policy_json() -> String {
    policy_json()
        .replace(
            r#""system":["transfer"]"#,
            r#""system":["transfer","advance_nonce"]"#,
        )
        .replace(
            r#""allowed_recipients""#,
            &format!(r#""allowed_nonce_accounts":["{NONCE_ACCOUNT}"],"allowed_recipients""#),
        )
}

fn nonce_config_with_policy(policy: &str) -> String {
    format!(
        r#"{{"rpc_url":"https://rpc.test","fee_payer":"{PAYER}","nonce_account":"{NONCE_ACCOUNT}","nonce_authority":"{PAYER}","policy_json":{}}}"#,
        serde_json::to_string(&json!(policy)).unwrap()
    )
}

fn nonce_config() -> String {
    nonce_config_with_policy(&nonce_policy_json())
}

#[test]
fn durable_mode_is_refused_until_the_operator_opts_in_twice() {
    // Default policy: `advance_nonce` is not an allowed instruction and no
    // nonce account is allowlisted. Configuring the builder is not enough.
    let out = run(
        &sol_args(&nonce_config_with_policy(&policy_json())),
        Some(&nonce_transport(PAYER, NONCE_VALUE) as &dyn RpcTransport),
    );
    assert!(!out.success);
    let error = out.error.unwrap();
    assert!(error.contains("SH-DENY-IX"), "{error}");
    assert!(error.contains("NONCE"), "{error}");

    // Allowlisting the instruction alone still leaves the nonce unapproved.
    let instruction_only = policy_json().replace(
        r#""system":["transfer"]"#,
        r#""system":["transfer","advance_nonce"]"#,
    );
    let out = run(
        &sol_args(&nonce_config_with_policy(&instruction_only)),
        Some(&nonce_transport(PAYER, NONCE_VALUE) as &dyn RpcTransport),
    );
    assert!(!out.success);
    assert!(out.error.unwrap().contains("SH-REVIEW-NONCE-009"));
}

fn sol_args(config: &str) -> String {
    format!(r#"{{"recipient":"{RECIP}","amount_raw":"1000000000","__config":{config}}}"#)
}

#[test]
fn durable_mode_pins_validity_to_the_nonce_and_puts_advance_first() {
    let out = run(
        &sol_args(&nonce_config()),
        Some(&nonce_transport(PAYER, NONCE_VALUE) as &dyn RpcTransport),
    );
    assert!(out.success, "error: {:?}", out.error);
    let value: Value = serde_json::from_str(&out.output).unwrap();
    assert_eq!(value["durable_nonce"], json!(true));

    let bytes = base64_decode(value["transaction_base64"].as_str().unwrap(), 4096).unwrap();
    let decoded = decode(&bytes).expect("durable transaction decodes");

    // The runtime requires AdvanceNonceAccount to be instruction 0, and the
    // decoder must agree that it landed there.
    assert!(decoded.facts.durable_nonce_used);
    assert!(decoded.facts.nonce_is_first_instruction);
    assert_eq!(
        decoded.facts.nonce_account.as_deref(),
        Some(NONCE_ACCOUNT),
        "the decoder must name the exact nonce account policy will check"
    );
    assert_eq!(
        decoded.facts.instructions[0].name.as_deref(),
        Some("advance_nonce")
    );

    // Validity is pinned to the nonce value, not to a recent blockhash.
    assert_eq!(decoded.blockhash, NONCE_VALUE);
    assert_ne!(decoded.blockhash, FAKE_BLOCKHASH);
    // The payment itself is unchanged and still unsigned.
    assert!(!decoded.facts.signed);
    assert_eq!(decoded.facts.transfers[0].recipient, RECIP);
}

#[test]
fn without_nonce_config_the_builder_is_unchanged() {
    let out = run(
        &sol_args(&config()),
        Some(&devnet_transport() as &dyn RpcTransport),
    );
    assert!(out.success, "error: {:?}", out.error);
    let value: Value = serde_json::from_str(&out.output).unwrap();
    assert_eq!(value["durable_nonce"], json!(false));
    let bytes = base64_decode(value["transaction_base64"].as_str().unwrap(), 4096).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert!(!decoded.facts.durable_nonce_used);
    assert_eq!(decoded.blockhash, FAKE_BLOCKHASH);
}

#[test]
fn blank_nonce_config_means_not_configured() {
    // Regression from a live run: clearing the nonce keys left "" behind and
    // every build failed on "invalid base58 pubkey".
    let cleared = format!(
        r#"{{"rpc_url":"https://rpc.test","fee_payer":"{PAYER}","nonce_account":"","nonce_authority":"  ","policy_json":{}}}"#,
        serde_json::to_string(&json!(policy_json())).unwrap()
    );
    let out = run(
        &sol_args(&cleared),
        Some(&devnet_transport() as &dyn RpcTransport),
    );
    assert!(out.success, "error: {:?}", out.error);
    let value: Value = serde_json::from_str(&out.output).unwrap();
    assert_eq!(value["durable_nonce"], json!(false));
}

#[test]
fn half_configured_nonce_mode_fails_closed() {
    let half = format!(
        r#"{{"rpc_url":"https://rpc.test","fee_payer":"{PAYER}","nonce_account":"{NONCE_ACCOUNT}","policy_json":{}}}"#,
        serde_json::to_string(&json!(policy_json())).unwrap()
    );
    let out = run(
        &sol_args(&half),
        Some(&nonce_transport(PAYER, NONCE_VALUE) as &dyn RpcTransport),
    );
    assert!(!out.success);
    assert!(out.error.unwrap().contains("fails closed"));
}

#[test]
fn a_nonce_account_with_the_wrong_authority_is_refused() {
    // The on-chain authority disagrees with the configured nonce_authority.
    let out = run(
        &sol_args(&nonce_config()),
        Some(&nonce_transport(RECIP, NONCE_VALUE) as &dyn RpcTransport),
    );
    assert!(!out.success);
    assert!(out.error.unwrap().contains("durable nonce unusable"));
}

#[test]
fn blank_optional_fields_are_treated_as_absent() {
    // Regression from a live agent run: the model emitted token_program: ""
    // and the build failed on a field the operator never set.
    let args = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"25000000","mint":"{USDC}","token_program":"","memo":"","__config":{}}}"#,
        config()
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
}

#[test]
fn sol_transfer_emits_canonical_unsigned_wire_and_roundtrips() {
    let args = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"1000000000","__config":{}}}"#,
        config()
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let value: Value = serde_json::from_str(&out.output).unwrap();
    let bytes = base64_decode(value["transaction_base64"].as_str().unwrap(), 4096).unwrap();
    let (signature_count, used) = shortvec_decode(&bytes).unwrap();
    assert_eq!(signature_count, 1);
    assert_eq!(&bytes[used..used + 64], &[0u8; 64]);
    let decoded = decode(&bytes).expect("canonical transaction decodes");
    assert!(decoded.has_signature_array);
    assert!(!decoded.facts.signed);
    assert_eq!(decoded.facts.transfers[0].recipient, RECIP);
    assert_eq!(decoded.facts.transfers[0].amount_raw, 1_000_000_000);
}

#[test]
fn spl_transfer_is_exact_idempotent_ata_plus_transfer_checked() {
    let args = spl_args(r#", "memo":"invoice-412""#, &config());
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let value: Value = serde_json::from_str(&out.output).unwrap();
    let bytes = base64_decode(value["transaction_base64"].as_str().unwrap(), 4096).unwrap();
    let decoded = decode(&bytes).expect("decodes");
    assert_eq!(decoded.facts.instructions.len(), 3);
    assert_eq!(decoded.facts.instructions[0].program, "associated_token");
    assert_eq!(
        decoded.facts.instructions[1].name.as_deref(),
        Some("transfer_checked")
    );
    let expected_ata = ata_address(
        &parse_pubkey(RECIP).unwrap(),
        &ix::spl_token_program(),
        &parse_pubkey(USDC).unwrap(),
    );
    assert_eq!(
        decoded.facts.transfers[0].recipient,
        expected_ata.to_string()
    );
}

#[test]
fn missing_and_malformed_policy_are_hard_errors() {
    let missing = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"1000","__config":{{"fee_payer":"{PAYER}"}}}}"#
    );
    let malformed_config =
        format!(r#"{{"rpc_url":"https://rpc.test","fee_payer":"{PAYER}","policy_json":"{{bad"}}"#);
    let malformed =
        format!(r#"{{"recipient":"{RECIP}","amount_raw":"1000","__config":{malformed_config}}}"#);
    for args in [missing, malformed] {
        let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
        assert!(!out.success);
        assert!(out.error.unwrap().contains("policy"));
    }
}

#[test]
fn review_policy_refuses_output() {
    let review_policy = policy_json()
        .replace(r#""memo":["memo"]"#, r#""memo":[]"#)
        .replace(
            r#""unknown_instruction":"deny"#,
            r#""unknown_instruction":"review"#,
        );
    let args = spl_args(
        r#", "memo":"needs-review""#,
        &config_with_policy(&review_policy),
    );
    let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("REVIEW"));
}

#[test]
fn arbitrary_and_token_2022_programs_are_refused() {
    let arbitrary = parse_pubkey(RECIP).unwrap().to_string();
    for program in [arbitrary.as_str(), TOKEN_2022_PROGRAM] {
        let args = spl_args(&format!(r#", "token_program":"{program}""#), &config());
        let out = run(&args, Some(&devnet_transport() as &dyn RpcTransport));
        assert!(!out.success);
        assert!(out.error.unwrap().contains("only classic SPL Token"));
    }
}

#[test]
fn forged_owner_uninitialized_and_truncated_mints_are_refused() {
    let args = spl_args("", &config());
    let cases = [
        transport_with_mint(TOKEN_2022_PROGRAM, mint_account_b64(6, true, 82)),
        transport_with_mint(TOKEN_PROGRAM, mint_account_b64(6, false, 82)),
        transport_with_mint(TOKEN_PROGRAM, mint_account_b64(6, true, 46)),
    ];
    for transport in cases {
        let out = run(&args, Some(&transport as &dyn RpcTransport));
        assert!(!out.success, "invalid mint account must fail");
    }
}

#[test]
fn malformed_coption_tags_are_refused() {
    let args = spl_args("", &config());
    for range in [0..4, 46..50] {
        let mut data = vec![0u8; 82];
        data[range].copy_from_slice(&2u32.to_le_bytes());
        data[44] = 6;
        data[45] = 1;
        let transport = transport_with_mint(TOKEN_PROGRAM, base64_encode(&data));
        let out = run(&args, Some(&transport as &dyn RpcTransport));
        assert!(!out.success, "malformed COption tag must fail");
    }
}

#[test]
fn null_malformed_and_error_mint_envelopes_are_refused() {
    let args = spl_args("", &config());
    let responses = [
        json!({"result":{"value":null}}),
        json!({"result":{"value":{"owner":TOKEN_PROGRAM,"data":"bad"}}}),
        json!({"error":{"code":-32000,"message":"rejected"}}),
    ];
    for response in responses {
        let transport = MockTransport::new().with("getAccountInfo", response).with(
            "getLatestBlockhash",
            json!({"result":{"value":{"blockhash":FAKE_BLOCKHASH}}}),
        );
        assert!(!run(&args, Some(&transport as &dyn RpcTransport)).success);
    }
}

#[test]
fn deny_and_bad_inputs_are_hard_errors() {
    let over_cap = format!(
        r#"{{"recipient":"{RECIP}","amount_raw":"500000000","mint":"{USDC}","__config":{}}}"#,
        config()
    );
    let out = run(&over_cap, Some(&devnet_transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("DENY"));

    let bad_recipient = format!(
        r#"{{"recipient":"nope","amount_raw":"1000","__config":{}}}"#,
        config()
    );
    assert!(
        !run(
            &bad_recipient,
            Some(&devnet_transport() as &dyn RpcTransport)
        )
        .success
    );
}
