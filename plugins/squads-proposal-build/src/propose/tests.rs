//! Host tests for strict Squads proposal construction.

use super::*;
use safe_hands_core::codec::{base64_decode, base64_encode, shortvec_decode};
use safe_hands_core::crypto::{parse_pubkey, TOKEN_PROGRAM};
use safe_hands_core::ix;
use safe_hands_core::rpc::{DownTransport, MockTransport};

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIP: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const CREATE_KEY: &str = "5s1NDHwvKfMf3zXSGC6h6hZn1C2SM9MPWi5KUCG6UHA8";
const OTHER_CREATE_KEY: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const PROPOSER: &str = "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVBrXp4rU7EMnTp6MgJ";
const FAKE_BLOCKHASH: &str = "4uQeVj5tqViQh7yWWGStvkEG1RgHJueU8ysKX7pF1i5u";
const MULTISIG_DISCRIMINATOR: [u8; 8] = [0xe0, 0x74, 0x79, 0xba, 0x44, 0xa1, 0x4f, 0xec];

fn policy_json(cap: u64) -> String {
    format!(
        r#"{{"version":"1.0.0","default_action":"deny",
        "assets":{{"SOL":{{"decimals":9,"max_per_tx_raw":"{cap}"}},"{USDC}":{{"decimals":6,"max_per_tx_raw":"25000000"}}}},
        "allowed_recipients":["{RECIP}"],
        "allowed_instructions":{{"system":["transfer"],"spl_token":["transfer_checked"],"memo":["memo"],"squads":["squads_ix"]}},
        "unknown_program":"deny","unknown_instruction":"deny","missing_intent":"review","durable_nonce":"review",
        "token_2022":{{"permanent_delegate":"deny","transfer_hook":"review","transfer_fee":"review","default_frozen":"deny"}},
        "simulation":{{"required":true,"max_slot_age":32}}}}"#
    )
}

fn config_with_policy(_cap: u64, policy: &str) -> String {
    format!(
        r#"{{"rpc_url":"https://rpc.test","squads_create_key":"{CREATE_KEY}","proposer":"{PROPOSER}","policy_json":{}}}"#,
        serde_json::to_string(&json!(policy)).unwrap()
    )
}

fn config(cap: u64) -> String {
    config_with_policy(cap, &policy_json(cap))
}

fn multisig_and_vault() -> (solana_pubkey::Pubkey, solana_pubkey::Pubkey) {
    let multisig = squads::multisig_pda(&parse_pubkey(CREATE_KEY).unwrap());
    let vault = squads::vault_pda(&multisig, 0);
    (multisig, vault)
}

fn multisig_account_b64(
    create_key: &str,
    proposer: &str,
    permissions: u8,
    transaction_index: u64,
) -> String {
    let (_, canonical_bump) = squads::multisig_pda_with_bump(&parse_pubkey(create_key).unwrap());
    multisig_account_b64_with_state(
        create_key,
        proposer,
        permissions,
        transaction_index,
        0,
        canonical_bump,
    )
}

fn multisig_account_b64_with_state(
    create_key: &str,
    proposer: &str,
    permissions: u8,
    transaction_index: u64,
    stale_transaction_index: u64,
    bump: u8,
) -> String {
    let mut data = MULTISIG_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&parse_pubkey(create_key).unwrap().to_bytes());
    // Autonomous multisig: config_authority unset. A Controlled multisig has a
    // key that can add members and change the threshold without a vote, which
    // would make the Initiate-only proposer check meaningless — the builder
    // refuses those outright, and `a_controlled_multisig_is_refused` covers it.
    data.extend_from_slice(&[0u8; 32]); // config_authority (Autonomous)
    data.extend_from_slice(&1u16.to_le_bytes()); // threshold
    data.extend_from_slice(&0u32.to_le_bytes()); // time_lock
    data.extend_from_slice(&transaction_index.to_le_bytes());
    data.extend_from_slice(&stale_transaction_index.to_le_bytes());
    data.push(0); // rent_collector None
    data.push(bump);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&parse_pubkey(proposer).unwrap().to_bytes());
    data.push(permissions);
    data.extend_from_slice(&[0u8; 32]); // reserved rent_collector allocation
    base64_encode(&data)
}

fn account_value(owner: &str, data: String) -> Value {
    json!({"result":{"value":{"owner":owner,"data":[data,"base64"]}}})
}

fn transport_with(
    simulation: Value,
    slot: Value,
    account: Value,
    _transaction_index: u64,
) -> MockTransport {
    MockTransport::new()
        .with("simulateTransaction", simulation)
        .with("getSlot", slot)
        .with("getAccountInfo", account)
        .with(
            "getLatestBlockhash",
            json!({"result":{"value":{"blockhash":FAKE_BLOCKHASH}}}),
        )
}

fn transport() -> MockTransport {
    transport_with(
        json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
        json!({"result":100}),
        account_value(
            squads::SQUADS_PROGRAM,
            multisig_account_b64(CREATE_KEY, PROPOSER, 1, 41),
        ),
        41,
    )
}

fn vault_transfer_bare_b64(lamports: u64) -> String {
    let (_, vault) = multisig_and_vault();
    let recipient = parse_pubkey(RECIP).unwrap();
    let instruction = ix::system_transfer(&vault, &recipient, lamports);
    let mut message = Message::new(&[instruction], Some(&vault));
    message.recent_blockhash = Hash::new_from_array([7u8; 32]);
    base64_encode(&bincode::serialize(&message).unwrap())
}

fn vault_transfer_b64(lamports: u64) -> String {
    let bare = base64_decode(&vault_transfer_bare_b64(lamports), 4096).unwrap();
    let decoded = decode(&bare).unwrap();
    unsigned_transaction_base64(&decoded.serialized_message, decoded.required_signatures).unwrap()
}

fn vault_spl_transfer_b64(amount: u64) -> String {
    let (_, vault) = multisig_and_vault();
    let recipient = parse_pubkey(RECIP).unwrap();
    let mint = parse_pubkey(USDC).unwrap();
    let token_program = ix::spl_token_program();
    let destination = safe_hands_core::crypto::ata_address(&recipient, &token_program, &mint);
    let source = solana_pubkey::Pubkey::new_from_array([7u8; 32]);
    let instruction = ix::transfer_checked(
        &token_program,
        &source,
        &mint,
        &destination,
        &vault,
        amount,
        6,
    );
    let mut message = Message::new(&[instruction], Some(&vault));
    message.recent_blockhash = Hash::new_from_array([7u8; 32]);
    let serialized = bincode::serialize(&message).unwrap();
    unsigned_transaction_base64(&serialized, 1).unwrap()
}

fn foreign_signer_transfer_b64(lamports: u64) -> String {
    let foreign = parse_pubkey(OTHER_CREATE_KEY).unwrap();
    let recipient = parse_pubkey(RECIP).unwrap();
    let instruction = ix::system_transfer(&foreign, &recipient, lamports);
    let mut message = Message::new(&[instruction], Some(&foreign));
    message.recent_blockhash = Hash::new_from_array([7u8; 32]);
    let serialized = bincode::serialize(&message).unwrap();
    unsigned_transaction_base64(&serialized, 1).unwrap()
}

fn intent(lamports: u64) -> String {
    format!(r#"{{"action":"transfer","amount_raw":"{lamports}","recipient":"{RECIP}"}}"#)
}

fn spl_intent(amount: u64) -> String {
    format!(
        r#"{{"action":"spl_transfer","mint":"{USDC}","amount_raw":"{amount}","recipient":"{RECIP}"}}"#
    )
}

fn args_with(tx: &str, lamports: u64, config: &str) -> String {
    format!(
        r#"{{"transaction_base64":"{tx}","intent":{},"memo":"payroll","__config":{config}}}"#,
        intent(lamports)
    )
}

#[test]
fn happy_path_emits_canonical_outer_wire() {
    let args = args_with(
        &vault_transfer_b64(1_000_000_000),
        1_000_000_000,
        &config(2_000_000_000),
    );
    let out = run(&args, Some(&transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let value: Value = serde_json::from_str(&out.output).unwrap();
    assert_eq!(value["transaction_index"], 42);
    let bytes = base64_decode(value["transaction_base64"].as_str().unwrap(), 65_536).unwrap();
    let (signature_count, used) = shortvec_decode(&bytes).unwrap();
    assert_eq!(signature_count, 1);
    assert_eq!(&bytes[used..used + 64], &[0u8; 64]);
    let decoded = decode(&bytes).expect("outer transaction decodes");
    assert!(decoded.has_signature_array);
    assert_eq!(decoded.facts.instructions.len(), 2);
    assert!(decoded
        .facts
        .instructions
        .iter()
        .all(|instruction| instruction.program == "squads"));
}

#[test]
fn inner_message_preserves_original_instructions_exactly() {
    let draft = vault_transfer_b64(1_000_000_000);
    let draft_decoded = decode(&base64_decode(&draft, 4096).unwrap()).unwrap();
    let (_, vault) = multisig_and_vault();
    let expected = squads::compile_inner_message(&draft_decoded.raw_instructions, &vault).unwrap();
    let args = args_with(&draft, 1_000_000_000, &config(2_000_000_000));
    let out = run(&args, Some(&transport() as &dyn RpcTransport));
    assert!(out.success, "error: {:?}", out.error);
    let value: Value = serde_json::from_str(&out.output).unwrap();
    let outer =
        decode(&base64_decode(value["transaction_base64"].as_str().unwrap(), 65_536).unwrap())
            .unwrap();
    let create = &outer.raw_instructions[0];
    let length = u32::from_le_bytes(create.data[10..14].try_into().unwrap()) as usize;
    assert_eq!(&create.data[14..14 + length], expected.as_slice());
}

#[test]
fn non_vault_and_signed_drafts_are_refused() {
    let foreign = args_with(
        &foreign_signer_transfer_b64(1_000),
        1_000,
        &config(2_000_000_000),
    );
    let out = run(&foreign, Some(&transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("vault-native"));

    let bare_args = args_with(
        &vault_transfer_bare_b64(1_000),
        1_000,
        &config(2_000_000_000),
    );
    let out = run(&bare_args, Some(&transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("canonical full transaction"));

    let canonical = base64_decode(&vault_transfer_b64(1_000), 4096).unwrap();
    let decoded = decode(&canonical).unwrap();
    let mut signed = unsigned_transaction_bytes(&decoded.serialized_message, 1).unwrap();
    signed[1] = 7;
    let signed_args = args_with(&base64_encode(&signed), 1_000, &config(2_000_000_000));
    assert!(!run(&signed_args, Some(&transport() as &dyn RpcTransport)).success);

    let mut noncanonical = vec![0x81, 0x00];
    noncanonical.extend_from_slice(&canonical[1..]);
    let noncanonical_args = args_with(&base64_encode(&noncanonical), 1_000, &config(2_000_000_000));
    assert!(!run(&noncanonical_args, Some(&transport() as &dyn RpcTransport)).success);
}

#[test]
fn forged_allow_and_every_other_decision_mismatch_are_refused() {
    let over_cap = format!(
        r#"{{"transaction_base64":"{}","intent":{},"decision_record":{{"verdict":"ALLOW"}},"__config":{}}}"#,
        vault_transfer_b64(500_000_000_000),
        intent(500_000_000_000),
        config(2_000_000_000)
    );
    let out = run(&over_cap, Some(&transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("SH-TRUST-FORGED"));

    for decision_record in [json!({"verdict":"DENY"}), json!({"note":"missing verdict"})] {
        let mismatch = format!(
            r#"{{"transaction_base64":"{}","intent":{},"decision_record":{},"__config":{}}}"#,
            vault_transfer_b64(1_000),
            intent(1_000),
            decision_record,
            config(2_000_000_000)
        );
        let out = run(&mismatch, Some(&transport() as &dyn RpcTransport));
        assert!(!out.success);
        assert!(out.error.unwrap().contains("SH-TRUST-MISMATCH"));
    }

    let review_policy = policy_json(2_000_000_000)
        .replace(r#""system":["transfer"]"#, r#""system":[]"#)
        .replace(
            r#""unknown_instruction":"deny"#,
            r#""unknown_instruction":"review"#,
        );
    let review = args_with(
        &vault_transfer_b64(1_000),
        1_000,
        &config_with_policy(2_000_000_000, &review_policy),
    );
    let out = run(&review, Some(&transport() as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("REVIEW"));
}

#[test]
fn inner_squads_instruction_is_denied_even_when_policy_allows_it() {
    let (multisig, vault) = multisig_and_vault();
    let recipient = parse_pubkey(RECIP).unwrap();
    let hidden_proposal = solana_pubkey::Pubkey::new_from_array([9u8; 32]);
    let instructions = vec![
        ix::system_transfer(&vault, &recipient, 1_000),
        // This official Squads instruction uses only the vault as signer. It
        // would satisfy the vault-native signer checks and is deliberately
        // allowlisted by policy_json, so the non-relaxable v0.1 denial is the
        // boundary under test.
        squads::proposal_create(&multisig, &hidden_proposal, &vault, &vault, 7, false),
    ];
    let mut message = Message::new(&instructions, Some(&vault));
    message.recent_blockhash = Hash::new_from_array([7u8; 32]);
    let transaction = unsigned_transaction_base64(&bincode::serialize(&message).unwrap(), 1)
        .expect("canonical transaction");
    let args = args_with(&transaction, 1_000, &config(2_000_000_000));
    let rpc = transport();
    let out = run(&args, Some(&rpc as &dyn RpcTransport));

    assert!(!out.success);
    assert!(out.output.is_empty());
    assert!(out.error.unwrap().contains("SH-DENY-SQUADS-INNER-063"));
    assert!(
        rpc.calls()
            .iter()
            .all(|(method, _)| method != "getAccountInfo"),
        "proposal construction must stop before loading multisig state"
    );
}

#[test]
fn proposer_requires_strict_classic_mint_proof() {
    let mut malformed_mint = vec![0u8; 82];
    malformed_mint[0..4].copy_from_slice(&2u32.to_le_bytes());
    malformed_mint[44] = 6;
    malformed_mint[45] = 1;
    let rpc = transport_with(
        json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
        json!({"result":100}),
        account_value(TOKEN_PROGRAM, base64_encode(&malformed_mint)),
        41,
    );
    let args = format!(
        r#"{{"transaction_base64":"{}","intent":{},"__config":{}}}"#,
        vault_spl_transfer_b64(1_000),
        spl_intent(1_000),
        config(2_000_000_000),
    );
    let out = run(&args, Some(&rpc as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("SH-UNKNOWN-MINT-EVIDENCE-053"));

    let mut wrong_decimals = vec![0u8; 82];
    wrong_decimals[44] = 9;
    wrong_decimals[45] = 1;
    let rpc = transport_with(
        json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
        json!({"result":100}),
        account_value(TOKEN_PROGRAM, base64_encode(&wrong_decimals)),
        41,
    );
    let out = run(&args, Some(&rpc as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out
        .error
        .unwrap()
        .contains("inconsistent with TransferChecked"));
}

#[test]
fn strict_simulation_rejects_missing_fields_stale_and_rpc_errors() {
    let account = account_value(
        squads::SQUADS_PROGRAM,
        multisig_account_b64(CREATE_KEY, PROPOSER, 1, 41),
    );
    let cases = [
        (
            json!({"result":{"context":{"slot":100},"value":{}}}),
            json!({"result":100}),
        ),
        (
            json!({"result":{"value":{"err":null}}}),
            json!({"result":100}),
        ),
        (
            json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
            json!({"result":null}),
        ),
        (
            json!({"error":{"code":-32000,"message":"rejected"}}),
            json!({"result":100}),
        ),
        (
            json!({"result":{"context":{"slot":1},"value":{"err":null}}}),
            json!({"result":100}),
        ),
    ];
    let args = args_with(&vault_transfer_b64(1_000), 1_000, &config(2_000_000_000));
    for (simulation, slot) in cases {
        let rpc = transport_with(simulation, slot, account.clone(), 41);
        assert!(!run(&args, Some(&rpc as &dyn RpcTransport)).success);
    }

    // A definite simulation failure is custody-blocking even if a policy does
    // not independently require simulation evidence.
    let optional_simulation_policy =
        policy_json(2_000_000_000).replace(r#""required":true"#, r#""required":false"#);
    let optional_args = args_with(
        &vault_transfer_b64(1_000),
        1_000,
        &config_with_policy(2_000_000_000, &optional_simulation_policy),
    );
    let rpc = transport_with(
        json!({"result":{"context":{"slot":100},"value":{"err":{"InstructionError":[0,"Custom"]}}}}),
        json!({"result":100}),
        account,
        41,
    );
    let out = run(&optional_args, Some(&rpc as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("simulation failed"));
}

#[test]
fn multisig_owner_discriminator_create_key_and_rpc_envelope_are_strict() {
    let mut bad_discriminator =
        base64_decode(&multisig_account_b64(CREATE_KEY, PROPOSER, 1, 41), 65_536).unwrap();
    bad_discriminator[0] ^= 1;
    let accounts = [
        account_value(
            TOKEN_PROGRAM,
            multisig_account_b64(CREATE_KEY, PROPOSER, 1, 41),
        ),
        account_value(squads::SQUADS_PROGRAM, base64_encode(&bad_discriminator)),
        account_value(
            squads::SQUADS_PROGRAM,
            multisig_account_b64(OTHER_CREATE_KEY, PROPOSER, 1, 41),
        ),
        json!({"result":{"value":null}}),
        json!({"error":{"code":-32000,"message":"rejected"}}),
    ];
    let args = args_with(&vault_transfer_b64(1_000), 1_000, &config(2_000_000_000));
    for account in accounts {
        let rpc = transport_with(
            json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
            json!({"result":100}),
            account,
            41,
        );
        assert!(!run(&args, Some(&rpc as &dyn RpcTransport)).success);
    }
}

#[test]
fn canonical_multisig_bump_and_stale_index_are_required() {
    let (_, canonical_bump) = squads::multisig_pda_with_bump(&parse_pubkey(CREATE_KEY).unwrap());
    let invalid_accounts = [
        multisig_account_b64_with_state(
            CREATE_KEY,
            PROPOSER,
            1,
            41,
            0,
            canonical_bump.wrapping_add(1),
        ),
        multisig_account_b64_with_state(CREATE_KEY, PROPOSER, 1, 41, 42, canonical_bump),
    ];
    let args = args_with(&vault_transfer_b64(1_000), 1_000, &config(2_000_000_000));
    for account_data in invalid_accounts {
        let rpc = transport_with(
            json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
            json!({"result":100}),
            account_value(squads::SQUADS_PROGRAM, account_data),
            41,
        );
        assert!(!run(&args, Some(&rpc as &dyn RpcTransport)).success);
    }
}

#[test]
fn proposer_must_be_member_with_exact_initiate_permission() {
    let absent = parse_pubkey(OTHER_CREATE_KEY).unwrap().to_string();
    for account_data in [
        multisig_account_b64(CREATE_KEY, &absent, 1, 41),
        multisig_account_b64(CREATE_KEY, PROPOSER, 3, 41),
        multisig_account_b64(CREATE_KEY, PROPOSER, 0, 41),
    ] {
        let rpc = transport_with(
            json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
            json!({"result":100}),
            account_value(squads::SQUADS_PROGRAM, account_data),
            41,
        );
        let args = args_with(&vault_transfer_b64(1_000), 1_000, &config(2_000_000_000));
        assert!(!run(&args, Some(&rpc as &dyn RpcTransport)).success);
    }
}

#[test]
fn transaction_index_overflow_and_rpc_down_refuse() {
    let overflow = transport_with(
        json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
        json!({"result":100}),
        account_value(
            squads::SQUADS_PROGRAM,
            multisig_account_b64(CREATE_KEY, PROPOSER, 1, u64::MAX),
        ),
        u64::MAX,
    );
    let args = args_with(&vault_transfer_b64(1_000), 1_000, &config(2_000_000_000));
    let out = run(&args, Some(&overflow as &dyn RpcTransport));
    assert!(!out.success);
    assert!(out.error.unwrap().contains("overflow"));
    assert!(!run(&args, Some(&DownTransport as &dyn RpcTransport)).success);
}

#[test]
fn a_controlled_multisig_is_refused() {
    // The same account the happy path uses, with only config_authority set.
    // Building the bytes by hand here would test the parser, not the rule —
    // an earlier draft did exactly that and refused for a malformed-account
    // reason instead of the one under test.
    //
    // A Controlled multisig's config_authority can call multisig_add_member
    // and multisig_change_threshold with no vote, so an Initiate-only proposer
    // proves nothing about what the agent can approve.
    let mut data = base64_decode(&multisig_account_b64(CREATE_KEY, PROPOSER, 1, 41), 4096).unwrap();
    // discriminator(8) + create_key(32) => config_authority occupies 40..72
    data[40..72].copy_from_slice(&[8u8; 32]);

    let rpc = transport_with(
        json!({"result":{"context":{"slot":100},"value":{"err":null}}}),
        json!({"result":100}),
        account_value(squads::SQUADS_PROGRAM, base64_encode(&data)),
        41,
    );
    let args = args_with(
        &vault_transfer_b64(1_000_000_000),
        1_000_000_000,
        &config(2_000_000_000),
    );
    let out = run(&args, Some(&rpc as &dyn RpcTransport));

    assert!(
        !out.success,
        "a Controlled multisig must be refused, not proposed against"
    );
    let rendered = format!("{:?}", out.error);
    assert!(
        rendered.contains("Controlled"),
        "the refusal must name the reason: {rendered}"
    );
}
