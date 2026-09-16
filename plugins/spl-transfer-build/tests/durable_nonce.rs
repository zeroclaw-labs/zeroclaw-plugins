//! Durable-nonce mode: config/policy, instruction shape, adversarial final-byte
//! mutations, mode-confusion, and simulation. Mock transport only; no network.

mod common;

use std::{cell::RefCell, collections::HashMap};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nanosol::{
    inspect::decode_advance_nonce_account,
    instruction::TokenProgram,
    message::Transaction,
    pubkey::{Pubkey, LEGACY_TOKEN_PROGRAM_ID, RECENT_BLOCKHASHES_SYSVAR_ID, SYSTEM_PROGRAM_ID},
    reference::derive_payment_reference,
};
use serde_json::{json, Value};
use spl_transfer_build::{
    rpc::{RpcTransport, TransportError},
    transfer::{
        build_unsigned_bytes, execute_component_input, verify_final_bytes, BlockhashMode,
        TransferConfig, TransferOutput, VerificationPolicy,
    },
};

use common::{
    account_response, envelope, host_inject, mint_data, pubkey, simulation_response, valid_args,
    valid_config, MINT, RECIPIENT, SENDER,
};

// ---------- fixtures ----------

fn nonce_account_key() -> Pubkey {
    Pubkey::new([9u8; 32])
}

fn nonce_value() -> [u8; 32] {
    [0x22; 32]
}

/// 80-byte initialized, current-version nonce account data.
fn nonce_data(authority: &Pubkey, nonce: [u8; 32], lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&1u32.to_le_bytes()); // Versions::Current
    data.extend_from_slice(&1u32.to_le_bytes()); // State::Initialized
    data.extend_from_slice(authority.as_bytes());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

fn nonce_response(owner: Pubkey, data: &[u8]) -> String {
    envelope(
        4,
        json!({
            "context": {"slot": 1},
            "value": {
                "data": [STANDARD.encode(data), "base64"],
                "executable": false,
                "lamports": 1,
                "owner": owner.to_string(),
                "space": data.len()
            }
        }),
    )
}

fn durable_config() -> HashMap<String, String> {
    let mut config = valid_config();
    config.insert("blockhash_mode".to_string(), "durable_nonce".to_string());
    config.insert(
        "nonce_account_pubkey".to_string(),
        nonce_account_key().to_string(),
    );
    config
}

fn durable_policy() -> VerificationPolicy {
    let sender = pubkey(SENDER);
    let recipient = pubkey(RECIPIENT);
    let mint = pubkey(MINT);
    let reference = derive_payment_reference(&recipient, Some(&mint), "25.01", "412");
    VerificationPolicy {
        sender,
        recipient,
        mint,
        token_program: TokenProgram::Legacy,
        raw_amount: 25_010_000,
        decimals: 6,
        recent_blockhash: nonce_value(),
        reference: Some(reference),
        memo: Some("invoice 412".to_string()),
        mode: BlockhashMode::DurableNonce,
        nonce_account: Some(nonce_account_key()),
    }
}

fn durable_bytes() -> Vec<u8> {
    build_unsigned_bytes(&durable_policy()).expect("durable bytes")
}

/// Durable-aware mock: getAccountInfo id 1 -> mint, id 4 -> nonce; id 3
/// simulate. getLatestBlockhash intentionally unavailable (durable must not
/// call it).
struct DurableMock {
    mint: String,
    nonce: String,
    simulation: String,
    calls: RefCell<Vec<String>>,
}

impl DurableMock {
    fn valid() -> Self {
        Self {
            mint: account_response(LEGACY_TOKEN_PROGRAM_ID, &mint_data(6)),
            nonce: nonce_response(
                SYSTEM_PROGRAM_ID,
                &nonce_data(&pubkey(SENDER), nonce_value(), 5000),
            ),
            simulation: simulation_response(Value::Null),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn methods(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl RpcTransport for DurableMock {
    fn post(
        &self,
        _endpoint: &str,
        request_body: &str,
        _maximum_bytes: usize,
    ) -> Result<String, TransportError> {
        let request: Value =
            serde_json::from_str(request_body).map_err(|_| TransportError::Unavailable)?;
        let method = request["method"].as_str().unwrap_or_default().to_string();
        self.calls.borrow_mut().push(method.clone());
        match method.as_str() {
            "getAccountInfo" => match request["id"].as_u64() {
                Some(1) => Ok(self.mint.clone()),
                Some(4) => Ok(self.nonce.clone()),
                _ => Err(TransportError::Unavailable),
            },
            "simulateTransaction" => Ok(self.simulation.clone()),
            _ => Err(TransportError::Unavailable),
        }
    }
}

fn run(
    config: &HashMap<String, String>,
    mock: &DurableMock,
) -> spl_transfer_build::transfer::ToolResponse {
    execute_component_input(&host_inject(valid_args(), config), mock)
}

// ---------- config and mode ----------

#[test]
fn default_config_is_recent_mode() {
    let config = TransferConfig::from_section(&valid_config()).expect("recent config");
    assert_eq!(config.blockhash_mode(), BlockhashMode::Recent);
    assert_eq!(config.nonce_account(), None);
}

#[test]
fn explicit_recent_stays_recent() {
    let mut section = valid_config();
    section.insert("blockhash_mode".to_string(), "recent".to_string());
    let config = TransferConfig::from_section(&section).expect("recent config");
    assert_eq!(config.blockhash_mode(), BlockhashMode::Recent);
}

#[test]
fn durable_mode_requires_nonce_account() {
    let mut section = valid_config();
    section.insert("blockhash_mode".to_string(), "durable_nonce".to_string());
    assert!(TransferConfig::from_section(&section).is_err());
}

#[test]
fn durable_config_parses() {
    let config = TransferConfig::from_section(&durable_config()).expect("durable config");
    assert_eq!(config.blockhash_mode(), BlockhashMode::DurableNonce);
    assert_eq!(config.nonce_account(), Some(nonce_account_key()));
}

#[test]
fn invalid_mode_refuses() {
    let mut section = valid_config();
    section.insert("blockhash_mode".to_string(), "durable".to_string());
    assert!(TransferConfig::from_section(&section).is_err());
    section.insert("blockhash_mode".to_string(), String::new());
    assert!(TransferConfig::from_section(&section).is_err());
}

#[test]
fn recent_mode_rejects_nonce_only_config() {
    // nonce_account_pubkey present without durable mode is refused, not ignored.
    let mut section = valid_config();
    section.insert(
        "nonce_account_pubkey".to_string(),
        nonce_account_key().to_string(),
    );
    assert!(TransferConfig::from_section(&section).is_err());

    let mut recent = valid_config();
    recent.insert("blockhash_mode".to_string(), "recent".to_string());
    recent.insert(
        "nonce_account_pubkey".to_string(),
        nonce_account_key().to_string(),
    );
    assert!(TransferConfig::from_section(&recent).is_err());
}

#[test]
fn malformed_nonce_pubkey_refuses() {
    let mut section = valid_config();
    section.insert("blockhash_mode".to_string(), "durable_nonce".to_string());
    section.insert(
        "nonce_account_pubkey".to_string(),
        "not-a-valid-pubkey".to_string(),
    );
    assert!(TransferConfig::from_section(&section).is_err());
}

#[test]
fn model_arguments_cannot_choose_mode() {
    // An unknown top-level argument (deny_unknown_fields) is refused outright, so
    // the model cannot smuggle blockhash_mode / nonce_account_pubkey as args.
    let mut args = valid_args();
    args["blockhash_mode"] = json!("durable_nonce");
    let input = host_inject(args, &valid_config());
    let response = execute_component_input(&input, &common::MockTransport::valid(6));
    assert!(!response.success);
    assert_eq!(response.category, Some("invalid_arguments"));
}

#[test]
fn caller_config_cannot_choose_mode_or_nonce_account() {
    // The caller supplies a durable __config, but the host strips it and injects
    // the trusted recent section; the resolved run is recent.
    let mut args = valid_args();
    args["__config"] = json!({
        "blockhash_mode": "durable_nonce",
        "nonce_account_pubkey": nonce_account_key().to_string(),
    });
    let input = host_inject(args, &valid_config());
    let response = execute_component_input(&input, &common::MockTransport::valid(6));
    assert!(response.success, "recent run should succeed: {response:?}");
    let output: TransferOutput = serde_json::from_str(&response.output).expect("output");
    assert_eq!(output.blockhash_mode, "recent");
    assert!(output.nonce_account.is_none());
}

// ---------- authority and policy ----------

#[test]
fn durable_happy_path_returns_durable_output() {
    let mock = DurableMock::valid();
    let response = run(&durable_config(), &mock);
    assert!(response.success, "durable run failed: {response:?}");
    let output: TransferOutput = serde_json::from_str(&response.output).expect("output");
    assert_eq!(output.blockhash_mode, "durable_nonce");
    assert_eq!(output.nonce_account, Some(nonce_account_key().to_string()));
    assert_eq!(output.nonce, Some(Pubkey::new(nonce_value()).to_string()));
    assert!(output.last_valid_block_height.is_none());
    assert!(output.summary.contains("durable_nonce"));
    assert!(output.summary.contains("Execution warning"));
    assert!(output
        .summary
        .contains("external approval and signing required"));
    // Durable mode never calls getLatestBlockhash.
    assert!(!mock.methods().contains(&"getLatestBlockhash".to_string()));
    // The returned bytes decode with AdvanceNonceAccount at instruction zero.
    let bytes = STANDARD.decode(&output.transaction_base64).expect("bytes");
    let tx = Transaction::deserialize(&bytes).expect("tx");
    let advance = decode_advance_nonce_account(&tx.message, 0).expect("advance at 0");
    assert_eq!(advance.nonce_account, nonce_account_key());
    assert_eq!(advance.nonce_authority, pubkey(SENDER));
}

#[test]
fn separate_authority_refuses() {
    let mock = DurableMock {
        nonce: nonce_response(
            SYSTEM_PROGRAM_ID,
            &nonce_data(&pubkey(RECIPIENT), nonce_value(), 5000),
        ),
        ..DurableMock::valid()
    };
    let response = run(&durable_config(), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("nonce_authority_mismatch"));
}

#[test]
fn wrong_owner_nonce_account_refuses() {
    let mock = DurableMock {
        nonce: nonce_response(
            LEGACY_TOKEN_PROGRAM_ID,
            &nonce_data(&pubkey(SENDER), nonce_value(), 5000),
        ),
        ..DurableMock::valid()
    };
    let response = run(&durable_config(), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("invalid_nonce_state"));
}

#[test]
fn executable_nonce_account_refuses() {
    let data = nonce_data(&pubkey(SENDER), nonce_value(), 5000);
    let body = envelope(
        4,
        json!({
            "context": {"slot": 1},
            "value": {
                "data": [STANDARD.encode(&data), "base64"],
                "executable": true,
                "lamports": 1,
                "owner": SYSTEM_PROGRAM_ID.to_string(),
                "space": data.len()
            }
        }),
    );
    let mock = DurableMock {
        nonce: body,
        ..DurableMock::valid()
    };
    let response = run(&durable_config(), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("invalid_nonce_state"));
}

#[test]
fn uninitialized_nonce_account_refuses() {
    let mut data = nonce_data(&pubkey(SENDER), nonce_value(), 5000);
    data[4..8].copy_from_slice(&0u32.to_le_bytes()); // State::Uninitialized
    let mock = DurableMock {
        nonce: nonce_response(SYSTEM_PROGRAM_ID, &data),
        ..DurableMock::valid()
    };
    let response = run(&durable_config(), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("invalid_nonce_state"));
}

#[test]
fn truncated_nonce_account_refuses() {
    let data = nonce_data(&pubkey(SENDER), nonce_value(), 5000);
    let mock = DurableMock {
        nonce: nonce_response(SYSTEM_PROGRAM_ID, &data[..79]),
        ..DurableMock::valid()
    };
    let response = run(&durable_config(), &mock);
    assert!(!response.success);
    assert_eq!(response.category, Some("invalid_nonce_state"));
}

#[test]
fn nonce_account_swap_refuses() {
    // The exact bytes are valid, but the policy expects a different nonce account.
    let bytes = durable_bytes();
    let mut policy = durable_policy();
    policy.nonce_account = Some(Pubkey::new([123; 32]));
    assert!(verify_final_bytes(&bytes, &policy).is_err());
}

#[test]
fn sender_swap_refuses() {
    let bytes = durable_bytes();
    let mut policy = durable_policy();
    policy.sender = Pubkey::new([124; 32]);
    assert!(verify_final_bytes(&bytes, &policy).is_err());
}

#[test]
fn nonce_changed_between_policy_and_verification_refuses() {
    // Bytes built with nonce A; final verification runs against nonce B.
    let bytes = durable_bytes();
    let mut policy = durable_policy();
    policy.recent_blockhash = [0x77; 32];
    assert!(verify_final_bytes(&bytes, &policy).is_err());
}

// ---------- durable final-byte mutations ----------

fn mutate(bytes: &[u8], mutate: impl FnOnce(&mut Transaction)) -> Option<Vec<u8>> {
    let mut transaction = Transaction::deserialize(bytes).expect("valid durable fixture");
    mutate(&mut transaction);
    transaction.serialize().ok()
}

#[test]
fn durable_final_byte_mutations_all_fail_closed() {
    let policy = durable_policy();
    let bytes = durable_bytes();
    // Baseline: the unmutated durable transaction verifies.
    let baseline = verify_final_bytes(&bytes, &policy).expect("baseline durable verifies");

    type Mut = (&'static str, Box<dyn Fn(&mut Transaction)>);
    let mutations: Vec<Mut> = vec![
        (
            "move advance away from index zero",
            Box::new(|tx| tx.message.instructions.swap(0, 1)),
        ),
        (
            "remove advance",
            Box::new(|tx| {
                tx.message.instructions.remove(0);
            }),
        ),
        (
            "duplicate advance",
            Box::new(|tx| {
                let advance = tx.message.instructions[0].clone();
                tx.message.instructions.insert(1, advance);
            }),
        ),
        (
            "make nonce account read-only (drop from writable-nonsigner region)",
            Box::new(|tx| {
                // Increase readonly-unsigned count so the nonce key is seen readonly.
                tx.message.header.num_readonly_unsigned_accounts += 1;
            }),
        ),
        (
            "replace recent-blockhashes sysvar index with the mint",
            Box::new(|tx| {
                // Point the advance's sysvar slot at a different existing key.
                tx.message.instructions[0].account_indexes[1] = 0;
            }),
        ),
        (
            "make authority a non-signer (advance authority index -> non-signer key)",
            Box::new(|tx| {
                let last = u8::try_from(tx.message.account_keys.len() - 1).unwrap();
                tx.message.instructions[0].account_indexes[2] = last;
            }),
        ),
        (
            "add second signer",
            Box::new(|tx| {
                tx.message.header.num_required_signatures = 2;
                tx.signatures.push([0; 64]);
            }),
        ),
        (
            "change message blockhash",
            Box::new(|tx| tx.message.recent_blockhash[0] ^= 1),
        ),
        (
            "append unknown instruction",
            Box::new(|tx| {
                let mut extra = tx.message.instructions[0].clone();
                extra.account_indexes.clear();
                extra.data = vec![0xde, 0xad];
                tx.message.instructions.push(extra);
            }),
        ),
        (
            "reorder ATA and transfer",
            Box::new(|tx| tx.message.instructions.swap(1, 2)),
        ),
        (
            "alter amount",
            Box::new(|tx| tx.message.instructions[2].data[1] ^= 1),
        ),
        (
            "alter mint index",
            Box::new(|tx| tx.message.instructions[2].account_indexes[1] = 0),
        ),
        (
            "alter recipient (ATA owner index)",
            Box::new(|tx| tx.message.instructions[1].account_indexes[2] = 0),
        ),
        (
            "advance program id points elsewhere",
            Box::new(|tx| tx.message.instructions[0].program_id_index = 1),
        ),
        (
            "advance data mutated",
            Box::new(|tx| tx.message.instructions[0].data[0] ^= 1),
        ),
    ];

    for (name, mutation) in mutations {
        // A mutation that cannot even be re-serialized is also rejected.
        if let Some(mutated) = mutate(&bytes, mutation) {
            assert!(
                verify_final_bytes(&mutated, &policy).is_err(),
                "durable mutation accepted: {name}; baseline {baseline:?}"
            );
        }
    }

    // Wire-level mutations.
    let mut nonzero_signature = bytes.clone();
    nonzero_signature[1] = 1;
    assert!(verify_final_bytes(&nonzero_signature, &policy).is_err());

    let mut address_lookup = bytes.clone();
    *address_lookup.last_mut().expect("lookup count") = 1;
    assert!(verify_final_bytes(&address_lookup, &policy).is_err());

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify_final_bytes(&trailing, &policy).is_err());
}

#[test]
fn durable_change_nonce_account_key_is_rejected() {
    // Rewrite the nonce account key bytes in the message to a different pubkey.
    let bytes = durable_bytes();
    let policy = durable_policy();
    let mutated = mutate(&bytes, |tx| {
        let target = nonce_account_key();
        for key in &mut tx.message.account_keys {
            if *key == target {
                *key = Pubkey::new([200; 32]);
            }
        }
    })
    .expect("serializable");
    assert!(verify_final_bytes(&mutated, &policy).is_err());
}

#[test]
fn durable_replace_recent_blockhashes_sysvar_key_is_rejected() {
    let bytes = durable_bytes();
    let policy = durable_policy();
    let mutated = mutate(&bytes, |tx| {
        for key in &mut tx.message.account_keys {
            if *key == RECENT_BLOCKHASHES_SYSVAR_ID {
                *key = Pubkey::new([201; 32]);
            }
        }
    })
    .expect("serializable");
    assert!(verify_final_bytes(&mutated, &policy).is_err());
}

#[test]
fn durable_append_unreferenced_key_is_rejected() {
    let bytes = durable_bytes();
    let policy = durable_policy();
    let mutated = mutate(&bytes, |tx| {
        tx.message.account_keys.push(Pubkey::new([202; 32]));
        tx.message.header.num_readonly_unsigned_accounts += 1;
    })
    .expect("serializable");
    assert!(verify_final_bytes(&mutated, &policy).is_err());
}

#[test]
fn durable_reorder_static_keys_with_remapped_indexes_is_rejected() {
    // Swap two static keys and remap every index so the message stays internally
    // consistent but is non-canonical.
    let bytes = durable_bytes();
    let policy = durable_policy();
    let mutated = mutate(&bytes, |tx| {
        let len = tx.message.account_keys.len();
        // Swap the last two writable/readonly non-signer keys (safe indexes).
        let (a, b) = (
            u8::try_from(len - 2).unwrap(),
            u8::try_from(len - 1).unwrap(),
        );
        tx.message.account_keys.swap(usize::from(a), usize::from(b));
        for instruction in &mut tx.message.instructions {
            if instruction.program_id_index == a {
                instruction.program_id_index = b;
            } else if instruction.program_id_index == b {
                instruction.program_id_index = a;
            }
            for index in &mut instruction.account_indexes {
                if *index == a {
                    *index = b;
                } else if *index == b {
                    *index = a;
                }
            }
        }
    });
    // Either it fails to re-serialize cleanly or verification rejects it.
    if let Some(mutated) = mutated {
        assert!(verify_final_bytes(&mutated, &policy).is_err());
    }
}

// ---------- mode confusion ----------

fn recent_policy() -> VerificationPolicy {
    let mut policy = durable_policy();
    policy.mode = BlockhashMode::Recent;
    policy.nonce_account = None;
    policy
}

#[test]
fn recent_transaction_cannot_pass_durable_verification() {
    let recent = build_unsigned_bytes(&recent_policy()).expect("recent bytes");
    assert!(verify_final_bytes(&recent, &durable_policy()).is_err());
}

#[test]
fn durable_transaction_cannot_pass_recent_verification() {
    let durable = durable_bytes();
    assert!(verify_final_bytes(&durable, &recent_policy()).is_err());
}

#[test]
fn old_recent_blockhash_alone_does_not_trigger_durable_mode() {
    // A recent transaction verifies against the recent policy regardless of the
    // blockhash value; durable mode is chosen by policy, never inferred.
    let recent = build_unsigned_bytes(&recent_policy()).expect("recent bytes");
    assert!(verify_final_bytes(&recent, &recent_policy()).is_ok());
    assert!(verify_final_bytes(&recent, &durable_policy()).is_err());
}

#[test]
fn durable_blockhash_without_instruction_zero_refuses() {
    // Recent-style bytes (no advance) that happen to use the nonce value as the
    // blockhash must not pass durable verification.
    let mut recent = recent_policy();
    recent.recent_blockhash = nonce_value();
    let bytes = build_unsigned_bytes(&recent).expect("recent bytes with nonce blockhash");
    assert!(verify_final_bytes(&bytes, &durable_policy()).is_err());
}

// ---------- simulation ----------

fn durable_with_simulation(simulation: String) -> spl_transfer_build::transfer::ToolResponse {
    let mock = DurableMock {
        simulation,
        ..DurableMock::valid()
    };
    run(&durable_config(), &mock)
}

#[test]
fn valid_durable_simulation_passes() {
    let response = durable_with_simulation(simulation_response(Value::Null));
    assert!(response.success, "{response:?}");
}

#[test]
fn stale_nonce_simulation_error_refuses() {
    let response = durable_with_simulation(simulation_response(json!("BlockhashNotFound")));
    assert!(!response.success);
    assert_eq!(response.category, Some("simulation_failed"));
}

#[test]
fn later_instruction_failure_simulation_refuses() {
    let response = durable_with_simulation(simulation_response(
        json!({"InstructionError": [2, "Custom"]}),
    ));
    assert!(!response.success);
    assert_eq!(response.category, Some("simulation_failed"));
}

#[test]
fn malformed_simulation_response_refuses() {
    let response = durable_with_simulation("{ not json".to_string());
    assert!(!response.success);
    assert_eq!(response.category, Some("rpc_failure"));
}

#[test]
fn oversized_simulation_response_refuses() {
    let filler = "x".repeat(70 * 1024);
    let body = envelope(
        3,
        json!({"context": {"slot": 1}, "value": {"err": null, "logs": [filler]}}),
    );
    let response = durable_with_simulation(body);
    assert!(!response.success);
    assert_eq!(response.category, Some("rpc_failure"));
}

#[test]
fn unexpected_replacement_blockhash_refuses() {
    let body = envelope(
        3,
        json!({
            "context": {"slot": 1},
            "value": {
                "err": null,
                "logs": [],
                "replacementBlockhash": {"blockhash": "So11111111111111111111111111111111111111112", "lastValidBlockHeight": 42}
            }
        }),
    );
    let response = durable_with_simulation(body);
    assert!(!response.success);
    assert_eq!(response.category, Some("simulation_failed"));
}

#[test]
fn simulation_diagnostics_are_bounded() {
    let huge = "A".repeat(4000);
    let response = durable_with_simulation(simulation_response(json!(huge)));
    assert!(!response.success);
    let error = response.error.expect("error");
    assert!(
        error.len() <= 240,
        "error not bounded: {} bytes",
        error.len()
    );
}
