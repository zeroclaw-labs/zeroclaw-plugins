use std::collections::HashMap;

use base64::Engine;
use solana_policy_firewall::firewall::{evaluate, DecisionReceipt};
use solana_policy_firewall::programs::{SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use solana_policy_firewall::rpc::{RpcAccount, RpcClient, SimulationResult};
use solana_policy_firewall::transaction::ADDRESS_LOOKUP_TABLE_PROGRAM;

#[derive(Default)]
struct MockRpc {
    accounts: HashMap<String, RpcAccount>,
    simulation_error: Option<String>,
    simulation_calls: usize,
}

impl RpcClient for MockRpc {
    fn get_account(&mut self, address: &str) -> Result<Option<RpcAccount>, String> {
        Ok(self.accounts.get(address).cloned())
    }

    fn simulate_transaction(
        &mut self,
        _transaction_base64: &str,
    ) -> Result<SimulationResult, String> {
        self.simulation_calls += 1;
        Ok(SimulationResult {
            error: self.simulation_error.clone(),
            units_consumed: Some(450),
        })
    }
}

#[derive(Clone)]
struct TestInstruction {
    program_index: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

fn key(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

fn key_bytes(value: &str) -> Vec<u8> {
    bs58::decode(value).into_vec().unwrap()
}

fn compact(value: usize) -> Vec<u8> {
    let mut value = value;
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
    bytes
}

fn system_transfer_data(lamports: u64) -> Vec<u8> {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

fn wire_instruction(bytes: &mut Vec<u8>, instruction: &TestInstruction) {
    bytes.push(instruction.program_index);
    bytes.extend(compact(instruction.accounts.len()));
    bytes.extend(&instruction.accounts);
    bytes.extend(compact(instruction.data.len()));
    bytes.extend(&instruction.data);
}

fn legacy_transaction(
    accounts: &[String],
    readonly_unsigned: u8,
    instructions: &[TestInstruction],
    signed: bool,
) -> String {
    let mut message = vec![1, 0, readonly_unsigned];
    message.extend(compact(accounts.len()));
    for account in accounts {
        message.extend(key_bytes(account));
    }
    message.extend([9u8; 32]);
    message.extend(compact(instructions.len()));
    for instruction in instructions {
        wire_instruction(&mut message, instruction);
    }

    let mut transaction = compact(1);
    transaction.extend(if signed { [7u8; 64] } else { [0u8; 64] });
    transaction.extend(message);
    base64::engine::general_purpose::STANDARD.encode(transaction)
}

fn v0_alt_transfer(fee_payer: &str, recipient: &str, table_address: &str) -> (String, RpcAccount) {
    let mut message = vec![0x80, 1, 0, 1];
    message.extend(compact(2));
    message.extend(key_bytes(fee_payer));
    message.extend(key_bytes(SYSTEM_PROGRAM));
    message.extend([9u8; 32]);
    message.extend(compact(1));
    wire_instruction(
        &mut message,
        &TestInstruction {
            program_index: 1,
            accounts: vec![0, 2],
            data: system_transfer_data(1_000_000),
        },
    );
    message.extend(compact(1));
    message.extend(key_bytes(table_address));
    message.extend(compact(1));
    message.push(0);
    message.extend(compact(0));

    let mut transaction = compact(1);
    transaction.extend([0u8; 64]);
    transaction.extend(message);

    let mut table_data = vec![0u8; 56];
    table_data.extend(key_bytes(recipient));
    (
        base64::engine::general_purpose::STANDARD.encode(transaction),
        RpcAccount {
            owner: ADDRESS_LOOKUP_TABLE_PROGRAM.to_string(),
            data: table_data,
        },
    )
}

fn base_policy(fee_payer: &str, recipient: &str, programs: &str) -> HashMap<String, String> {
    HashMap::from([
        (
            "rpc_url".to_string(),
            "https://api.devnet.solana.com".to_string(),
        ),
        ("allowed_fee_payers".to_string(), fee_payer.to_string()),
        ("allowed_signers".to_string(), fee_payer.to_string()),
        ("allowed_programs".to_string(), programs.to_string()),
        ("allowed_recipients".to_string(), recipient.to_string()),
        ("allowed_mints".to_string(), String::new()),
        ("max_sol_lamports".to_string(), "2000000".to_string()),
        ("max_token_amounts".to_string(), String::new()),
        ("max_priority_fee_lamports".to_string(), "0".to_string()),
        ("max_instructions".to_string(), "6".to_string()),
        ("max_writable_accounts".to_string(), "6".to_string()),
        ("allow_ata_creation".to_string(), "false".to_string()),
        ("require_unsigned".to_string(), "true".to_string()),
        ("require_simulation".to_string(), "true".to_string()),
        ("require_value_transfer".to_string(), "true".to_string()),
    ])
}

fn simple_sol_transfer(recipient: &str, signed: bool) -> (String, String) {
    let fee_payer = key(1);
    let accounts = vec![
        fee_payer.clone(),
        recipient.to_string(),
        SYSTEM_PROGRAM.to_string(),
    ];
    let transaction = legacy_transaction(
        &accounts,
        1,
        &[TestInstruction {
            program_index: 2,
            accounts: vec![0, 1],
            data: system_transfer_data(1_000_000),
        }],
        signed,
    );
    (fee_payer, transaction)
}

fn has_code(receipt: &DecisionReceipt, code: &str) -> bool {
    receipt
        .violations
        .iter()
        .any(|violation| violation.code == code)
}

#[test]
fn allows_exact_unsigned_sol_payment_after_simulation() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let policy = base_policy(&fee_payer, &recipient, "system");
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(receipt.allowed(), "{:?}", receipt.violations);
    assert_eq!(receipt.version.as_deref(), Some("legacy"));
    assert_eq!(receipt.transfers[0].amount_raw, "1000000");
    assert_eq!(receipt.transfers[0].recipient, recipient);
    assert_eq!(receipt.simulation.status, "passed");
    assert_eq!(rpc.simulation_calls, 1);
}

#[test]
fn prompt_cannot_redirect_to_an_unapproved_recipient() {
    let approved = key(2);
    let attacker = key(3);
    let (fee_payer, transaction) = simple_sol_transfer(&attacker, false);
    let policy = base_policy(&fee_payer, &approved, "system");
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(!receipt.allowed());
    assert!(has_code(&receipt, "recipient_not_allowed"));
    assert_eq!(receipt.simulation.status, "skipped-policy-denied");
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn signed_transaction_is_rejected_before_simulation() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, true);
    let policy = base_policy(&fee_payer, &recipient, "system");
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "transaction_already_signed"));
    assert_eq!(receipt.risk, "critical");
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn excessive_sol_amount_is_rejected() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let mut policy = base_policy(&fee_payer, &recipient, "system");
    policy.insert("max_sol_lamports".to_string(), "999999".to_string());
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "sol_limit_exceeded"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn simulation_failure_is_a_hard_denial() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let policy = base_policy(&fee_payer, &recipient, "system");
    let mut rpc = MockRpc {
        simulation_error: Some("BlockhashNotFound".to_string()),
        ..MockRpc::default()
    };

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "simulation_failed"));
    assert_eq!(receipt.simulation.status, "failed");
}

#[test]
fn unknown_config_key_fails_closed() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let mut policy = base_policy(&fee_payer, &recipient, "system");
    policy.insert("caller_override".to_string(), "allow".to_string());
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "invalid_policy_configuration"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn non_https_rpc_configuration_fails_closed() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let mut policy = base_policy(&fee_payer, &recipient, "system");
    policy.insert("rpc_url".to_string(), "http://localhost:8899".to_string());
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "invalid_policy_configuration"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn v0_lookup_recipient_is_resolved_and_checked() {
    let fee_payer = key(1);
    let recipient = key(2);
    let table_address = key(8);
    let (transaction, table) = v0_alt_transfer(&fee_payer, &recipient, &table_address);
    let policy = base_policy(&fee_payer, &recipient, "system");
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(table_address, table);

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(receipt.allowed(), "{:?}", receipt.violations);
    assert_eq!(receipt.version.as_deref(), Some("v0"));
    assert!(receipt.summary.contains("1 lookup table"));
}

#[test]
fn unresolved_lookup_table_fails_closed() {
    let fee_payer = key(1);
    let recipient = key(2);
    let table_address = key(8);
    let (transaction, _) = v0_alt_transfer(&fee_payer, &recipient, &table_address);
    let policy = base_policy(&fee_payer, &recipient, "system");
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "transaction_parse_failed"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn token_transfer_checked_resolves_mint_and_destination_owner() {
    let fee_payer = key(1);
    let recipient_owner = key(2);
    let source_account = key(3);
    let destination_account = key(4);
    let mint = key(5);
    let accounts = vec![
        fee_payer.clone(),
        source_account.clone(),
        destination_account.clone(),
        mint.clone(),
        TOKEN_PROGRAM.to_string(),
    ];
    let mut data = vec![12];
    data.extend_from_slice(&1_500_000u64.to_le_bytes());
    data.push(6);
    let transaction = legacy_transaction(
        &accounts,
        2,
        &[TestInstruction {
            program_index: 4,
            accounts: vec![1, 3, 2, 0],
            data,
        }],
        false,
    );
    let mut policy = base_policy(&fee_payer, &recipient_owner, "token");
    policy.insert("allowed_mints".to_string(), mint.clone());
    policy.insert("max_token_amounts".to_string(), format!("{mint}=2000000"));
    policy.insert("max_sol_lamports".to_string(), "0".to_string());

    let mut source_data = vec![0u8; 165];
    source_data[0..32].copy_from_slice(&key_bytes(&mint));
    source_data[32..64].copy_from_slice(&key_bytes(&fee_payer));
    let mut destination_data = vec![0u8; 165];
    destination_data[0..32].copy_from_slice(&key_bytes(&mint));
    destination_data[32..64].copy_from_slice(&key_bytes(&recipient_owner));
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(
        source_account,
        RpcAccount {
            owner: TOKEN_PROGRAM.to_string(),
            data: source_data,
        },
    );
    rpc.accounts.insert(
        destination_account,
        RpcAccount {
            owner: TOKEN_PROGRAM.to_string(),
            data: destination_data,
        },
    );

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(receipt.allowed(), "{:?}", receipt.violations);
    assert_eq!(receipt.transfers[0].asset, mint);
    assert_eq!(receipt.transfers[0].recipient, recipient_owner);
}

#[test]
fn token_authority_change_is_critical_even_when_program_is_allowlisted() {
    let fee_payer = key(1);
    let recipient = key(2);
    let token_account = key(3);
    let accounts = vec![fee_payer.clone(), token_account, TOKEN_PROGRAM.to_string()];
    let transaction = legacy_transaction(
        &accounts,
        1,
        &[TestInstruction {
            program_index: 2,
            accounts: vec![1, 0],
            data: vec![6],
        }],
        false,
    );
    let policy = base_policy(&fee_payer, &recipient, "token");
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "token_authority_change"));
    assert_eq!(receipt.risk, "critical");
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn token_2022_is_denied_until_extensions_are_proven() {
    let fee_payer = key(1);
    let recipient = key(2);
    let token_account = key(3);
    let accounts = vec![
        fee_payer.clone(),
        token_account,
        TOKEN_2022_PROGRAM.to_string(),
    ];
    let transaction = legacy_transaction(
        &accounts,
        1,
        &[TestInstruction {
            program_index: 2,
            accounts: vec![1, 0],
            data: vec![12, 0, 0, 0, 0, 0, 0, 0, 0, 6],
        }],
        false,
    );
    let policy = base_policy(&fee_payer, &recipient, "token-2022");
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "token_2022_extensions_not_supported"));
    assert_eq!(receipt.risk, "critical");
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn receipt_is_deterministic_for_identical_input_and_policy() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let policy = base_policy(&fee_payer, &recipient, "system");
    let mut first_rpc = MockRpc::default();
    let mut second_rpc = MockRpc::default();

    let first = evaluate(&transaction, &policy, &mut first_rpc);
    let second = evaluate(&transaction, &policy, &mut second_rpc);

    assert_eq!(first, second);
    assert_eq!(first.receipt_hash.len(), 64);
}

#[test]
fn malformed_base64_is_denied_without_rpc() {
    let mut rpc = MockRpc::default();
    let receipt = evaluate("%%%not-base64%%%", &HashMap::new(), &mut rpc);
    assert!(has_code(&receipt, "invalid_base64"));
    assert_eq!(rpc.simulation_calls, 0);
}
