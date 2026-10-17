use std::collections::HashMap;

use base64::Engine;
use solana_policy_firewall::firewall::{evaluate, DecisionReceipt};
use solana_policy_firewall::programs::{
    ASSOCIATED_TOKEN_PROGRAM, COMPUTE_BUDGET_PROGRAM, RECENT_BLOCKHASHES_SYSVAR, SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
};
use solana_policy_firewall::rpc::{RpcAccount, RpcClient, SimulationResult};
use solana_policy_firewall::transaction::ADDRESS_LOOKUP_TABLE_PROGRAM;

struct MockRpc {
    accounts: HashMap<String, RpcAccount>,
    simulation_error: Option<String>,
    simulation_slot: Option<u64>,
    simulation_calls: usize,
    fee_lamports: Option<u64>,
    fee_calls: usize,
    rent_lamports: u64,
    rent_calls: usize,
}

impl Default for MockRpc {
    fn default() -> Self {
        Self {
            accounts: HashMap::new(),
            simulation_error: None,
            simulation_slot: Some(424_242),
            simulation_calls: 0,
            fee_lamports: Some(5_000),
            fee_calls: 0,
            rent_lamports: 2_039_280,
            rent_calls: 0,
        }
    }
}

impl RpcClient for MockRpc {
    fn get_account(&mut self, address: &str) -> Result<Option<RpcAccount>, String> {
        Ok(self.accounts.get(address).cloned())
    }

    fn get_fee_for_message(&mut self, _message_base64: &str) -> Result<Option<u64>, String> {
        self.fee_calls += 1;
        Ok(self.fee_lamports)
    }

    fn get_minimum_balance_for_rent_exemption(&mut self, _data_len: usize) -> Result<u64, String> {
        self.rent_calls += 1;
        Ok(self.rent_lamports)
    }

    fn simulate_transaction(
        &mut self,
        _transaction_base64: &str,
    ) -> Result<SimulationResult, String> {
        self.simulation_calls += 1;
        Ok(SimulationResult {
            error: self.simulation_error.clone(),
            units_consumed: Some(450),
            slot: self.simulation_slot,
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
    legacy_transaction_with_blockhash(
        accounts,
        readonly_unsigned,
        instructions,
        signed,
        &[9u8; 32],
    )
}

fn legacy_transaction_with_blockhash(
    accounts: &[String],
    readonly_unsigned: u8,
    instructions: &[TestInstruction],
    signed: bool,
    blockhash: &[u8; 32],
) -> String {
    let mut message = vec![1, 0, readonly_unsigned];
    message.extend(compact(accounts.len()));
    for account in accounts {
        message.extend(key_bytes(account));
    }
    message.extend(blockhash);
    message.extend(compact(instructions.len()));
    for instruction in instructions {
        wire_instruction(&mut message, instruction);
    }

    let mut transaction = compact(1);
    transaction.extend(if signed { [7u8; 64] } else { [0u8; 64] });
    transaction.extend(message);
    base64::engine::general_purpose::STANDARD.encode(transaction)
}

fn nonce_account_data(authority: &str, nonce: &[u8; 32], fee: u64) -> Vec<u8> {
    let mut data = 1u32.to_le_bytes().to_vec();
    data.extend(1u32.to_le_bytes());
    data.extend(key_bytes(authority));
    data.extend(nonce);
    data.extend(fee.to_le_bytes());
    assert_eq!(data.len(), 80);
    data
}

fn durable_nonce_transfer(
    authority: &str,
    nonce_account: &str,
    recipient: &str,
    nonce: &[u8; 32],
    advance_first: bool,
) -> String {
    let sysvar = "SysvarRecentB1ockHashes11111111111111111111".to_string();
    let accounts = vec![
        authority.to_string(),
        nonce_account.to_string(),
        recipient.to_string(),
        sysvar,
        SYSTEM_PROGRAM.to_string(),
    ];
    let advance = TestInstruction {
        program_index: 4,
        accounts: vec![1, 3, 0],
        data: 4u32.to_le_bytes().to_vec(),
    };
    let transfer = TestInstruction {
        program_index: 4,
        accounts: vec![0, 2],
        data: system_transfer_data(1_000_000),
    };
    let instructions = if advance_first {
        vec![advance, transfer]
    } else {
        vec![transfer, advance]
    };
    legacy_transaction_with_blockhash(&accounts, 2, &instructions, false, nonce)
}

fn v0_durable_ata_transfer_checked(
    authority: &str,
    nonce_account: &str,
    recipient_owner: &str,
    source_account: &str,
    destination_ata: &str,
    mint: &str,
    nonce: &[u8; 32],
) -> String {
    let accounts = vec![
        authority.to_string(),
        nonce_account.to_string(),
        destination_ata.to_string(),
        source_account.to_string(),
        recipient_owner.to_string(),
        mint.to_string(),
        RECENT_BLOCKHASHES_SYSVAR.to_string(),
        SYSTEM_PROGRAM.to_string(),
        TOKEN_PROGRAM.to_string(),
        ASSOCIATED_TOKEN_PROGRAM.to_string(),
    ];
    let mut transfer_data = vec![12];
    transfer_data.extend_from_slice(&1_500_000u64.to_le_bytes());
    transfer_data.push(6);
    let instructions = [
        TestInstruction {
            program_index: 7,
            accounts: vec![1, 6, 0],
            data: 4u32.to_le_bytes().to_vec(),
        },
        TestInstruction {
            program_index: 9,
            accounts: vec![0, 2, 4, 5, 7, 8],
            data: vec![1],
        },
        TestInstruction {
            program_index: 8,
            accounts: vec![3, 5, 2, 0],
            data: transfer_data,
        },
    ];

    let mut message = vec![0x80, 1, 0, 6];
    message.extend(compact(accounts.len()));
    for account in accounts {
        message.extend(key_bytes(&account));
    }
    message.extend(nonce);
    message.extend(compact(instructions.len()));
    for instruction in &instructions {
        wire_instruction(&mut message, instruction);
    }
    message.extend(compact(0));

    let mut transaction = compact(1);
    transaction.extend([0u8; 64]);
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
        ("allowed_nonce_accounts".to_string(), String::new()),
        ("max_sol_lamports".to_string(), "2000000".to_string()),
        ("max_token_amounts".to_string(), String::new()),
        ("max_priority_fee_lamports".to_string(), "0".to_string()),
        (
            "max_transaction_fee_lamports".to_string(),
            "10000".to_string(),
        ),
        (
            "max_account_creation_lamports".to_string(),
            "3000000".to_string(),
        ),
        (
            "max_total_sol_outflow_lamports".to_string(),
            "4000000".to_string(),
        ),
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
    let mut second_rpc = MockRpc {
        simulation_slot: Some(424_999),
        ..MockRpc::default()
    };

    let first = evaluate(&transaction, &policy, &mut first_rpc);
    let second = evaluate(&transaction, &policy, &mut second_rpc);

    assert_ne!(first.simulation.slot, second.simulation.slot);
    assert_eq!(first.receipt_hash, second.receipt_hash);
    assert_eq!(first.receipt_hash.len(), 64);
}

#[test]
fn malformed_base64_is_denied_without_rpc() {
    let mut rpc = MockRpc::default();
    let receipt = evaluate("%%%not-base64%%%", &HashMap::new(), &mut rpc);
    assert!(has_code(&receipt, "invalid_base64"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn allows_operator_approved_durable_nonce_payment() {
    let authority = key(1);
    let recipient = key(2);
    let nonce_account = key(7);
    let nonce = [88u8; 32];
    let transaction = durable_nonce_transfer(&authority, &nonce_account, &recipient, &nonce, true);
    let mut policy = base_policy(&authority, &recipient, "system");
    policy.insert("allowed_nonce_accounts".to_string(), nonce_account.clone());
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(
        nonce_account.clone(),
        RpcAccount {
            owner: SYSTEM_PROGRAM.to_string(),
            data: nonce_account_data(&authority, &nonce, 5_000),
        },
    );

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(receipt.allowed(), "{:?}", receipt.violations);
    let durable = receipt.durable_nonce.expect("durable nonce evidence");
    assert_eq!(durable.account, nonce_account);
    assert_eq!(durable.authority, authority);
    assert_eq!(durable.nonce, bs58::encode(nonce).into_string());
    assert_eq!(
        receipt.native_outflow.unwrap().transaction_fee_lamports,
        5_000
    );
    assert_eq!(receipt.simulation.slot, Some(424_242));
    assert_eq!(rpc.fee_calls, 1, "exact fee comes from the message RPC");
    assert_eq!(rpc.simulation_calls, 1);
}

#[test]
fn v0_durable_nonce_ata_transfer_accounts_for_rent_and_fee() {
    let authority = key(1);
    let recipient_owner = key(2);
    let destination_ata = key(3);
    let source_account = key(4);
    let mint = key(5);
    let nonce_account = key(7);
    let nonce = [88u8; 32];
    let transaction = v0_durable_ata_transfer_checked(
        &authority,
        &nonce_account,
        &recipient_owner,
        &source_account,
        &destination_ata,
        &mint,
        &nonce,
    );
    let mut policy = base_policy(
        &authority,
        &recipient_owner,
        "system,associated-token,token",
    );
    policy.insert("allowed_nonce_accounts".to_string(), nonce_account.clone());
    policy.insert("allowed_mints".to_string(), mint.clone());
    policy.insert("max_token_amounts".to_string(), format!("{mint}=1500000"));
    policy.insert("max_sol_lamports".to_string(), "0".to_string());
    policy.insert("allow_ata_creation".to_string(), "true".to_string());

    let mut source_data = vec![0u8; 165];
    source_data[0..32].copy_from_slice(&key_bytes(&mint));
    source_data[32..64].copy_from_slice(&key_bytes(&authority));
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(
        nonce_account.clone(),
        RpcAccount {
            owner: SYSTEM_PROGRAM.to_string(),
            data: nonce_account_data(&authority, &nonce, 5_000),
        },
    );
    rpc.accounts.insert(
        source_account,
        RpcAccount {
            owner: TOKEN_PROGRAM.to_string(),
            data: source_data,
        },
    );

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(receipt.allowed(), "{:?}", receipt.violations);
    assert_eq!(receipt.version.as_deref(), Some("v0"));
    assert_eq!(receipt.instructions, 3);
    assert_eq!(receipt.transfers[0].asset, mint);
    assert_eq!(receipt.transfers[0].amount_raw, "1500000");
    assert_eq!(receipt.transfers[0].recipient, recipient_owner);
    assert_eq!(receipt.durable_nonce.unwrap().account, nonce_account);
    let outflow = receipt.native_outflow.unwrap();
    assert_eq!(outflow.transaction_fee_lamports, 5_000);
    assert_eq!(outflow.account_creation_lamports, 2_039_280);
    assert_eq!(outflow.total_lamports, 2_044_280);
    assert_eq!(rpc.rent_calls, 1);
    assert_eq!(rpc.fee_calls, 1);
    assert_eq!(rpc.simulation_calls, 1);
}

#[test]
fn unapproved_durable_nonce_account_is_denied() {
    let authority = key(1);
    let recipient = key(2);
    let nonce_account = key(7);
    let nonce = [88u8; 32];
    let transaction = durable_nonce_transfer(&authority, &nonce_account, &recipient, &nonce, true);
    let policy = base_policy(&authority, &recipient, "system");
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(
        nonce_account,
        RpcAccount {
            owner: SYSTEM_PROGRAM.to_string(),
            data: nonce_account_data(&authority, &nonce, 5_000),
        },
    );

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "nonce_account_not_allowed"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn durable_nonce_must_match_current_account_state() {
    let authority = key(1);
    let recipient = key(2);
    let nonce_account = key(7);
    let transaction_nonce = [88u8; 32];
    let account_nonce = [89u8; 32];
    let transaction = durable_nonce_transfer(
        &authority,
        &nonce_account,
        &recipient,
        &transaction_nonce,
        true,
    );
    let mut policy = base_policy(&authority, &recipient, "system");
    policy.insert("allowed_nonce_accounts".to_string(), nonce_account.clone());
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(
        nonce_account,
        RpcAccount {
            owner: SYSTEM_PROGRAM.to_string(),
            data: nonce_account_data(&authority, &account_nonce, 5_000),
        },
    );

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "durable_nonce_mismatch"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn durable_nonce_authority_must_match_account_state() {
    let transaction_authority = key(1);
    let account_authority = key(6);
    let recipient = key(2);
    let nonce_account = key(7);
    let nonce = [88u8; 32];
    let transaction = durable_nonce_transfer(
        &transaction_authority,
        &nonce_account,
        &recipient,
        &nonce,
        true,
    );
    let mut policy = base_policy(&transaction_authority, &recipient, "system");
    policy.insert("allowed_nonce_accounts".to_string(), nonce_account.clone());
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(
        nonce_account,
        RpcAccount {
            owner: SYSTEM_PROGRAM.to_string(),
            data: nonce_account_data(&account_authority, &nonce, 5_000),
        },
    );

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "nonce_authority_mismatch"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn durable_nonce_advance_must_be_first() {
    let authority = key(1);
    let recipient = key(2);
    let nonce_account = key(7);
    let nonce = [88u8; 32];
    let transaction = durable_nonce_transfer(&authority, &nonce_account, &recipient, &nonce, false);
    let mut policy = base_policy(&authority, &recipient, "system");
    policy.insert("allowed_nonce_accounts".to_string(), nonce_account.clone());
    let mut rpc = MockRpc::default();
    rpc.accounts.insert(
        nonce_account,
        RpcAccount {
            owner: SYSTEM_PROGRAM.to_string(),
            data: nonce_account_data(&authority, &nonce, 5_000),
        },
    );

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "nonce_advance_not_first"));
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn unsigned_and_simulation_invariants_cannot_be_disabled() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    for key in ["require_unsigned", "require_simulation"] {
        let mut policy = base_policy(&fee_payer, &recipient, "system");
        policy.insert(key.to_string(), "false".to_string());
        let mut rpc = MockRpc::default();
        let receipt = evaluate(&transaction, &policy, &mut rpc);
        assert!(has_code(&receipt, "invalid_policy_configuration"));
        assert_eq!(rpc.simulation_calls, 0);
    }
}

#[test]
fn transaction_fee_is_included_in_native_outflow_policy() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let mut policy = base_policy(&fee_payer, &recipient, "system");
    policy.insert(
        "max_transaction_fee_lamports".to_string(),
        "4999".to_string(),
    );
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "transaction_fee_limit_exceeded"));
    assert_eq!(
        receipt.native_outflow.unwrap().transaction_fee_lamports,
        5_000
    );
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn rpc_transaction_fee_is_not_double_counted_with_priority_fee() {
    let fee_payer = key(1);
    let recipient = key(2);
    let accounts = vec![
        fee_payer.clone(),
        recipient.clone(),
        SYSTEM_PROGRAM.to_string(),
        COMPUTE_BUDGET_PROGRAM.to_string(),
    ];
    let mut unit_limit = vec![2];
    unit_limit.extend_from_slice(&200_000u32.to_le_bytes());
    let mut unit_price = vec![3];
    unit_price.extend_from_slice(&1_000u64.to_le_bytes());
    let transaction = legacy_transaction(
        &accounts,
        2,
        &[
            TestInstruction {
                program_index: 3,
                accounts: Vec::new(),
                data: unit_limit,
            },
            TestInstruction {
                program_index: 3,
                accounts: Vec::new(),
                data: unit_price,
            },
            TestInstruction {
                program_index: 2,
                accounts: vec![0, 1],
                data: system_transfer_data(1_000_000),
            },
        ],
        false,
    );
    let mut policy = base_policy(&fee_payer, &recipient, "system,compute-budget");
    policy.insert("max_priority_fee_lamports".to_string(), "200".to_string());
    policy.insert(
        "max_transaction_fee_lamports".to_string(),
        "5200".to_string(),
    );
    policy.insert(
        "max_total_sol_outflow_lamports".to_string(),
        "1005200".to_string(),
    );
    let mut rpc = MockRpc {
        fee_lamports: Some(5_200),
        ..MockRpc::default()
    };

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(receipt.allowed(), "{:?}", receipt.violations);
    let outflow = receipt.native_outflow.unwrap();
    assert_eq!(outflow.priority_fee_lamports, 200);
    assert_eq!(outflow.transaction_fee_lamports, 5_200);
    assert_eq!(outflow.total_lamports, 1_005_200);
}

#[test]
fn total_native_outflow_includes_transfer_fee_and_rent() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let mut policy = base_policy(&fee_payer, &recipient, "system");
    policy.insert(
        "max_total_sol_outflow_lamports".to_string(),
        "1004999".to_string(),
    );
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "total_sol_outflow_limit_exceeded"));
    let outflow = receipt.native_outflow.unwrap();
    assert_eq!(outflow.transfer_lamports, 1_000_000);
    assert_eq!(outflow.transaction_fee_lamports, 5_000);
    assert_eq!(outflow.total_lamports, 1_005_000);
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn ata_rent_is_bounded_before_simulation() {
    let fee_payer = key(1);
    let recipient = key(2);
    let ata = key(3);
    let mint = key(4);
    let accounts = vec![
        fee_payer.clone(),
        ata,
        recipient.clone(),
        mint.clone(),
        SYSTEM_PROGRAM.to_string(),
        TOKEN_PROGRAM.to_string(),
        solana_policy_firewall::programs::ASSOCIATED_TOKEN_PROGRAM.to_string(),
    ];
    let transaction = legacy_transaction(
        &accounts,
        5,
        &[TestInstruction {
            program_index: 6,
            accounts: vec![0, 1, 2, 3, 4, 5],
            data: vec![1],
        }],
        false,
    );
    let mut policy = base_policy(&fee_payer, &recipient, "associated-token");
    policy.insert("allowed_mints".to_string(), mint);
    policy.insert("allow_ata_creation".to_string(), "true".to_string());
    policy.insert("require_value_transfer".to_string(), "false".to_string());
    policy.insert(
        "max_account_creation_lamports".to_string(),
        "1000000".to_string(),
    );
    let mut rpc = MockRpc::default();

    let receipt = evaluate(&transaction, &policy, &mut rpc);

    assert!(has_code(&receipt, "account_creation_limit_exceeded"));
    assert_eq!(
        receipt.native_outflow.unwrap().account_creation_lamports,
        2_039_280
    );
    assert_eq!(rpc.rent_calls, 1);
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn oversized_base64_is_rejected_before_decoding() {
    let mut rpc = MockRpc::default();
    let receipt = evaluate(&"A".repeat(1_645), &HashMap::new(), &mut rpc);
    assert!(has_code(&receipt, "transaction_input_too_large"));
    assert_eq!(rpc.fee_calls, 0);
    assert_eq!(rpc.simulation_calls, 0);
}

#[test]
fn direct_tool_receipts_remain_context_bounded() {
    let recipient = key(2);
    let (fee_payer, transaction) = simple_sol_transfer(&recipient, false);
    let policy = base_policy(&fee_payer, &recipient, "system");
    let mut rpc = MockRpc::default();
    let receipt = evaluate(&transaction, &policy, &mut rpc);
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.len() <= 1_200, "{} bytes: {json}", json.len());
}
