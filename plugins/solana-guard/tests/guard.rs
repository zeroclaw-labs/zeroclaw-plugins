//! Host integration tests for the ogige guard core.
//! Exercises the same analyze() path the wasm `execute` entry point uses.

use std::collections::HashMap;

use solana_guard::core::base64;
use solana_guard::core::programs::{
    bpf_upgradeable_loader, system_program, token_2022_program, token_program,
};
use solana_guard::core::pubkey::Pubkey;
use solana_guard::guard::{analyze, GuardConfig, Verdict};

/// Build a minimal legacy unsigned transaction as base64.
fn legacy_tx(account_keys: &[Pubkey], instructions: &[(u8, &[u8], &[u8])]) -> String {
    let mut msg = Vec::new();
    // header: 1 required sig, 0 readonly signed, 0 readonly unsigned
    msg.push(1u8);
    msg.push(0);
    msg.push(0);
    write_compact_u16(&mut msg, account_keys.len() as u16);
    for k in account_keys {
        msg.extend_from_slice(k.as_bytes());
    }
    msg.extend_from_slice(&[0u8; 32]); // blockhash
    write_compact_u16(&mut msg, instructions.len() as u16);
    for (program_idx, accounts, data) in instructions {
        msg.push(*program_idx);
        write_compact_u16(&mut msg, accounts.len() as u16);
        msg.extend_from_slice(accounts);
        write_compact_u16(&mut msg, data.len() as u16);
        msg.extend_from_slice(data);
    }

    // 1 empty signature slot
    let mut bytes = Vec::new();
    write_compact_u16(&mut bytes, 1);
    bytes.extend_from_slice(&[0u8; 64]);
    bytes.extend_from_slice(&msg);
    base64::encode(&bytes)
}

fn write_compact_u16(buf: &mut Vec<u8>, mut val: u16) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            break;
        } else {
            byte |= 0x80;
            buf.push(byte);
        }
    }
}

fn sol_transfer_tx() -> String {
    let from = Pubkey::new([1u8; 32]);
    let to = Pubkey::new([2u8; 32]);
    let system = system_program();
    // System Transfer: disc=2 (u32 LE) + lamports u64 LE = 1_000_000_000 (1 SOL)
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
    legacy_tx(&[from, to, system], &[(2, &[0, 1], &data)])
}

fn token_approve_max_tx() -> String {
    let source = Pubkey::new([3u8; 32]);
    let delegate = Pubkey::new([4u8; 32]);
    let owner = Pubkey::new([5u8; 32]);
    let token = token_program();
    // Approve: disc=4, amount=u64::MAX
    let mut data = vec![4u8];
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    legacy_tx(&[source, delegate, owner, token], &[(3, &[0, 1, 2], &data)])
}

fn system_assign_tx() -> String {
    let account = Pubkey::new([6u8; 32]);
    let system = system_program();
    // Assign: disc=1 (u32) + owner pubkey
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&[9u8; 32]);
    legacy_tx(&[account, system], &[(1, &[0], &data)])
}

fn program_upgrade_tx() -> String {
    let programdata = Pubkey::new([7u8; 32]);
    let program = Pubkey::new([8u8; 32]);
    let buffer = Pubkey::new([9u8; 32]);
    let spill = Pubkey::new([10u8; 32]);
    let authority = Pubkey::new([11u8; 32]);
    let loader = bpf_upgradeable_loader();
    // Upgrade discriminant = 3u32 LE
    let data = 3u32.to_le_bytes().to_vec();
    legacy_tx(
        &[programdata, program, buffer, spill, authority, loader],
        &[(5, &[0, 1, 2, 3, 4], &data)],
    )
}

fn token_2022_permanent_delegate_tx() -> String {
    let mint = Pubkey::new([12u8; 32]);
    let token_2022 = token_2022_program();
    let mut data = vec![35u8];
    data.extend_from_slice(&[13u8; 32]);
    legacy_tx(&[mint, token_2022], &[(1, &[0], &data)])
}

fn token_2022_transfer_hook_update_tx() -> String {
    let mint = Pubkey::new([14u8; 32]);
    let authority = Pubkey::new([15u8; 32]);
    let token_2022 = token_2022_program();
    let mut data = vec![36u8, 1u8];
    data.extend_from_slice(&[16u8; 32]);
    legacy_tx(&[mint, authority, token_2022], &[(2, &[0, 1], &data)])
}

fn unknown_program_tx() -> String {
    let signer = Pubkey::new([17u8; 32]);
    let unknown_program = Pubkey::new([18u8; 32]);
    legacy_tx(&[signer, unknown_program], &[(1, &[0], &[99u8])])
}

fn token_burn_tx() -> String {
    let account = Pubkey::new([19u8; 32]);
    let mint = Pubkey::new([20u8; 32]);
    let owner = Pubkey::new([21u8; 32]);
    let token = token_program();
    let mut data = vec![8u8];
    data.extend_from_slice(&42u64.to_le_bytes());
    legacy_tx(&[account, mint, owner, token], &[(3, &[0, 1, 2], &data)])
}

#[test]
fn allows_simple_sol_transfer() {
    let cfg = GuardConfig::default();
    let report = analyze(&sol_transfer_tx(), &cfg).expect("decode");
    assert_eq!(report.verdict, Verdict::Allow);
    assert!(report.narration.contains("Transfer"));
    assert!(report.narration.contains("SOL"));
    assert_eq!(report.tx_version, "legacy");
}

#[test]
fn rejects_unlimited_token_approve() {
    let cfg = GuardConfig::default();
    let report = analyze(&token_approve_max_tx(), &cfg).expect("decode");
    assert_eq!(report.verdict, Verdict::Reject);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "TOKEN_APPROVE_MAX"));
    assert!(report.summary.contains("REJECT"));
}

#[test]
fn rejects_system_assign() {
    let cfg = GuardConfig::default();
    let report = analyze(&system_assign_tx(), &cfg).expect("decode");
    assert_eq!(report.verdict, Verdict::Reject);
    assert!(report.findings.iter().any(|f| f.code == "SYSTEM_ASSIGN"));
}

#[test]
fn rejects_program_upgrade() {
    let cfg = GuardConfig::default();
    let report = analyze(&program_upgrade_tx(), &cfg).expect("decode");
    assert_eq!(report.verdict, Verdict::Reject);
    assert!(report.findings.iter().any(|f| f.code == "PROGRAM_UPGRADE"));
    assert!(report.narration.contains("Upgrade"));
}

#[test]
fn rejects_token_2022_permanent_delegate() {
    let report =
        analyze(&token_2022_permanent_delegate_tx(), &GuardConfig::default()).expect("decode");
    assert_eq!(report.verdict, Verdict::Reject);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "TOKEN_2022_PERMANENT_DELEGATE"));
    assert!(report.narration.contains("InitializePermanentDelegate"));
}

#[test]
fn holds_token_2022_transfer_hook_update() {
    let report = analyze(
        &token_2022_transfer_hook_update_tx(),
        &GuardConfig::default(),
    )
    .expect("decode");
    assert_eq!(report.verdict, Verdict::Hold);
    assert!(report
        .findings
        .iter()
        .any(|f| f.code == "TOKEN_2022_TRANSFER_HOOK_UPDATE"));
    assert!(report.narration.contains("UpdateTransferHook"));
}

#[test]
fn holds_unknown_program() {
    let report = analyze(&unknown_program_tx(), &GuardConfig::default()).expect("decode");
    assert_eq!(report.verdict, Verdict::Hold);
    assert!(report.findings.iter().any(|f| f.code == "UNKNOWN_PROGRAM"));
}

#[test]
fn holds_token_burn() {
    let report = analyze(&token_burn_tx(), &GuardConfig::default()).expect("decode");
    assert_eq!(report.verdict, Verdict::Hold);
    assert!(report.findings.iter().any(|f| f.code == "TOKEN_BURN"));
    assert!(report.narration.contains("permanently destroys"));
}

#[test]
fn config_can_downgrade_critical_to_hold() {
    let mut section = HashMap::new();
    section.insert("reject_on_critical".into(), "false".into());
    let cfg = GuardConfig::from_section(&section);
    let report = analyze(&system_assign_tx(), &cfg).expect("decode");
    assert_eq!(report.verdict, Verdict::Hold);
}

#[test]
fn empty_config_is_safe_defaults() {
    let cfg = GuardConfig::from_section(&HashMap::new());
    assert!(cfg.reject_on_critical);
    assert!(cfg.hold_on_high);
    assert!(!cfg.hold_on_medium);
}

#[test]
fn rejects_garbage_base64_cleanly() {
    let cfg = GuardConfig::default();
    let err = analyze("!!!not-base64!!!", &cfg).unwrap_err();
    assert!(err.contains("base64") || err.contains("decode") || err.contains("invalid"));
}

#[test]
fn rejects_truncated_payload() {
    let cfg = GuardConfig::default();
    // Valid base64 but not a transaction
    let err = analyze(&base64::encode(&[1, 2, 3]), &cfg).unwrap_err();
    assert!(err.contains("truncated") || err.contains("decode") || err.contains("failed"));
}

#[test]
fn rejects_signature_count_mismatch() {
    let tx = sol_transfer_tx();
    let mut bytes = base64::decode(&tx).expect("base64");
    // shortvec signature count (1 byte) + one 64-byte signature = header offset 65
    bytes[65] = 2;
    let err = analyze(&base64::encode(&bytes), &GuardConfig::default()).unwrap_err();
    assert!(err.contains("signature count"));
}

#[test]
fn rejects_trailing_transaction_bytes() {
    let tx = sol_transfer_tx();
    let mut bytes = base64::decode(&tx).expect("base64");
    bytes.push(0xff);
    let err = analyze(&base64::encode(&bytes), &GuardConfig::default()).unwrap_err();
    assert!(err.contains("trailing transaction bytes"));
}
