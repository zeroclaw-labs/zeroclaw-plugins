//! Host tests over the pure core. The centerpiece builds a genuine Squads
//! proposal-creation transaction with quorum-core and asserts the xray
//! receipt surfaces the inner transfer, so the two plugins are verified
//! against each other's bytes.

use quorum_core::message::{compile_legacy_message, unsigned_tx_base64, AccountMeta, Instruction};
use quorum_core::pubkey::Pubkey;
use quorum_core::rpc::MockRpc;
use quorum_core::spl::{
    create_ata_idempotent_ix, derive_ata, memo_ix, transfer_checked_ix, TOKEN_PROGRAM,
};
use quorum_core::squads::{
    compile_transaction_message, proposal_create_ix, vault_transaction_create_ix,
};
use serde_json::{json, Value};
use tx_xray::core::{run, XrayArgs};

fn usdc() -> Pubkey {
    Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap()
}

fn build_proposal_tx() -> String {
    let ms = Pubkey([4u8; 32]);
    let vault = Pubkey([1u8; 32]);
    let recipient = Pubkey([2u8; 32]);
    let creator = Pubkey([6u8; 32]);
    let vault_ata = derive_ata(&vault, &usdc(), &TOKEN_PROGRAM);
    let rec_ata = derive_ata(&recipient, &usdc(), &TOKEN_PROGRAM);
    let inner = vec![
        create_ata_idempotent_ix(&vault, &recipient, &usdc(), &TOKEN_PROGRAM),
        transfer_checked_ix(
            &TOKEN_PROGRAM,
            &vault_ata,
            &usdc(),
            &rec_ata,
            &vault,
            150_000_000,
            6,
        ),
        memo_ix("inv-88"),
    ];
    let msg = compile_transaction_message(&vault, &inner).unwrap();
    let outer = vec![
        vault_transaction_create_ix(
            &ms,
            &Pubkey([5u8; 32]),
            &creator,
            &creator,
            0,
            0,
            &msg,
            None,
        ),
        proposal_create_ix(&ms, &Pubkey([3u8; 32]), &creator, &creator, 42, false),
    ];
    let compiled = compile_legacy_message(&creator, &outer, &[9u8; 32]).unwrap();
    unsigned_tx_base64(&compiled)
}

fn xargs(tx: &str, simulate: bool) -> XrayArgs {
    serde_json::from_value(json!({"unsigned_tx_base64": tx, "simulate": simulate})).unwrap()
}

#[test]
fn unwraps_squads_proposal_and_shows_inner_transfer() {
    let rpc = MockRpc::new();
    let out = run(&rpc, &Value::Null, &xargs(&build_proposal_tx(), false)).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let summary = v["summary"].as_str().unwrap();
    assert!(summary.contains("create vault transaction"), "{summary}");
    assert!(summary.contains("Token transfer: 150"), "{summary}");
    assert!(summary.contains("Memo: inv-88"), "{summary}");
    assert!(summary.contains("proposal #42"), "{summary}");
    assert!(
        rpc.log.borrow().is_empty(),
        "simulate=false must stay offline"
    );
    assert!(summary.len() <= 900);
}

#[test]
fn flags_unknown_programs_instead_of_guessing() {
    let payer = Pubkey([1u8; 32]);
    let mystery = Instruction {
        program_id: Pubkey([200u8; 32]),
        accounts: vec![AccountMeta::writable(payer, true)],
        data: vec![1, 2, 3],
    };
    let compiled = compile_legacy_message(&payer, &[mystery], &[9u8; 32]).unwrap();
    let out = run(
        &MockRpc::new(),
        &Value::Null,
        &xargs(&unsigned_tx_base64(&compiled), false),
    )
    .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v["flags"][0].as_str().unwrap().contains("UNKNOWN program"));
}

#[test]
fn flags_delegate_approval() {
    let payer = Pubkey([1u8; 32]);
    let approve = Instruction {
        program_id: TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::writable(Pubkey([2u8; 32]), false),
            AccountMeta::readonly(Pubkey([3u8; 32]), false),
            AccountMeta::readonly(payer, true),
        ],
        data: {
            let mut d = vec![4u8];
            d.extend_from_slice(&1_000_000u64.to_le_bytes());
            d
        },
    };
    let compiled = compile_legacy_message(&payer, &[approve], &[9u8; 32]).unwrap();
    let out = run(
        &MockRpc::new(),
        &Value::Null,
        &xargs(&unsigned_tx_base64(&compiled), false),
    )
    .unwrap();
    assert!(out.contains("APPROVE DELEGATE"));
}

#[test]
fn simulation_verdicts_surface_both_ways() {
    let tx = build_proposal_tx();

    let ok = MockRpc::new();
    ok.push_ok(
        "simulateTransaction",
        json!({"value": {"err": null, "unitsConsumed": 8000, "logs": []}}),
    );
    let out = run(&ok, &Value::Null, &xargs(&tx, true)).unwrap();
    assert!(out.contains("Simulation: OK"));

    let bad = MockRpc::new();
    bad.push_ok(
        "simulateTransaction",
        json!({"value": {"err": {"InstructionError": [1, "Custom"]}, "logs": []}}),
    );
    let out = run(&bad, &Value::Null, &xargs(&tx, true)).unwrap();
    assert!(out.contains("SIMULATION FAILED"));
}

#[test]
fn receipt_stays_under_budget_with_many_instructions() {
    let payer = Pubkey([1u8; 32]);
    let mut ixs = Vec::new();
    for i in 0..40u8 {
        ixs.push(Instruction {
            program_id: Pubkey([210u8.wrapping_add(i); 32]),
            accounts: vec![AccountMeta::writable(payer, true)],
            data: vec![i],
        });
    }
    let compiled = compile_legacy_message(&payer, &ixs, &[9u8; 32]).unwrap();
    let out = run(
        &MockRpc::new(),
        &Value::Null,
        &xargs(&unsigned_tx_base64(&compiled), false),
    )
    .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let summary = v["summary"].as_str().unwrap();
    assert!(
        summary.len() <= 900,
        "receipt overflows budget: {}",
        summary.len()
    );
    assert!(summary.contains("[truncated for brevity]"));
}
