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

/// A token-program instruction with the given tag and total data length,
/// three throwaway accounts (source, mint, dest slots).
fn token_ix(tag: u8, data_len: usize) -> Instruction {
    let mut data = vec![tag];
    data.extend(std::iter::repeat(0u8).take(data_len.saturating_sub(1)));
    Instruction {
        program_id: TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::writable(Pubkey([2u8; 32]), false),
            AccountMeta::readonly(Pubkey([3u8; 32]), false),
            AccountMeta::writable(Pubkey([4u8; 32]), false),
        ],
        data,
    }
}

fn xray_ixs(ixs: &[Instruction], simulate: bool, rpc: &MockRpc) -> Value {
    let payer = Pubkey([1u8; 32]);
    let compiled = compile_legacy_message(&payer, ixs, &[9u8; 32]).unwrap();
    let out = run(
        rpc,
        &Value::Null,
        &xargs(&unsigned_tx_base64(&compiled), simulate),
    )
    .unwrap();
    serde_json::from_str(&out).unwrap()
}

#[test]
fn flags_every_authority_moving_token_instruction() {
    // Tag -> the hazard word that must appear. None of these may read as safe.
    let cases: &[(u8, &str)] = &[
        (13, "APPROVE DELEGATE"), // ApproveChecked
        (6, "SET AUTHORITY"),     // SetAuthority
        (7, "MINT TO"),           // MintTo
        (8, "BURN"),              // Burn
        (9, "CLOSE ACCOUNT"),     // CloseAccount
    ];
    for (tag, needle) in cases {
        let v = xray_ixs(&[token_ix(*tag, 4)], false, &MockRpc::new());
        let summary = v["summary"].as_str().unwrap();
        assert!(summary.contains(needle), "tag {tag} not flagged: {summary}");
    }
}

#[test]
fn flags_unrecognized_token_tag_instead_of_calling_it_safe() {
    let v = xray_ixs(&[token_ix(200, 4)], false, &MockRpc::new());
    let summary = v["summary"].as_str().unwrap();
    assert!(summary.contains("UNRECOGNIZED token"), "{summary}");
    assert!(!summary.contains("No hazards flagged"), "{summary}");
}

#[test]
fn implausible_decimals_are_flagged_and_never_trap() {
    // A TransferChecked whose decimals byte is 64 would overflow 10^decimals
    // to a 0 divisor and divide-by-zero-trap in the release build; here it
    // must produce a flag and a receipt, not a panic.
    let mut data = vec![12u8];
    data.extend_from_slice(&1_000u64.to_le_bytes());
    data.push(64); // decimals
    let ix = Instruction {
        program_id: TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::writable(Pubkey([2u8; 32]), false),
            AccountMeta::readonly(Pubkey([3u8; 32]), false),
            AccountMeta::writable(Pubkey([4u8; 32]), false),
            AccountMeta::readonly(Pubkey([5u8; 32]), true),
        ],
        data,
    };
    let v = xray_ixs(&[ix], false, &MockRpc::new());
    let summary = v["summary"].as_str().unwrap();
    assert!(summary.contains("implausible decimals"), "{summary}");
}

#[test]
fn hazard_flag_survives_receipt_truncation() {
    // Pad the transaction with many benign memos so the descriptive lines
    // overflow the budget, then a delegate approval. Because flags render
    // first, the hazard must still be in the summary.
    let mut ixs: Vec<Instruction> = (0..40)
        .map(|_| memo_ix("padding padding padding padding padding padding"))
        .collect();
    ixs.push(token_ix(4, 9)); // Approve
    let v = xray_ixs(&ixs, false, &MockRpc::new());
    let summary = v["summary"].as_str().unwrap();
    assert!(summary.len() <= 900, "over budget: {}", summary.len());
    assert!(
        summary.contains("APPROVE DELEGATE"),
        "hazard was truncated away: {summary}"
    );
}

#[test]
fn degraded_simulation_is_not_reported_as_ok() {
    let tx = build_proposal_tx();
    // Response missing the whole `value` object: must be flagged, not OK.
    let rpc = MockRpc::new();
    rpc.push_ok("simulateTransaction", json!({"context": {"slot": 1}}));
    let out = run(&rpc, &Value::Null, &xargs(&tx, true)).unwrap();
    assert!(!out.contains("Simulation: OK"), "{out}");
    assert!(out.contains("unparseable"), "{out}");
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
