//! Host tests over the pure core with a mocked RPC.

use base64::Engine;
use quorum_core::pubkey::Pubkey;
use quorum_core::rpc::MockRpc;
use quorum_core::squads::{
    encode_multisig_for_test, encode_proposal_for_test, multisig_pda, Member, MultisigState,
    ProposalState, ProposalStatus,
};
use serde_json::{json, Value};
use squads_watch::core::{run, WatchArgs};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn setup(transaction_index: u64) -> (Pubkey, Vec<u8>) {
    let create_key = Pubkey([9u8; 32]);
    let (ms_addr, bump) = multisig_pda(&create_key);
    let state = MultisigState {
        create_key,
        config_authority: Pubkey::ZERO,
        threshold: 2,
        time_lock: 0,
        transaction_index,
        stale_transaction_index: 0,
        rent_collector: None,
        bump,
        members: vec![
            Member {
                key: Pubkey([1u8; 32]),
                permissions: 7,
            },
            Member {
                key: Pubkey([2u8; 32]),
                permissions: 7,
            },
            Member {
                key: Pubkey([3u8; 32]),
                permissions: 1,
            },
        ],
    };
    (ms_addr, encode_multisig_for_test(&state))
}

fn proposal(ms: &Pubkey, index: u64, status: ProposalStatus, approvals: usize) -> Vec<u8> {
    let approved = (0..approvals).map(|i| Pubkey([i as u8 + 1; 32])).collect();
    encode_proposal_for_test(&ProposalState {
        multisig: *ms,
        transaction_index: index,
        status,
        bump: 250,
        approved,
        rejected: vec![],
        cancelled: vec![],
    })
}

fn wargs(cursor: Option<u64>) -> WatchArgs {
    serde_json::from_value(json!({"cursor": cursor})).unwrap()
}

#[test]
fn fails_closed_without_multisig_config() {
    let rpc = MockRpc::new();
    let err = run(&rpc, &json!({"rpc_url": "https://x"}), &wargs(None)).unwrap_err();
    assert!(err.contains("multisig"));
    assert!(rpc.log.borrow().is_empty());
}

#[test]
fn reports_pending_and_outcomes_since_cursor() {
    let (ms_addr, ms_bytes) = setup(42);
    let rpc = MockRpc::new();
    rpc.push_ok(
        "getAccountInfo",
        json!({"value": {"data": [b64(&ms_bytes), "base64"]}}),
    );
    // Indices 41 and 42: one executed, one active with a single approval.
    rpc.push_ok(
        "getMultipleAccounts",
        json!({"value": [
            {"data": [b64(&proposal(&ms_addr, 41, ProposalStatus::Executed(1_700_000_000), 2)), "base64"]},
            {"data": [b64(&proposal(&ms_addr, 42, ProposalStatus::Active(1_700_000_100), 1)), "base64"]}
        ]}),
    );
    let cfg = json!({"rpc_url": "https://x", "multisig": ms_addr.to_base58()});
    let out = run(&rpc, &cfg, &wargs(Some(40))).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let summary = v["summary"].as_str().unwrap();
    assert!(summary.contains("#41: Executed"), "{summary}");
    assert!(summary.contains("#42: Active, 1 of 2"), "{summary}");
    assert!(summary.contains("Action needed"), "{summary}");
    assert_eq!(v["next_cursor"], 42);
    assert_eq!(v["pending"], json!([42]));
    assert_eq!(rpc.log.borrow().len(), 2);
    assert!(summary.len() <= 900);
}

#[test]
fn quiet_when_up_to_date() {
    let (ms_addr, ms_bytes) = setup(42);
    let rpc = MockRpc::new();
    rpc.push_ok(
        "getAccountInfo",
        json!({"value": {"data": [b64(&ms_bytes), "base64"]}}),
    );
    let cfg = json!({"rpc_url": "https://x", "multisig": ms_addr.to_base58()});
    let out = run(&rpc, &cfg, &wargs(Some(42))).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v["summary"].as_str().unwrap().contains("No new activity"));
    assert_eq!(v["pending"], json!([]));
    assert_eq!(
        rpc.log.borrow().len(),
        1,
        "no proposal fetch when nothing is new"
    );
}

#[test]
fn handles_missing_proposal_accounts() {
    let (ms_addr, ms_bytes) = setup(3);
    let rpc = MockRpc::new();
    rpc.push_ok(
        "getAccountInfo",
        json!({"value": {"data": [b64(&ms_bytes), "base64"]}}),
    );
    rpc.push_ok("getMultipleAccounts", json!({"value": [null]}));
    let cfg = json!({"rpc_url": "https://x", "multisig": ms_addr.to_base58()});
    let out = run(&rpc, &cfg, &wargs(Some(2))).unwrap();
    assert!(out.contains("no proposal opened yet"));
}
