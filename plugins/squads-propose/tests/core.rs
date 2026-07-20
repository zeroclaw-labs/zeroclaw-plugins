//! Host tests over the pure core with a mocked RPC. The happy path does not
//! just assert success: it re-parses the produced unsigned transaction and
//! checks the Squads instructions, PDAs, and amounts byte by byte.

use quorum_core::message::parse_tx_base64;
use quorum_core::pubkey::Pubkey;
use quorum_core::rpc::MockRpc;
use quorum_core::squads::{
    encode_multisig_for_test, multisig_pda, proposal_pda, transaction_pda, Member, MultisigState,
    DISC_PROPOSAL_CREATE, DISC_VAULT_TRANSACTION_CREATE, SQUADS_PROGRAM,
};
use serde_json::{json, Value};
use squads_propose::core::{run, ProposeArgs};

fn creator() -> Pubkey {
    Pubkey([6u8; 32])
}

fn multisig_state(transaction_index: u64, creator_perms: u8) -> (Pubkey, Vec<u8>) {
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
                key: creator(),
                permissions: creator_perms,
            },
            Member {
                key: Pubkey([8u8; 32]),
                permissions: 7,
            },
            Member {
                key: Pubkey([7u8; 32]),
                permissions: 7,
            },
        ],
    };
    (ms_addr, encode_multisig_for_test(&state))
}

fn base_cfg(ms_addr: &Pubkey) -> Value {
    json!({
        "rpc_url": "https://example.invalid",
        "multisig": ms_addr.to_base58(),
        "creator_pubkey": creator().to_base58(),
        "vault_index": 0,
        "mints": [{
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "symbol": "USDC",
            "decimals": 6,
            "per_proposal_cap": "500"
        }],
        "recipients": {
            "ana": "F65MT4J3kSRdyPMehKvuUvHmpCktrH9Q8n7J8dsHit68"
        }
    })
}

fn account_json(bytes: &[u8]) -> Value {
    use base64::Engine;
    json!({"value": {"data": [base64::engine::general_purpose::STANDARD.encode(bytes), "base64"], "owner": SQUADS_PROGRAM.to_base58()}})
}

fn args(recipient: &str, amount: &str, token: &str) -> ProposeArgs {
    serde_json::from_value(json!({
        "recipient": recipient, "amount": amount, "token": token, "memo": "inv-88"
    }))
    .unwrap()
}

#[test]
fn memo_is_stripped_of_control_and_byte_capped() {
    let (ms_addr, ms_bytes) = multisig_state(41, 7);
    let rpc = MockRpc::new();
    rpc.push_ok("getAccountInfo", account_json(&ms_bytes));
    rpc.push_ok(
        "getLatestBlockhash",
        json!({"value": {"blockhash": bs58::encode([5u8; 32]).into_string()}}),
    );
    let mut cfg = base_cfg(&ms_addr);
    cfg["max_memo_len"] = json!(8);
    let nasty: ProposeArgs = serde_json::from_value(json!({
        "recipient": "ana", "amount": "10", "token": "USDC",
        "memo": "ab\ncd\u{202E}\u{1F4B0}\u{1F4B0}\u{1F4B0}"
    }))
    .unwrap();
    let out = run(&rpc, &cfg, &nasty).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let summary = v["summary"].as_str().unwrap();
    // Control character and bidi override never survive into the receipt.
    assert!(!summary.contains('\u{202E}'), "bidi override survived");
    // The memo line's content is byte-capped at max_memo_len.
    let memo_line = summary
        .lines()
        .find(|l| l.starts_with("Memo: "))
        .expect("memo line present");
    let memo = &memo_line["Memo: ".len()..];
    assert!(
        memo.len() <= 8,
        "memo byte length {} exceeds cap",
        memo.len()
    );
    assert!(!memo.contains('\n'));
}

#[test]
fn refuses_without_policy_config() {
    let rpc = MockRpc::new();
    let cfg = json!({"rpc_url": "https://x", "multisig": "F65MT4J3kSRdyPMehKvuUvHmpCktrH9Q8n7J8dsHit68", "creator_pubkey": creator().to_base58()});
    let err = run(&rpc, &cfg, &args("ana", "10", "USDC")).unwrap_err();
    assert!(
        err.contains("mints"),
        "should refuse without an allowlist: {err}"
    );
    assert!(
        rpc.log.borrow().is_empty(),
        "must not touch the network before policy passes"
    );
}

#[test]
fn rejects_raw_address_recipient_even_when_valid() {
    let (ms_addr, _) = multisig_state(41, 7);
    let rpc = MockRpc::new();
    let err = run(
        &rpc,
        &base_cfg(&ms_addr),
        &args("DpcyqkendyzQd6yvDyHt9BEpUp2EnmXbEFUnpqAXpFAZ", "10", "USDC"),
    )
    .unwrap_err();
    assert!(err.contains("address book"), "{err}");
    assert!(rpc.log.borrow().is_empty());
}

#[test]
fn rejects_amount_over_cap_and_unknown_mint() {
    let (ms_addr, _) = multisig_state(41, 7);
    let rpc = MockRpc::new();
    let cfg = base_cfg(&ms_addr);
    assert!(run(&rpc, &cfg, &args("ana", "500.000001", "USDC"))
        .unwrap_err()
        .contains("cap"));
    assert!(run(&rpc, &cfg, &args("ana", "10", "BONK"))
        .unwrap_err()
        .contains("allowlist"));
    assert!(rpc.log.borrow().is_empty());
}

#[test]
fn rejects_creator_without_initiate_permission() {
    let (ms_addr, ms_bytes) = multisig_state(41, 2); // vote only, no initiate
    let rpc = MockRpc::new();
    rpc.push_ok("getAccountInfo", account_json(&ms_bytes));
    let err = run(&rpc, &base_cfg(&ms_addr), &args("ana", "10", "USDC")).unwrap_err();
    assert!(err.contains("Initiate"), "{err}");
}

#[test]
fn happy_path_builds_verifiable_proposal_transaction() {
    let (ms_addr, ms_bytes) = multisig_state(41, 7);
    let rpc = MockRpc::new();
    rpc.push_ok("getAccountInfo", account_json(&ms_bytes));
    rpc.push_ok(
        "getLatestBlockhash",
        json!({"value": {"blockhash": bs58::encode([5u8; 32]).into_string()}}),
    );

    let out = run(&rpc, &base_cfg(&ms_addr), &args("ana", "150", "USDC")).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["proposal_index"], 42);

    // The produced PDAs must match independent derivation.
    let (expected_tx, _) = transaction_pda(&ms_addr, 42);
    let (expected_prop, _) = proposal_pda(&ms_addr, 42);
    assert_eq!(v["transaction"], expected_tx.to_base58());
    assert_eq!(v["proposal"], expected_prop.to_base58());

    // Re-parse the unsigned transaction and verify structure end to end.
    let parsed = parse_tx_base64(v["unsigned_tx_base64"].as_str().unwrap()).unwrap();
    assert_eq!(
        parsed.num_required_signatures, 1,
        "only the human creator signs"
    );
    assert_eq!(parsed.account_keys[0], creator(), "creator is fee payer");
    assert_eq!(parsed.instructions.len(), 2);
    let vtc = &parsed.instructions[0];
    assert_eq!(vtc.program_id, SQUADS_PROGRAM);
    assert_eq!(vtc.data[..8], DISC_VAULT_TRANSACTION_CREATE);
    assert_eq!(vtc.accounts[0], ms_addr);
    assert_eq!(vtc.accounts[1], expected_tx);
    let pc = &parsed.instructions[1];
    assert_eq!(pc.data[..8], DISC_PROPOSAL_CREATE);
    assert_eq!(pc.data[8..16], 42u64.to_le_bytes());
    assert_eq!(pc.accounts[1], expected_prop);

    // The inner amount (150 USDC, 6 decimals) is embedded in the wire bytes
    // of the transaction message: transfer_checked tag 12 + u64 LE.
    let needle = {
        let mut n = vec![12u8];
        n.extend_from_slice(&150_000_000u64.to_le_bytes());
        n.push(6u8);
        n
    };
    assert!(
        vtc.data.windows(needle.len()).any(|w| w == needle),
        "inner transfer_checked bytes not found"
    );

    // Exactly two RPC calls: one account read, one blockhash. No sends.
    assert_eq!(rpc.log.borrow().len(), 2);
    let summary = v["summary"].as_str().unwrap();
    assert!(summary.contains("150 USDC"));
    assert!(summary.len() < 900);
}

/// The ZeroClaw host injects `__config` as a flat map of strings (its config
/// schema is HashMap<String, String>), so mints/recipients arrive as JSON in
/// a string and vault_index as a decimal string. That shape must produce a
/// transaction byte-identical to the native-JSON shape.
#[test]
fn host_flat_string_config_is_equivalent() {
    let (ms_addr, ms_bytes) = multisig_state(41, 7);
    let native = base_cfg(&ms_addr);
    let flat = json!({
        "rpc_url": "https://example.invalid",
        "multisig": ms_addr.to_base58(),
        "creator_pubkey": creator().to_base58(),
        "vault_index": "0",
        "mints": serde_json::to_string(&native["mints"]).unwrap(),
        "recipients": serde_json::to_string(&native["recipients"]).unwrap(),
    });

    let mut outputs = Vec::new();
    for cfg in [&native, &flat] {
        let rpc = MockRpc::new();
        rpc.push_ok("getAccountInfo", account_json(&ms_bytes));
        rpc.push_ok(
            "getLatestBlockhash",
            json!({"value": {"blockhash": bs58::encode([5u8; 32]).into_string()}}),
        );
        outputs.push(run(&rpc, cfg, &args("ana", "150", "USDC")).unwrap());
    }
    assert_eq!(
        outputs[0], outputs[1],
        "flat host config must not change the transaction"
    );

    // A present but malformed vault_index refuses instead of silently
    // becoming vault 0.
    let mut bad = flat.clone();
    bad["vault_index"] = json!("primary");
    let rpc = MockRpc::new();
    let err = run(&rpc, &bad, &args("ana", "150", "USDC")).unwrap_err();
    assert!(err.contains("vault_index"), "{err}");
    assert!(
        rpc.log.borrow().is_empty(),
        "must refuse before any network call"
    );
}
