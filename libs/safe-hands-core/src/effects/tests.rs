//! Effect analysis is only worth anything if it cannot be fooled by moving
//! value around inside a wallet, and if it refuses to guess when the node is
//! unhelpful. Most of these push on one of those two edges.

use super::*;
use crate::codec::base64_encode;
use crate::crypto::{TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use crate::rpc::MockTransport;
use proptest::prelude::*;

const WALLET: &str = "5Z6Ay5NEcbg3xhopc522sBCRXQujkTiuDRnHGfQdcnSf";
const OTHER: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const ATA_A: &str = "3wvJdyFnGvaMWpbq93NU91SggiVRveULUXL6iX5VZDGP";
const ATA_B: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const SYSTEM: &str = "11111111111111111111111111111111";

fn key(base58: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let decoded = bs58::decode(base58).into_vec().expect("base58");
    out.copy_from_slice(&decoded);
    out
}

/// A classic SPL token account, as the RPC renders it.
fn token_account(mint: &str, owner: &str, amount: u64, lamports: u64, program: &str) -> Value {
    let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
    data[0..32].copy_from_slice(&key(mint));
    data[32..64].copy_from_slice(&key(owner));
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = TOKEN_STATE_INITIALIZED;
    json!({
        "lamports": lamports,
        "owner": program,
        "data": [base64_encode(&data), "base64"],
    })
}

/// A plain system-owned account.
fn system_account(lamports: u64) -> Value {
    json!({"lamports": lamports, "owner": SYSTEM, "data": ["", "base64"]})
}

fn guarded(owners: &[&str]) -> BTreeSet<String> {
    owners.iter().map(|o| o.to_string()).collect()
}

// ── reading accounts ────────────────────────────────────────────────────────

#[test]
fn a_token_account_yields_its_balance_and_its_rent() {
    let balances = balances_of(
        ATA_A,
        &token_account(USDC, WALLET, 1_000, 2_039_280, TOKEN_PROGRAM),
    );
    assert_eq!(
        balances,
        vec![
            Balance {
                address: ATA_A.into(),
                mint: Some(USDC.into()),
                owner: WALLET.into(),
                raw: 1_000
            },
            // The rent belongs to whoever owns the token account, so draining
            // it shows up against the wallet that would lose it.
            Balance {
                address: ATA_A.into(),
                mint: None,
                owner: WALLET.into(),
                raw: 2_039_280
            },
        ]
    );
}

#[test]
fn token_2022_accounts_read_with_the_same_offsets() {
    let balances = balances_of(
        ATA_A,
        &token_account(USDC, WALLET, 7, 1, TOKEN_2022_PROGRAM),
    );
    assert_eq!(balances[0].mint.as_deref(), Some(USDC));
    assert_eq!(balances[0].raw, 7);
}

/// Token-2022 appends extension bytes after the base layout. The base offsets
/// must still be read, or every extended account would look like a plain one.
#[test]
fn a_token_2022_account_with_extensions_still_parses() {
    let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
    data[0..32].copy_from_slice(&key(USDC));
    data[32..64].copy_from_slice(&key(WALLET));
    data[64..72].copy_from_slice(&99u64.to_le_bytes());
    data[108] = TOKEN_STATE_INITIALIZED;
    data.push(2); // account type discriminant
    data.extend_from_slice(&[0xab; 64]); // extension payload
    let account = json!({
        "lamports": 5,
        "owner": TOKEN_2022_PROGRAM,
        "data": [base64_encode(&data), "base64"],
    });
    assert_eq!(balances_of(ATA_A, &account)[0].raw, 99);
}

/// A frozen account still holds value, and freezing must not make it invisible.
#[test]
fn a_frozen_token_account_is_still_a_balance() {
    let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
    data[0..32].copy_from_slice(&key(USDC));
    data[32..64].copy_from_slice(&key(WALLET));
    data[64..72].copy_from_slice(&500u64.to_le_bytes());
    data[108] = TOKEN_STATE_FROZEN;
    let account =
        json!({"lamports": 1, "owner": TOKEN_PROGRAM, "data": [base64_encode(&data), "base64"]});
    assert_eq!(balances_of(ATA_A, &account)[0].raw, 500);
}

/// An account that merely happens to be the right length is not a token
/// account. Misreading one would invent balances that do not exist.
#[test]
fn a_look_alike_account_is_not_read_as_tokens() {
    // Right length, right program, uninitialized state.
    let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
    data[64..72].copy_from_slice(&u64::MAX.to_le_bytes());
    data[108] = 0;
    let uninitialized =
        json!({"lamports": 9, "owner": TOKEN_PROGRAM, "data": [base64_encode(&data), "base64"]});
    assert_eq!(balances_of(ATA_A, &uninitialized)[0].mint, None);

    // Right length and state, wrong program.
    data[108] = TOKEN_STATE_INITIALIZED;
    let foreign = json!({"lamports": 9, "owner": SYSTEM, "data": [base64_encode(&data), "base64"]});
    let read = balances_of(ATA_A, &foreign);
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].mint, None);

    // Too short.
    let stub = json!({"lamports": 9, "owner": TOKEN_PROGRAM, "data": [base64_encode(&[0u8; 64]), "base64"]});
    assert_eq!(balances_of(ATA_A, &stub)[0].mint, None);
}

/// A closed account reads as zero rather than as silence: saying nothing would
/// make "drained and closed" look like "unchanged".
#[test]
fn a_missing_account_reads_as_zero() {
    assert_eq!(
        balances_of(ATA_A, &Value::Null),
        vec![Balance {
            address: ATA_A.into(),
            mint: None,
            owner: ATA_A.into(),
            raw: 0
        }]
    );
}

// ── movements ───────────────────────────────────────────────────────────────

fn effects(before: Vec<Balance>, after: Vec<Balance>) -> Effects {
    Effects { before, after }
}

fn token(address: &str, owner: &str, raw: u128) -> Balance {
    Balance {
        address: address.into(),
        mint: Some(USDC.into()),
        owner: owner.into(),
        raw,
    }
}

fn sol(address: &str, raw: u128) -> Balance {
    Balance {
        address: address.into(),
        mint: None,
        owner: address.into(),
        raw,
    }
}

#[test]
fn a_transfer_out_is_an_outflow_for_the_sender_and_an_inflow_for_the_receiver() {
    let fx = effects(
        vec![token(ATA_A, WALLET, 1_000), token(ATA_B, OTHER, 0)],
        vec![token(ATA_A, WALLET, 400), token(ATA_B, OTHER, 600)],
    );
    let movements = fx.movements();
    // Sorted by owner, so the wallet (base58 "5Z6A…") precedes "AKnL…".
    assert_eq!(
        movements,
        vec![
            Movement {
                owner: WALLET.into(),
                asset: USDC.into(),
                out_raw: 600,
                in_raw: 0
            },
            Movement {
                owner: OTHER.into(),
                asset: USDC.into(),
                out_raw: 0,
                in_raw: 600
            },
        ]
    );
    assert_eq!(fx.outflows(&guarded(&[WALLET])).len(), 1);
    assert_eq!(fx.outflows(&guarded(&[WALLET]))[0].out_raw, 600);
    assert!(fx.outflows(&guarded(&[OTHER])).is_empty());
}

/// The reason movements aggregate by owner rather than by account: shuffling
/// value between two of your own token accounts must net to nothing, or every
/// internal rebalance would trip the cap.
#[test]
fn moving_value_between_your_own_accounts_is_not_an_outflow() {
    let fx = effects(
        vec![token(ATA_A, WALLET, 1_000), token(ATA_B, WALLET, 0)],
        vec![token(ATA_A, WALLET, 0), token(ATA_B, WALLET, 1_000)],
    );
    assert!(fx.movements().is_empty());
    assert!(fx.outflows(&guarded(&[WALLET])).is_empty());
}

/// And the reason it must not be evadable the other way: splitting a drain
/// across several of the wallet's accounts still totals to one outflow.
#[test]
fn a_drain_split_across_accounts_still_totals() {
    let fx = effects(
        vec![
            token(ATA_A, WALLET, 500),
            token(ATA_B, WALLET, 500),
            token("11111111111111111111111111111112", OTHER, 0),
        ],
        vec![
            token(ATA_A, WALLET, 100),
            token(ATA_B, WALLET, 100),
            token("11111111111111111111111111111112", OTHER, 800),
        ],
    );
    let out = fx.outflows(&guarded(&[WALLET]));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].out_raw, 800);
}

#[test]
fn a_swap_shows_one_asset_leaving_and_another_arriving() {
    let wsol = "So11111111111111111111111111111111111111112";
    let fx = Effects {
        before: vec![
            token(ATA_A, WALLET, 1_000_000),
            Balance {
                address: ATA_B.into(),
                mint: Some(wsol.into()),
                owner: WALLET.into(),
                raw: 0,
            },
        ],
        after: vec![
            token(ATA_A, WALLET, 0),
            Balance {
                address: ATA_B.into(),
                mint: Some(wsol.into()),
                owner: WALLET.into(),
                raw: 5_000_000,
            },
        ],
    };
    let movements = fx.movements();
    assert_eq!(movements.len(), 2);
    let usdc = movements.iter().find(|m| m.asset == USDC).expect("usdc");
    assert_eq!(usdc.out_raw, 1_000_000);
    let sol_leg = movements.iter().find(|m| m.asset == wsol).expect("wsol");
    assert_eq!(sol_leg.in_raw, 5_000_000);
    // Only the leg that left is an outflow — receiving is never a violation.
    assert_eq!(fx.outflows(&guarded(&[WALLET])).len(), 1);
}

#[test]
fn sol_movements_are_tracked_alongside_tokens() {
    let fx = effects(vec![sol(WALLET, 10_000)], vec![sol(WALLET, 4_000)]);
    let out = fx.outflows(&guarded(&[WALLET]));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].asset, SOL);
    assert_eq!(out[0].out_raw, 6_000);
}

/// Rent extraction: the token balance is untouched, the account is closed, and
/// the lamports go elsewhere. Attributing an account's rent to its owner is
/// what makes this visible.
#[test]
fn closing_a_token_account_shows_the_rent_leaving_its_owner() {
    let before = balances_of(
        ATA_A,
        &token_account(USDC, WALLET, 0, 2_039_280, TOKEN_PROGRAM),
    );
    let after = balances_of(ATA_A, &Value::Null);
    let fx = Effects { before, after };
    let movements = fx.movements();
    let lost = movements
        .iter()
        .find(|m| m.owner == WALLET && m.asset == SOL)
        .expect("the owner loses the rent");
    assert_eq!(lost.out_raw, 2_039_280);
}

#[test]
fn an_unguarded_owner_is_not_reported() {
    let fx = effects(vec![token(ATA_B, OTHER, 900)], vec![token(ATA_B, OTHER, 0)]);
    assert!(fx.outflows(&guarded(&[WALLET])).is_empty());
    assert_eq!(fx.outflows(&guarded(&[OTHER]))[0].out_raw, 900);
}

#[test]
fn no_change_is_no_movement() {
    let fx = effects(
        vec![token(ATA_A, WALLET, 1_000), sol(WALLET, 5)],
        vec![token(ATA_A, WALLET, 1_000), sol(WALLET, 5)],
    );
    assert!(fx.movements().is_empty());
}

// ── observation ─────────────────────────────────────────────────────────────

fn decoded(payer: &str, others: &[&str]) -> DecodedTx {
    use crate::crypto::parse_pubkey;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::Message;

    let payer_key = parse_pubkey(payer).expect("payer");
    let accounts: Vec<AccountMeta> = others
        .iter()
        .map(|a| AccountMeta::new(parse_pubkey(a).expect("account"), false))
        .collect();
    let instruction = Instruction {
        program_id: parse_pubkey(SYSTEM).expect("system"),
        accounts,
        data: vec![0],
    };
    let message = Message::new(&[instruction], Some(&payer_key));
    let wire = crate::codec::unsigned_transaction_bytes(
        &bincode::serialize(&message).expect("serialize"),
        message.header.num_required_signatures as usize,
    )
    .expect("wire");
    crate::decode::decode(&wire).expect("decode")
}

fn observing(pre: Value, post: Value) -> MockTransport {
    MockTransport::new()
        .with("getMultipleAccounts", pre)
        .with("simulateTransaction", post)
}

#[test]
fn observation_diffs_pre_state_against_simulated_post_state() {
    let tx = decoded(WALLET, &[ATA_A]);
    let addresses = writable_accounts(&tx);
    assert_eq!(addresses.len(), 2, "payer and the named writable account");

    // Addresses are sorted, so build the answers in the same order.
    let answer = |amount_a: u64, lamports: u64| -> Vec<Value> {
        addresses
            .iter()
            .map(|address| {
                if address == ATA_A {
                    token_account(USDC, WALLET, amount_a, 2_039_280, TOKEN_PROGRAM)
                } else {
                    system_account(lamports)
                }
            })
            .collect()
    };

    let rpc = observing(
        json!({"result": {"value": answer(1_000, 900_000)}}),
        json!({"result": {"value": {"err": null, "accounts": answer(250, 895_000)}}}),
    );
    let fx = observe(&rpc, &tx).expect("observed");
    let out = fx.outflows(&guarded(&[WALLET]));
    assert_eq!(out.len(), 2, "the token leg and the fee");
    let usdc = out.iter().find(|m| m.asset == USDC).expect("usdc leg");
    assert_eq!(usdc.out_raw, 750);
    let fee = out.iter().find(|m| m.asset == SOL).expect("sol leg");
    assert_eq!(fee.out_raw, 5_000);
}

/// Every way the node can be unhelpful has to end in an error, never in an
/// empty set of effects that reads as "nothing moved".
#[test]
fn an_unhelpful_node_is_an_error_and_never_an_empty_result() {
    let tx = decoded(WALLET, &[ATA_A]);
    let two = vec![system_account(1), system_account(1)];

    let cases: Vec<(&str, MockTransport)> = vec![
        (
            "no pre-state array",
            observing(
                json!({"result": {}}),
                json!({"result": {"value": {"err": null, "accounts": two.clone()}}}),
            ),
        ),
        (
            "pre-state length mismatch",
            observing(
                json!({"result": {"value": [system_account(1)]}}),
                json!({"result": {"value": {"err": null, "accounts": two.clone()}}}),
            ),
        ),
        (
            "no post-state accounts",
            observing(
                json!({"result": {"value": two.clone()}}),
                json!({"result": {"value": {"err": null}}}),
            ),
        ),
        (
            "post-state length mismatch",
            observing(
                json!({"result": {"value": two.clone()}}),
                json!({"result": {"value": {"err": null, "accounts": [system_account(1)]}}}),
            ),
        ),
        (
            "missing err field",
            observing(
                json!({"result": {"value": two.clone()}}),
                json!({"result": {"value": {"accounts": two.clone()}}}),
            ),
        ),
        (
            "simulation itself failed",
            observing(
                json!({"result": {"value": two.clone()}}),
                json!({"result": {"value": {"err": {"InstructionError": []}, "accounts": two.clone()}}}),
            ),
        ),
        (
            "json-rpc error",
            observing(
                json!({"result": {"value": two.clone()}}),
                json!({"error": {"code": -32000, "message": "nope"}}),
            ),
        ),
    ];

    for (name, rpc) in cases {
        assert!(
            observe(&rpc, &tx).is_err(),
            "{name} should have been an error"
        );
    }
}

#[test]
fn the_fee_payer_is_always_observed_even_when_no_instruction_names_it() {
    let tx = decoded(WALLET, &[ATA_A]);
    assert!(writable_accounts(&tx).contains(&WALLET.to_string()));
}

/// Read-only accounts cannot change, so observing them would only cost RPC
/// weight. They must still never be silently counted as writable.
#[test]
fn read_only_accounts_are_not_observed() {
    use crate::crypto::parse_pubkey;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::Message;

    let payer = parse_pubkey(WALLET).expect("payer");
    let instruction = Instruction {
        program_id: parse_pubkey(SYSTEM).expect("system"),
        accounts: vec![
            AccountMeta::new(parse_pubkey(ATA_A).expect("a"), false),
            AccountMeta::new_readonly(parse_pubkey(ATA_B).expect("b"), false),
        ],
        data: vec![0],
    };
    let message = Message::new(&[instruction], Some(&payer));
    let wire = crate::codec::unsigned_transaction_bytes(
        &bincode::serialize(&message).expect("serialize"),
        message.header.num_required_signatures as usize,
    )
    .expect("wire");
    let tx = crate::decode::decode(&wire).expect("decode");

    let writable = writable_accounts(&tx);
    assert!(writable.contains(&ATA_A.to_string()));
    assert!(!writable.contains(&ATA_B.to_string()));
}

// ── properties ──────────────────────────────────────────────────────────────

proptest! {
    /// Value is conserved: whatever an owner is recorded as losing, some owner
    /// is recorded as gaining, for every asset. A movement table that failed
    /// this would be inventing or destroying balances.
    #[test]
    fn movements_conserve_value(
        amounts in proptest::collection::vec(0u64..1_000_000, 2..8),
    ) {
        let owners = [WALLET, OTHER];
        let before: Vec<Balance> = amounts
            .iter()
            .enumerate()
            .map(|(i, raw)| token(ATA_A, owners[i % 2], *raw as u128))
            .collect();
        // Rotate the amounts between the same owners: total is unchanged.
        let mut rotated = amounts.clone();
        rotated.rotate_left(1);
        let after: Vec<Balance> = rotated
            .iter()
            .enumerate()
            .map(|(i, raw)| token(ATA_A, owners[i % 2], *raw as u128))
            .collect();

        let movements = Effects { before, after }.movements();
        let out: u128 = movements.iter().map(|m| m.out_raw).sum();
        let inn: u128 = movements.iter().map(|m| m.in_raw).sum();
        prop_assert_eq!(out, inn);
    }

    /// An owner is never recorded as both sending and receiving the same asset:
    /// the net is what a cap should be applied to, and reporting both sides
    /// would let a large drain hide behind a large deposit.
    #[test]
    fn a_movement_is_net_and_one_directional(
        before_raw in 0u128..1_000_000,
        after_raw in 0u128..1_000_000,
    ) {
        let fx = effects(
            vec![token(ATA_A, WALLET, before_raw)],
            vec![token(ATA_A, WALLET, after_raw)],
        );
        for movement in fx.movements() {
            prop_assert!(movement.out_raw == 0 || movement.in_raw == 0);
        }
    }

    /// Guarding nobody reports nothing, whatever moved.
    #[test]
    fn an_empty_guard_set_reports_nothing(
        before_raw in 0u128..1_000_000,
        after_raw in 0u128..1_000_000,
    ) {
        let fx = effects(
            vec![token(ATA_A, WALLET, before_raw)],
            vec![token(ATA_A, WALLET, after_raw)],
        );
        prop_assert!(fx.outflows(&BTreeSet::new()).is_empty());
    }
}
