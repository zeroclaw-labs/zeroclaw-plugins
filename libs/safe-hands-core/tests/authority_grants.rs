//! The delegate grant that moves nothing.
//!
//! Found by an independent adversarial review, not by us.
//!
//! Effect analysis diffs balances. An SPL `Approve` CPI'd out of a program the
//! operator has admitted moves **zero lamports and zero tokens** — so every
//! `Movement` is zero, the transaction sits inside any per-transaction cap,
//! and it can reach ALLOW. What it leaves behind is a delegate entitled to
//! move the whole balance later, at which point the drain happens outside this
//! system entirely and no policy here is consulted.
//!
//! `FreezeAccount` and `SetAuthority(CloseAccount)` are invisible the same way.
//!
//! The README used to say the worst case was the operator's cap. It was not.
//! The worst case was an unbounded standing delegate, and the amount at risk
//! was the whole account rather than the amount in the transaction.
//!
//! `effects::authority_changes` closes it by comparing the fields balance
//! diffing skips: delegate, delegated amount, close authority and frozen
//! state.

use safe_hands_core::crypto::TOKEN_PROGRAM;
use safe_hands_core::effects::authority_changes;
use serde_json::{json, Value};

const ACCOUNT: &str = "4rVEeDWz8JsXiTnCH4XJ7poFAzZHxcpv9Wy7SN4ZbMyn";
const TOKEN_ACCOUNT_LEN: usize = 165;

/// A minimal SPL token account, with the fields this test needs.
fn token_account(amount: u64, delegate: Option<[u8; 32]>, delegated: u64, frozen: bool) -> Value {
    let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
    data[0..32].copy_from_slice(&[9u8; 32]); // mint
    data[32..64].copy_from_slice(&[3u8; 32]); // owner
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    if let Some(key) = delegate {
        data[72..76].copy_from_slice(&1u32.to_le_bytes()); // COption::Some
        data[76..108].copy_from_slice(&key);
    }
    data[108] = if frozen { 2 } else { 1 };
    data[121..129].copy_from_slice(&delegated.to_le_bytes());
    json!({
        "lamports": 2_039_280u64,
        "owner": TOKEN_PROGRAM,
        "data": [safe_hands_core::codec::base64_encode(&data), "base64"],
    })
}

fn pair(before: Value, after: Value) -> (Vec<(String, Value)>, Vec<(String, Value)>) {
    (
        vec![(ACCOUNT.to_string(), before)],
        vec![(ACCOUNT.to_string(), after)],
    )
}

#[test]
fn an_approve_that_moves_nothing_is_still_seen() {
    // Same balance before and after — a balance diff reports nothing at all.
    let (before, after) = pair(
        token_account(1_000_000, None, 0, false),
        token_account(1_000_000, Some([7u8; 32]), u64::MAX, false),
    );
    assert_eq!(
        authority_changes(&before, &after),
        vec![ACCOUNT.to_string()],
        "an unlimited delegate grant that moves no value must still be visible"
    );
}

#[test]
fn a_frozen_account_is_seen() {
    let (before, after) = pair(
        token_account(1_000_000, None, 0, false),
        token_account(1_000_000, None, 0, true),
    );
    assert_eq!(
        authority_changes(&before, &after),
        vec![ACCOUNT.to_string()]
    );
}

#[test]
fn a_revoked_delegate_is_seen_too() {
    // Revocation is benign, but "the authority changed" is the fact being
    // reported. Deciding which changes are acceptable is the policy's job, not
    // this function's.
    let (before, after) = pair(
        token_account(1_000_000, Some([7u8; 32]), 500, false),
        token_account(1_000_000, None, 0, false),
    );
    assert_eq!(
        authority_changes(&before, &after),
        vec![ACCOUNT.to_string()]
    );
}

#[test]
fn an_ordinary_transfer_is_not_reported() {
    // The positive control. Without it, a function that returned every account
    // it was handed would pass every test above.
    let (before, after) = pair(
        token_account(1_000_000, None, 0, false),
        token_account(600_000, None, 0, false),
    );
    assert!(
        authority_changes(&before, &after).is_empty(),
        "a plain balance change is not an authority change"
    );
}

#[test]
fn a_delegate_whose_allowance_grows_is_reported() {
    let (before, after) = pair(
        token_account(1_000_000, Some([7u8; 32]), 10, false),
        token_account(1_000_000, Some([7u8; 32]), 900_000, false),
    );
    assert_eq!(
        authority_changes(&before, &after),
        vec![ACCOUNT.to_string()],
        "the delegate is unchanged but what it may take is not"
    );
}

#[test]
fn accounts_present_on_only_one_side_are_not_reported() {
    // Creation and closure already surface as movements; reporting them here
    // as well would make every ATA creation look like an authority change.
    let before: Vec<(String, Value)> = vec![];
    let after = vec![(
        ACCOUNT.to_string(),
        token_account(1_000_000, Some([7u8; 32]), 5, false),
    )];
    assert!(authority_changes(&before, &after).is_empty());
}

#[test]
fn a_non_token_account_is_ignored() {
    let sol = json!({ "lamports": 5_000_000u64, "owner": "11111111111111111111111111111111" });
    let (before, after) = pair(sol.clone(), sol);
    assert!(authority_changes(&before, &after).is_empty());
}
