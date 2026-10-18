//! Golden test for `rescue.rs` against a captured mainnet
//! `repay_obligation_liquidity_v2` transaction. Offline-deterministic: no
//! network access, no writes into the crate.
//!
//! `repay_tx.json` is a version-0 tx with an address lookup table, so
//! whole-tx bytes are not comparable (harden F6): the full account list at
//! execution is `transaction.message.accountKeys` ++
//! `meta.loadedAddresses.writable` ++ `meta.loadedAddresses.readonly`, and
//! per-instruction accounts are indexes into that list.

use std::collections::HashMap;

use liquidation_guard::rescue::{
    base64_decode, base64_encode, build_deposit_tx, build_repay_tx, extract_reserve_accounts,
    parse_nonce_account, refuse_referrer_obligation, NonceInfo, ReserveAccounts, TxOptions,
};
use sha2::{Digest, Sha256};

const REPAY_TX_JSON: &str = include_str!("fixtures/repay_tx.json");
const DEPOSIT_TX_JSON: &str = include_str!("fixtures/deposit_tx.json");
const RESERVE_ACCOUNTS_JSON: &str = include_str!("fixtures/reserve_accounts.json");

const KLEND_PROGRAM_ID: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";

/// One decoded instruction, accounts already resolved to (pubkey,
/// is_signer, is_writable).
struct ResolvedIx {
    program_id: String,
    accounts: Vec<(String, bool, bool)>,
    data: Vec<u8>,
}

/// Parses a captured `getTransaction` fixture (same shape as
/// `repay_tx.json`/`deposit_tx.json`) into the full resolved account list
/// (accountKeys ++ loadedAddresses.writable ++ loadedAddresses.readonly),
/// the ordered resolved instructions, and the recent blockhash.
fn parse_fixture_tx(fixture_json: &str) -> (Vec<String>, Vec<ResolvedIx>, String) {
    let v: serde_json::Value = serde_json::from_str(fixture_json).unwrap();
    let message = &v["transaction"]["message"];
    let static_keys: Vec<String> = message["accountKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    let loaded_writable: Vec<String> = v["meta"]["loadedAddresses"]["writable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    let loaded_readonly: Vec<String> = v["meta"]["loadedAddresses"]["readonly"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();

    let num_required_sigs = message["header"]["numRequiredSignatures"].as_u64().unwrap() as usize;
    let num_readonly_signed = message["header"]["numReadonlySignedAccounts"]
        .as_u64()
        .unwrap() as usize;
    let num_readonly_unsigned = message["header"]["numReadonlyUnsignedAccounts"]
        .as_u64()
        .unwrap() as usize;

    let static_len = static_keys.len();
    let num_loaded_writable = loaded_writable.len();

    let mut full_keys = static_keys.clone();
    full_keys.extend(loaded_writable);
    full_keys.extend(loaded_readonly);

    let flags = |i: usize| -> (bool, bool) {
        if i < static_len {
            let is_signer = i < num_required_sigs;
            let is_writable = if is_signer {
                i < num_required_sigs - num_readonly_signed
            } else {
                i < static_len - num_readonly_unsigned
            };
            (is_signer, is_writable)
        } else {
            let loaded_idx = i - static_len;
            (false, loaded_idx < num_loaded_writable)
        }
    };

    let resolved: Vec<ResolvedIx> = message["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|ix| {
            let program_idx = ix["programIdIndex"].as_u64().unwrap() as usize;
            let accounts: Vec<(String, bool, bool)> = ix["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    let idx = a.as_u64().unwrap() as usize;
                    let (is_signer, is_writable) = flags(idx);
                    (full_keys[idx].clone(), is_signer, is_writable)
                })
                .collect();
            let data_b58 = ix["data"].as_str().unwrap();
            let data = bs58::decode(data_b58).into_vec().unwrap();
            ResolvedIx {
                program_id: full_keys[program_idx].clone(),
                accounts,
                data,
            }
        })
        .collect();

    let recent_blockhash = message["recentBlockhash"].as_str().unwrap().to_string();
    (full_keys, resolved, recent_blockhash)
}

/// Parses the trimmed `reserve_accounts.json` fixture into (market,
/// {reserve pubkey -> base64 account data}).
fn parse_fixture_reserves() -> (String, HashMap<String, String>) {
    let v: serde_json::Value = serde_json::from_str(RESERVE_ACCOUNTS_JSON).unwrap();
    let entry = &v[0];
    let market = entry["market"].as_str().unwrap().to_string();
    let mut map = HashMap::new();
    for r in entry["reserves"].as_array().unwrap() {
        map.insert(
            r["pubkey"].as_str().unwrap().to_string(),
            r["data"].as_str().unwrap().to_string(),
        );
    }
    (market, map)
}

/// Decodes our own unsigned legacy tx base64 output into the same
/// `ResolvedIx` shape as the fixture parser, for direct comparison.
fn parse_our_tx(tx_base64: &str) -> (Vec<u8>, Vec<ResolvedIx>, u8) {
    let wire = base64_decode(tx_base64).unwrap();
    let mut pos = 0;

    let sig_count = read_compact_u16(&wire, &mut pos);
    assert_eq!(sig_count, 1);
    let signature = wire[pos..pos + 64].to_vec();
    pos += 64;

    let num_required_sigs = wire[pos] as usize;
    let num_readonly_signed = wire[pos + 1] as usize;
    let num_readonly_unsigned = wire[pos + 2] as usize;
    pos += 3;

    let key_count = read_compact_u16(&wire, &mut pos) as usize;
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        keys.push(bs58::encode(&wire[pos..pos + 32]).into_string());
        pos += 32;
    }
    pos += 32; // blockhash

    let flags = |i: usize| -> (bool, bool) {
        let is_signer = i < num_required_sigs;
        let is_writable = if is_signer {
            i < num_required_sigs - num_readonly_signed
        } else {
            i < key_count - num_readonly_unsigned
        };
        (is_signer, is_writable)
    };

    let ix_count = read_compact_u16(&wire, &mut pos) as usize;
    let mut ixs = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_idx = wire[pos] as usize;
        pos += 1;
        let acc_count = read_compact_u16(&wire, &mut pos) as usize;
        let mut accounts = Vec::with_capacity(acc_count);
        for _ in 0..acc_count {
            let idx = wire[pos] as usize;
            pos += 1;
            let (is_signer, is_writable) = flags(idx);
            accounts.push((keys[idx].clone(), is_signer, is_writable));
        }
        let data_len = read_compact_u16(&wire, &mut pos) as usize;
        let data = wire[pos..pos + data_len].to_vec();
        pos += data_len;
        ixs.push(ResolvedIx {
            program_id: keys[program_idx].clone(),
            accounts,
            data,
        });
    }
    assert_eq!(pos, wire.len(), "trailing bytes after parsing our own tx");
    (signature, ixs, num_required_sigs as u8)
}

fn read_compact_u16(bytes: &[u8], pos: &mut usize) -> u16 {
    let mut n: u16 = 0;
    let mut shift = 0;
    loop {
        let byte = bytes[*pos];
        *pos += 1;
        n |= ((byte & 0x7f) as u16) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    n
}

/// Extracts owner/obligation/market/repay_reserve/amount and the ordered
/// obligation-reserves list (deposits then borrows) straight from the
/// fixture's own instructions, then extracts every reserve's accounts from
/// the reserve_accounts fixture. `options` threads straight into
/// `build_repay_tx` so the fee-on/fee-off tests can share this exact
/// fixture-driven path.
fn build_plan_from_fixture(
    options: &TxOptions,
) -> (liquidation_guard::rescue::RescuePlan, Vec<ResolvedIx>) {
    let (_full_keys, fixture_ixs, blockhash) = parse_fixture_tx(REPAY_TX_JSON);
    let (market, reserve_data) = parse_fixture_reserves();

    let klend_ixs: Vec<ResolvedIx> = fixture_ixs
        .into_iter()
        .filter(|ix| ix.program_id == KLEND_PROGRAM_ID)
        .collect();
    assert_eq!(
        klend_ixs.len(),
        8,
        "expected 6 refresh_reserve + refresh_obligation + repay"
    );

    let refresh_obligation_ix = &klend_ixs[6];
    let repay_ix = &klend_ixs[7];

    let owner = repay_ix.accounts[0].0.clone();
    let obligation = repay_ix.accounts[1].0.clone();
    let repay_reserve = repay_ix.accounts[3].0.clone();
    assert_eq!(repay_ix.accounts[2].0, market, "repay ix market mismatch");

    assert_eq!(repay_ix.data.len(), 16, "repay ix data = disc + u64 amount");
    let amount_native = u64::from_le_bytes(repay_ix.data[8..16].try_into().unwrap());
    // repay ix data = 74aed54cb435d290c0ef0b0800000000 (disc ++ u64 LE
    // amount); c0ef0b0800000000 = 135,000,000 native units, matching the
    // pinned tx's log ("Repaying obligation liquidity 135000000") and its
    // pre/post user token balances (135000000 -> 0).
    assert_eq!(
        amount_native, 135_000_000,
        "pinned tx repays 135,000,000 native units"
    );

    let obligation_reserve_pubkeys: Vec<String> = refresh_obligation_ix.accounts[2..]
        .iter()
        .map(|(pk, _, _)| pk.clone())
        .collect();
    assert_eq!(obligation_reserve_pubkeys.len(), 6);

    let obligation_reserves: Vec<ReserveAccounts> = obligation_reserve_pubkeys
        .iter()
        .map(|pk| {
            let data = reserve_data
                .get(pk)
                .unwrap_or_else(|| panic!("fixture missing reserve account data for {pk}"));
            extract_reserve_accounts(pk, data, &market)
                .unwrap_or_else(|e| panic!("extract_reserve_accounts({pk}) failed: {e}"))
        })
        .collect();

    let plan = build_repay_tx(
        &owner,
        &obligation,
        &market,
        &obligation_reserves,
        &repay_reserve,
        amount_native,
        &blockhash,
        options,
    )
    .expect("build_repay_tx failed");

    (plan, klend_ixs)
}

/// Mirrors `build_plan_from_fixture` for the captured deposit tx
/// (`deposit_tx.json`, v11-deposit-encoder). Unlike repay, the deposit
/// reserve in this specific captured tx is *not* part of
/// `refresh_obligation`'s remaining accounts (a brand-new collateral
/// reserve for the obligation) — so
/// `obligation_reserves` (for `refresh_obligation`) and the deposit
/// reserve's own `ReserveAccounts` (for `build_deposit_tx`'s separate
/// parameter) are extracted from two different sources: the former from
/// `refresh_obligation`'s remaining accounts (5), the latter from the
/// deposit instruction's own `reserve` account (index 4).
fn build_deposit_plan_from_fixture(
    options: &TxOptions,
) -> (liquidation_guard::rescue::RescuePlan, Vec<ResolvedIx>) {
    let (_full_keys, fixture_ixs, blockhash) = parse_fixture_tx(DEPOSIT_TX_JSON);
    let (market, reserve_data) = parse_fixture_reserves();

    let klend_ixs: Vec<ResolvedIx> = fixture_ixs
        .into_iter()
        .filter(|ix| ix.program_id == KLEND_PROGRAM_ID)
        .collect();
    assert_eq!(
        klend_ixs.len(),
        8,
        "expected 6 refresh_reserve + refresh_obligation + deposit"
    );

    let refresh_obligation_ix = &klend_ixs[6];
    let deposit_ix = &klend_ixs[7];

    let owner = deposit_ix.accounts[0].0.clone();
    let obligation = deposit_ix.accounts[1].0.clone();
    let deposit_reserve_pk = deposit_ix.accounts[4].0.clone();
    assert_eq!(
        deposit_ix.accounts[2].0, market,
        "deposit ix market mismatch"
    );

    assert_eq!(
        deposit_ix.data.len(),
        16,
        "deposit ix data = disc + u64 amount"
    );
    let amount_native = u64::from_le_bytes(deposit_ix.data[8..16].try_into().unwrap());
    // deposit ix data = d8e0bf1bcc9766afd95ce2bb13000000 (disc ++ u64 LE
    // amount); d95ce2bb13000000 = 84,756,552,921 native units, matching the
    // pinned tx's log ("DepositReserveLiquidityAndObligationCollateral
    // Reserve d4A2prbA2whesmvHaL88BH6Ewn5N4bTSU2Ze8P6Bc4Q amount
    // 84756552921").
    assert_eq!(
        amount_native, 84_756_552_921,
        "pinned tx deposits 84,756,552,921 native units"
    );

    let obligation_reserve_pubkeys: Vec<String> = refresh_obligation_ix.accounts[2..]
        .iter()
        .map(|(pk, _, _)| pk.clone())
        .collect();
    assert_eq!(
        obligation_reserve_pubkeys.len(),
        5,
        "pinned tx's obligation has 5 pre-existing reserves \
         (the 6th, deposit target, is brand new)"
    );
    assert!(
        !obligation_reserve_pubkeys.contains(&deposit_reserve_pk),
        "deposit reserve must NOT already be one of the obligation's own reserves in this fixture"
    );

    let obligation_reserves: Vec<ReserveAccounts> = obligation_reserve_pubkeys
        .iter()
        .map(|pk| {
            let data = reserve_data
                .get(pk)
                .unwrap_or_else(|| panic!("fixture missing reserve account data for {pk}"));
            extract_reserve_accounts(pk, data, &market)
                .unwrap_or_else(|e| panic!("extract_reserve_accounts({pk}) failed: {e}"))
        })
        .collect();

    let deposit_reserve_data = reserve_data
        .get(&deposit_reserve_pk)
        .unwrap_or_else(|| panic!("fixture missing reserve account data for {deposit_reserve_pk}"));
    let deposit_reserve =
        extract_reserve_accounts(&deposit_reserve_pk, deposit_reserve_data, &market)
            .unwrap_or_else(|e| {
                panic!("extract_reserve_accounts({deposit_reserve_pk}) failed: {e}")
            });

    let plan = build_deposit_tx(
        &owner,
        &obligation,
        &market,
        &obligation_reserves,
        &deposit_reserve,
        amount_native,
        &blockhash,
        options,
    )
    .expect("build_deposit_tx failed");

    (plan, klend_ixs)
}

/// `refresh_reserve`'s discriminator, duplicated locally (also asserted in
/// `discriminator_derivation`) so [`assert_klend_ixs_match`] can identify
/// its oracle-account slots without exporting a private `rescue.rs` const.
const DISC_REFRESH_RESERVE: [u8; 8] = [0x02, 0xda, 0x8a, 0xeb, 0x4f, 0xc9, 0x19, 0x66];

/// Byte-compares our own encoder output against a captured mainnet tx's
/// real klend instructions — program ids, data (discriminator + args), and
/// every account's (pubkey, is_signer, is_writable) — instruction by
/// instruction. Shared by both `golden_repay_v2_matches_captured_tx` and
/// `golden_deposit_v2_matches_captured_tx`.
///
/// One narrow, documented relaxation: `refresh_reserve`'s four oracle
/// slots (pyth/switchboard/switchboard_twap/scope_prices, account indices
/// 2..6) are always declared readonly by klend itself — `refresh_reserve`
/// only *reads* them, it never writes. The captured deposit tx's own
/// `febGYTnFX...`/`ApQkX32U...` reserves show one such slot as writable
/// because an EARLIER, out-of-scope instruction in that same transaction
/// (`Program log: Instruction: RefreshPriceList` — Kamino's Scope
/// price-oracle push, which this encoder never replicates, see the
/// captured deposit tx) genuinely writes to that account:
/// Solana's legacy tx format assigns one writable/signer flag per pubkey
/// for the WHOLE transaction, so that unrelated instruction's requirement
/// leaks into every other instruction referencing the same pubkey. Skips
/// the `is_writable` assertion ONLY when ours says readonly (klend's true,
/// safe-to-build requirement) and the fixture says writable (the leaked
/// artifact) on one of those four slots — every other account, and every
/// other direction of mismatch, is still asserted strictly.
fn assert_klend_ixs_match(our_ixs: &[ResolvedIx], klend_ixs: &[ResolvedIx]) {
    assert_eq!(our_ixs.len(), klend_ixs.len(), "instruction count mismatch");
    for (i, (ours, fixture)) in our_ixs.iter().zip(klend_ixs.iter()).enumerate() {
        assert_eq!(ours.program_id, fixture.program_id, "ix {i}: program id");
        assert_eq!(
            ours.data, fixture.data,
            "ix {i}: data (discriminator + args)"
        );
        assert_eq!(
            ours.accounts.len(),
            fixture.accounts.len(),
            "ix {i}: account count"
        );
        let is_refresh_reserve =
            fixture.data.len() >= 8 && fixture.data[..8] == DISC_REFRESH_RESERVE;
        for (j, (o, f)) in ours
            .accounts
            .iter()
            .zip(fixture.accounts.iter())
            .enumerate()
        {
            assert_eq!(o.0, f.0, "ix {i} account {j}: pubkey");
            assert_eq!(o.1, f.1, "ix {i} account {j} ({}): is_signer", o.0);
            let oracle_slot_writable_artifact =
                is_refresh_reserve && (2..6).contains(&j) && !o.2 && f.2;
            if !oracle_slot_writable_artifact {
                assert_eq!(o.2, f.2, "ix {i} account {j} ({}): is_writable", o.0);
            }
        }
    }
}

/// v11-deposit-encoder: byte-compares our own `build_deposit_tx` output
/// against the captured mainnet deposit tx's real klend instructions. Same
/// method as `golden_repay_v2_matches_captured_tx`.
#[test]
fn golden_deposit_v2_matches_captured_tx() {
    let (plan, klend_ixs) = build_deposit_plan_from_fixture(&TxOptions::default());
    let (_sigs, our_ixs, num_required_sigs) = parse_our_tx(&plan.tx_base64);
    assert_eq!(num_required_sigs, 1);
    assert_klend_ixs_match(&our_ixs, &klend_ixs);
}

/// v11-deposit-encoder: referrer-bearing obligations are refused for the
/// deposit remedy too — same shared `refuse_referrer_obligation` guard
/// `build_repay_tx`'s call site uses.
#[test]
fn deposit_referrer_refused() {
    assert!(refuse_referrer_obligation(Some("SomeReferrerPubkey1111111111111111111111")).is_err());
    assert!(refuse_referrer_obligation(None).is_ok());
}

#[test]
fn golden_repay_v2_matches_captured_tx() {
    let (plan, klend_ixs) = build_plan_from_fixture(&TxOptions::default());
    let (_sigs, our_ixs, num_required_sigs) = parse_our_tx(&plan.tx_base64);
    assert_eq!(num_required_sigs, 1);
    assert_klend_ixs_match(&our_ixs, &klend_ixs);
}

#[test]
fn unsigned_single_zeroed_signature_slot() {
    let (plan, _klend_ixs) = build_plan_from_fixture(&TxOptions::default());
    let wire = base64_decode(&plan.tx_base64).unwrap();
    let mut pos = 0;
    let sig_count = read_compact_u16(&wire, &mut pos);
    assert_eq!(sig_count, 1, "exactly one signature slot");
    let sig = &wire[pos..pos + 64];
    assert!(
        sig.iter().all(|&b| b == 0),
        "signature slot must be all zero"
    );
    pos += 64;
    let num_required_signatures = wire[pos];
    assert_eq!(num_required_signatures, 1);
}

#[test]
fn discriminator_derivation() {
    let disc = |preimage: &str| -> [u8; 8] {
        let hash = Sha256::digest(preimage.as_bytes());
        hash[..8].try_into().unwrap()
    };
    assert_eq!(
        disc("global:refresh_reserve"),
        [0x02, 0xda, 0x8a, 0xeb, 0x4f, 0xc9, 0x19, 0x66]
    );
    assert_eq!(
        disc("global:refresh_obligation"),
        [0x21, 0x84, 0x93, 0xe4, 0x97, 0xc0, 0x48, 0x59]
    );
    assert_eq!(
        disc("global:repay_obligation_liquidity_v2"),
        [0x74, 0xae, 0xd5, 0x4c, 0xb4, 0x35, 0xd2, 0x90]
    );
    assert_eq!(
        disc("account:Reserve"),
        [0x2b, 0xf2, 0xcc, 0xca, 0x1a, 0xf7, 0x3b, 0x7f]
    );
}

#[test]
fn referrer_obligation_refused() {
    assert!(refuse_referrer_obligation(Some("SomeReferrerPubkey1111111111111111111111")).is_err());
    assert!(refuse_referrer_obligation(None).is_ok());
}

#[test]
fn wrong_discriminator_refused() {
    let (market, reserve_data) = parse_fixture_reserves();
    let (pk, data_b64) = reserve_data.iter().next().unwrap();
    let mut raw = base64_decode(data_b64).unwrap();
    raw[0] ^= 0xff; // corrupt the account discriminator
    let corrupted = base64_encode(&raw);
    let err = extract_reserve_accounts(pk, &corrupted, &market).unwrap_err();
    assert!(
        err.contains("discriminator"),
        "error should name the discriminator mismatch: {err}"
    );
}

/// Pins `mint_decimals` against externally-known values for every reserve
/// in the fixture.
///
/// This was the single most dangerous untested thing in the crate.
/// `mint_decimals` is the sole scaling factor turning a UI amount into the
/// native amount that goes into transaction bytes (`guard::ui_to_native`,
/// both money paths) and back out for display. The golden transaction tests
/// cannot catch a wrong `OFF_MINT_DECIMALS`: they pass the amount in already
/// native, read straight out of the capture. So a bad offset — or a reserve
/// whose layout differs — would silently mis-scale every rescue by a power
/// of ten while the whole suite stayed green. Its only defence was a comment
/// claiming manual verification.
///
/// The expected values are common knowledge about the assets, independent of
/// this crate and of the fixture bytes, which is what makes the assertion
/// real rather than circular.
#[test]
fn mint_decimals_extracted_at_the_right_offset() {
    let (market, reserve_data) = parse_fixture_reserves();
    let expected: &[(&str, u8)] = &[
        ("febGYTnFX4GbSGoFHFeJXUHgNaK53fB23uDins9Jp1E", 8), // ETH
        ("HV9KsS5mB4b9CFhDJVKdfxWBAomYfUk5PeUsdgMQsUrB", 9), // pSOL
        ("D6q6wuQSrifJKZYpR1M8R4YawnLDtDsMmWM1NbBmgJ59", 6), // USDC
        ("d4A2prbA2whesmvHaL88BH6Ewn5N4bTSU2Ze8P6Bc4Q", 9), // SOL
        ("ESCkPWKHmgNE7Msf77n9yzqJd5kQVWWGy3o5Mgxhvavp", 6), // USDG
        ("ApQkX32ULJUzszZDe986aobLDLMNDoGQK8tRm6oD6SsA", 6), // CASH
        ("37Jk2zkz23vkAYBT66HM2gaqJuNg2nYLsCreQAVt5MWK", 8), // cbBTC
        ("2gc9Dm1eB6UgVYFBUN9bWks6Kes9PbWSaPaa9DqyvEiN", 6), // PYUSD
    ];

    let mut checked = 0;
    for (pk, want) in expected {
        let Some(data) = reserve_data.get(*pk) else {
            continue;
        };
        let accounts = extract_reserve_accounts(pk, data, &market)
            .unwrap_or_else(|e| panic!("extract_reserve_accounts({pk}) failed: {e}"));
        assert_eq!(
            accounts.mint_decimals, *want,
            "{pk}: mint_decimals must match the asset's real decimals"
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        expected.len(),
        "fixture no longer carries every reserve this test pins"
    );
}

#[test]
fn wrong_length_refused() {
    let (market, reserve_data) = parse_fixture_reserves();
    let (pk, data_b64) = reserve_data.iter().next().unwrap();
    let raw = base64_decode(data_b64).unwrap();
    let truncated = base64_encode(&raw[..raw.len() - 8]);
    let err = extract_reserve_accounts(pk, &truncated, &market).unwrap_err();
    assert!(
        err.contains("8624"),
        "error should name the expected length: {err}"
    );
}

#[test]
fn market_mismatch_refused() {
    let (_market, reserve_data) = parse_fixture_reserves();
    let (pk, data_b64) = reserve_data.iter().next().unwrap();
    let err = extract_reserve_accounts(pk, data_b64, "Wr0ngMarket11111111111111111111111111111")
        .unwrap_err();
    assert!(
        err.contains("lending_market"),
        "error should name the market mismatch: {err}"
    );
}

const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

/// v11-priority-fee: fee off (the default) builds the exact same 8
/// instructions as before, with no compute-budget program id anywhere in
/// its account keys — proves the feature is byte-identical-off.
#[test]
fn fee_off_build_unchanged() {
    let (plan, _klend_ixs) = build_plan_from_fixture(&TxOptions::default());
    let (_sigs, our_ixs, _num_required_sigs) = parse_our_tx(&plan.tx_base64);
    assert_eq!(our_ixs.len(), 8, "fee-off build must have exactly 8 ixs");
    assert!(
        our_ixs
            .iter()
            .all(|ix| ix.program_id != COMPUTE_BUDGET_PROGRAM_ID
                && ix
                    .accounts
                    .iter()
                    .all(|(pk, _, _)| pk != COMPUTE_BUDGET_PROGRAM_ID)),
        "fee-off build must never reference the compute-budget program id"
    );
}

/// v11-priority-fee: fee on prepends exactly `SetComputeUnitLimit` +
/// `SetComputeUnitPrice` ahead of the untouched 8-ix fee-off sequence — the
/// same fixture path, same accounts, same everything from index 2 on.
#[test]
fn fee_on_prepends_compute_budget_ixs() {
    let fee: u64 = 12_345;
    let options = TxOptions {
        priority_fee_microlamports: Some(fee),
        ..TxOptions::default()
    };
    let (fee_on_plan, _) = build_plan_from_fixture(&options);
    let (fee_off_plan, _) = build_plan_from_fixture(&TxOptions::default());

    let (_sigs, fee_on_ixs, _) = parse_our_tx(&fee_on_plan.tx_base64);
    let (_sigs, fee_off_ixs, _) = parse_our_tx(&fee_off_plan.tx_base64);

    assert_eq!(
        fee_on_ixs.len(),
        fee_off_ixs.len() + 2,
        "fee-on build must have exactly 2 extra leading ixs"
    );

    // RESCUE_CU_LIMIT is not exported; mirror it here rather than importing a
    // private const, matching the derivation comment in src/rescue.rs.
    const RESCUE_CU_LIMIT: u32 = 900_000;

    // Regression guard for the defect this constant actually had. Setting a
    // compute-unit limit *lowers* the budget: with no compute-budget
    // instruction the runtime grants `min(n_ix * 200_000, 1_400_000)`, so this
    // 8-instruction build already gets 1,400,000 CU. A ceiling pinned to this
    // one 6-reserve fixture (261,070 consumed -> the old 400,000) was below
    // what a larger obligation needs, so turning the priority fee ON could
    // fail a rescue that succeeded with it OFF — backwards for a knob meant
    // for congestion. The ceiling must cover klend's worst case (8 deposits +
    // 5 borrows) and stay under the runtime maximum.
    // Compile-time, so reintroducing a too-low ceiling cannot even build.
    const WORST_CASE_CU: u32 = 13 * 37_000 + 90_000;
    const _: () = assert!(
        RESCUE_CU_LIMIT >= WORST_CASE_CU,
        "CU ceiling is under the worst-case obligation cost"
    );
    const _: () = assert!(
        RESCUE_CU_LIMIT <= 1_400_000,
        "CU ceiling exceeds the runtime maximum"
    );

    let mut expected_limit_data = vec![2u8];
    expected_limit_data.extend_from_slice(&RESCUE_CU_LIMIT.to_le_bytes());
    assert_eq!(fee_on_ixs[0].program_id, COMPUTE_BUDGET_PROGRAM_ID);
    assert!(fee_on_ixs[0].accounts.is_empty());
    assert_eq!(fee_on_ixs[0].data, expected_limit_data);

    let mut expected_price_data = vec![3u8];
    expected_price_data.extend_from_slice(&fee.to_le_bytes());
    assert_eq!(fee_on_ixs[1].program_id, COMPUTE_BUDGET_PROGRAM_ID);
    assert!(fee_on_ixs[1].accounts.is_empty());
    assert_eq!(fee_on_ixs[1].data, expected_price_data);

    for (i, (on, off)) in fee_on_ixs[2..].iter().zip(fee_off_ixs.iter()).enumerate() {
        assert_eq!(on.program_id, off.program_id, "ix {i}: program id");
        assert_eq!(on.data, off.data, "ix {i}: data");
        assert_eq!(
            on.accounts.len(),
            off.accounts.len(),
            "ix {i}: account count"
        );
        for (j, (a, b)) in on.accounts.iter().zip(off.accounts.iter()).enumerate() {
            assert_eq!(a, b, "ix {i} account {j}: (pubkey, is_signer, is_writable)");
        }
    }
}

// ---------------------------------------------------------------------
// v11-durable-nonce.
// ---------------------------------------------------------------------

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
const SYSVAR_RECENT_BLOCKHASHES_ID: &str = "SysvarRecentB1ockHashes11111111111111111111";
/// Stand-in nonce account address: any valid base58 32-byte pubkey works,
/// this test never reads or writes a real on-chain account.
const NONCE_ACCOUNT: &str = "AcNSmd5CxwLs21TYUmhWt7CW2v159TdYRkvQxb1iBYRj";

/// Extracts the fee payer (`owner`) the golden fixture's own captured
/// `repay_obligation_liquidity_v2` instruction uses, so nonce tests can
/// build an authority-matching synthetic blob without re-deriving the
/// whole plan.
fn fixture_owner() -> String {
    let (_full_keys, fixture_ixs, _blockhash) = parse_fixture_tx(REPAY_TX_JSON);
    let klend_ixs: Vec<ResolvedIx> = fixture_ixs
        .into_iter()
        .filter(|ix| ix.program_id == KLEND_PROGRAM_ID)
        .collect();
    klend_ixs[7].accounts[0].0.clone()
}

/// Synthesizes a valid 80-byte system-nonce-account blob: u32 LE version
/// (1) ++ u32 LE state (1, initialized) ++ 32-byte authority ++ 32-byte
/// stored nonce value ++ u64 LE lamports-per-signature.
fn synth_nonce_blob(authority: &str, stored_value: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&bs58::decode(authority).into_vec().unwrap());
    data.extend_from_slice(stored_value);
    data.extend_from_slice(&5000u64.to_le_bytes());
    assert_eq!(data.len(), 80);
    data
}

/// Reads the message's blockhash field (32 bytes right after the key
/// list) straight out of our own encoded tx bytes.
fn extract_message_blockhash(tx_base64: &str) -> [u8; 32] {
    let wire = base64_decode(tx_base64).unwrap();
    let mut pos = 0;
    let _sig_count = read_compact_u16(&wire, &mut pos);
    pos += 64; // zeroed signature slot
    pos += 3; // header
    let key_count = read_compact_u16(&wire, &mut pos) as usize;
    pos += key_count * 32; // keys
    wire[pos..pos + 32].try_into().unwrap()
}

/// `parse_nonce_account` extracts the stored value from a synthesized
/// blob; `build_repay_tx` with `nonce` set puts `AdvanceNonceAccount` at
/// instruction index 0 with the exact accounts/data, and stamps the
/// stored value into the message blockhash field. With both nonce and fee
/// on, the combined order is [advance, cu-limit, cu-price, ...klend...].
#[test]
fn nonce_account_parsed_and_applied() {
    let owner = fixture_owner();
    let stored_value_bytes = [7u8; 32];
    let stored_value = bs58::encode(stored_value_bytes).into_string();
    let blob = synth_nonce_blob(&owner, &stored_value_bytes);

    let parsed = parse_nonce_account(SYSTEM_PROGRAM_ID, &blob, &owner)
        .expect("valid nonce blob with matching authority must parse");
    assert_eq!(parsed, stored_value);

    let nonce = NonceInfo {
        account: NONCE_ACCOUNT.to_string(),
        authority: owner.clone(),
        stored_value: stored_value.clone(),
    };
    let options = TxOptions {
        priority_fee_microlamports: None,
        nonce: Some(nonce.clone()),
    };
    let (plan, _klend_ixs) = build_plan_from_fixture(&options);
    let (_sigs, our_ixs, _num_sigs) = parse_our_tx(&plan.tx_base64);

    assert_eq!(our_ixs[0].program_id, SYSTEM_PROGRAM_ID);
    assert_eq!(our_ixs[0].data, vec![4, 0, 0, 0]);
    assert_eq!(our_ixs[0].accounts.len(), 3);
    assert_eq!(our_ixs[0].accounts[0].0, NONCE_ACCOUNT);
    assert!(!our_ixs[0].accounts[0].1, "nonce account: not a signer");
    assert!(our_ixs[0].accounts[0].2, "nonce account: writable");
    assert_eq!(our_ixs[0].accounts[1].0, SYSVAR_RECENT_BLOCKHASHES_ID);
    assert!(
        !our_ixs[0].accounts[1].1,
        "recent-blockhashes sysvar: not a signer"
    );
    assert!(
        !our_ixs[0].accounts[1].2,
        "recent-blockhashes sysvar: readonly"
    );
    assert_eq!(our_ixs[0].accounts[2].0, owner);
    assert!(our_ixs[0].accounts[2].1, "authority: signer");

    let bh = extract_message_blockhash(&plan.tx_base64);
    assert_eq!(
        bh, stored_value_bytes,
        "message blockhash must be the stored nonce value"
    );

    // Both nonce and fee on: [advance, cu-limit, cu-price, ...klend...].
    let both_options = TxOptions {
        priority_fee_microlamports: Some(999),
        nonce: Some(nonce),
    };
    let (both_plan, klend_ixs) = build_plan_from_fixture(&both_options);
    let (_sigs, both_ixs, _) = parse_our_tx(&both_plan.tx_base64);
    assert_eq!(both_ixs.len(), klend_ixs.len() + 3);
    assert_eq!(
        both_ixs[0].program_id, SYSTEM_PROGRAM_ID,
        "ix 0: advance-nonce"
    );
    assert_eq!(
        both_ixs[1].program_id, COMPUTE_BUDGET_PROGRAM_ID,
        "ix 1: cu-limit"
    );
    assert_eq!(both_ixs[1].data[0], 2, "ix 1: SetComputeUnitLimit tag");
    assert_eq!(
        both_ixs[2].program_id, COMPUTE_BUDGET_PROGRAM_ID,
        "ix 2: cu-price"
    );
    assert_eq!(both_ixs[2].data[0], 3, "ix 2: SetComputeUnitPrice tag");
    for (i, (ix, k)) in both_ixs[3..].iter().zip(klend_ixs.iter()).enumerate() {
        assert_eq!(ix.program_id, k.program_id, "combined ix {i}: program id");
        assert_eq!(ix.data, k.data, "combined ix {i}: data");
    }
}

#[test]
fn nonce_wrong_authority_refused() {
    let owner = fixture_owner();
    let blob = synth_nonce_blob(&owner, &[7u8; 32]);
    let err = parse_nonce_account(SYSTEM_PROGRAM_ID, &blob, KLEND_PROGRAM_ID).unwrap_err();
    assert!(
        err.contains("authority"),
        "error should name the authority mismatch: {err}"
    );
}

#[test]
fn nonce_wrong_owner_refused() {
    let owner = fixture_owner();
    let blob = synth_nonce_blob(&owner, &[7u8; 32]);
    let err = parse_nonce_account(KLEND_PROGRAM_ID, &blob, &owner).unwrap_err();
    assert!(
        err.contains("owner"),
        "error should name the owner mismatch: {err}"
    );
}

#[test]
fn nonce_bad_state_refused() {
    let owner = fixture_owner();
    let mut blob = synth_nonce_blob(&owner, &[7u8; 32]);
    blob[4..8].copy_from_slice(&0u32.to_le_bytes()); // uninitialized
    let err = parse_nonce_account(SYSTEM_PROGRAM_ID, &blob, &owner).unwrap_err();
    assert!(
        err.contains("state"),
        "error should name the state mismatch: {err}"
    );
}

/// v11-durable-nonce: nonce off (the default) builds the exact same
/// instruction set as before (8, or 10 with fee also on), with no
/// system-program advance ix present anywhere.
#[test]
fn nonce_off_build_unchanged() {
    let (plan, _klend_ixs) = build_plan_from_fixture(&TxOptions::default());
    let (_sigs, our_ixs, _num_sigs) = parse_our_tx(&plan.tx_base64);
    assert_eq!(our_ixs.len(), 8, "nonce-off build must have exactly 8 ixs");
    assert!(
        our_ixs.iter().all(|ix| ix.program_id != SYSTEM_PROGRAM_ID),
        "nonce-off build must never reference the system program id"
    );

    let fee_options = TxOptions {
        priority_fee_microlamports: Some(500),
        ..TxOptions::default()
    };
    let (fee_plan, _) = build_plan_from_fixture(&fee_options);
    let (_sigs, fee_ixs, _) = parse_our_tx(&fee_plan.tx_base64);
    assert_eq!(
        fee_ixs.len(),
        10,
        "nonce-off, fee-on build must have exactly 10 ixs"
    );
    assert!(
        fee_ixs.iter().all(|ix| ix.program_id != SYSTEM_PROGRAM_ID),
        "nonce-off build must never reference the system program id"
    );
}

/// Live-evidence builder (integrate stage, `#[ignore]` — needs env vars,
/// run explicitly). Builds the fee+nonce composed rescue tx from the
/// committed golden fixture against a REAL mainnet durable-nonce account
/// (account pubkey + freshly-fetched stored value supplied via env) and
/// writes the base64 tx to `LIVE_NONCE_TX_OUT` for an out-of-plugin
/// `simulateTransaction` (curl; the plugin itself never simulates or
/// sends). The nonce authority is set to the fixture's owner — the exact
/// shape `guard::run` builds — so a real node is expected to REJECT the
/// simulation on the foreign stored authority's missing signature: the
/// same condition `parse_nonce_account` refuses fail-closed before a tx
/// is ever built. The evidence value is structural: a real node
/// sanitizes the composed message and engages the durable-nonce path
/// with `advance_nonce_account` at index 0.
#[test]
#[ignore]
fn live_nonce_fee_tx_builds() {
    let nonce_account =
        std::env::var("LIVE_NONCE_ACCOUNT").expect("LIVE_NONCE_ACCOUNT must be set");
    let stored_value = std::env::var("LIVE_NONCE_STORED").expect("LIVE_NONCE_STORED must be set");
    let out_path = std::env::var("LIVE_NONCE_TX_OUT").expect("LIVE_NONCE_TX_OUT must be set");

    let (_keys, fixture_ixs, _blockhash) = parse_fixture_tx(REPAY_TX_JSON);
    let owner = fixture_ixs
        .iter()
        .filter(|ix| ix.program_id == KLEND_PROGRAM_ID)
        .nth(7)
        .expect("fixture has 8 klend ixs")
        .accounts[0]
        .0
        .clone();

    let options = TxOptions {
        priority_fee_microlamports: Some(1000),
        nonce: Some(NonceInfo {
            account: nonce_account,
            authority: owner,
            stored_value: stored_value.clone(),
        }),
    };
    let (plan, _) = build_plan_from_fixture(&options);

    let (_sigs, our_ixs, _) = parse_our_tx(&plan.tx_base64);
    assert_eq!(
        our_ixs.len(),
        11,
        "nonce-on, fee-on build = advance_nonce + 2 compute-budget + 8 klend ixs"
    );
    assert_eq!(
        our_ixs[0].program_id, SYSTEM_PROGRAM_ID,
        "advance_nonce_account must be instruction index 0"
    );

    std::fs::write(&out_path, &plan.tx_base64).unwrap_or_else(|e| panic!("write {out_path}: {e}"));
    eprintln!(
        "wrote live nonce+fee rescue tx ({} bytes b64, nonce stored value {stored_value}) to {out_path}",
        plan.tx_base64.len()
    );
}
