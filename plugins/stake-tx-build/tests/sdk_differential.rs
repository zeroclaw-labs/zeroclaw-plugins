// The official crates are dev-dependencies for the host target only, so this
// file has nothing to link against under wasm32-wasip2. CI runs clippy with
// --all-targets on that target too, which would otherwise fail here on six
// unresolved imports rather than on anything real.
#![cfg(not(target_family = "wasm"))]

//! Differential test: this crate's hand-rolled encoder against the official crates.
//!
//! The golden tests in `txbuild.rs` pin our bytes against one real mainnet
//! transaction. That proves we got it right once. This file proves we get it
//! right in general: for a spread of generated inputs it builds the same message
//! twice, once with our encoder and once with the official `solana-message` and
//! `solana-stake-interface`, and compares what the runtime actually acts on.
//!
//! The official crates are dev-dependencies only. The shipped component carries
//! no SDK, which is the whole reason the encoder is hand-rolled; keeping the
//! official crates on the test side is what makes that claim checkable.
//!
//! ## Why this compares meaning rather than bytes
//!
//! The first run of this file compared serialized bytes and failed on all three
//! cases, inside the key table: at byte 68 for delegate, at 69 for deactivate,
//! and at 68 or 132 for the durable-nonce case depending on the input. The cause
//! is not in our encoder.
//!
//! We keep readonly keys in order of first appearance across the instructions:
//! `SysvarClock` (`06a7d517…`) before `StakeProgram` (`06a1d817…`) for the single
//! instruction we emit. `solana-message` v2 emits them in ascending order of the
//! key bytes instead, which is what a `BTreeMap` over pubkeys gives you. The real
//! mainnet delegate transaction follows the same first-appearance rule we do; its
//! own sequence differs from ours because it carries four instructions where we
//! carry one. No test in this package pins the message key-table order in either
//! direction, and the goldens compare through per-instruction indices, so the
//! argument below rests on the runtime's behaviour rather than on a golden.
//!
//! Both orders are valid on chain: the runtime does not require any particular
//! order inside the readonly-non-signer group, it resolves accounts through the
//! indices carried by each instruction, and those indices agree with their own
//! table in both encodings. So byte equality against the crate is the wrong
//! question. The right one is whether the transaction *means* the same thing:
//! same keys with the same signer and writable flags, same program, same
//! discriminant, same accounts passed to the instruction.
//!
//! That is what the comparison below does, and it still catches a wrong
//! discriminant, a wrong flag, a missing or extra account, and a wrong program.

use std::collections::BTreeSet;

use solana_hash::Hash;
use solana_message::Message as SdkMessage;
use solana_pubkey::Pubkey;
use solana_stake_interface::instruction as sdk_stake;
use solana_system_interface::instruction as system_instruction;

use stake_tx_build::txbuild::{
    advance_nonce_instruction, compile_message, deactivate_instruction, delegate_stake_instruction,
    serialize_message,
};

/// xorshift64*, so the cases are a spread rather than a handful of literals and
/// still identical on every run and every machine.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn key(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        out
    }
}

/// One account as the runtime sees it: which key, and what it is allowed to do.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Account {
    key: [u8; 32],
    is_signer: bool,
    is_writable: bool,
}

/// One instruction with account indices resolved to the keys they point at, so
/// two encodings with different key tables stay comparable.
#[derive(Debug, PartialEq, Eq)]
struct Call {
    program: [u8; 32],
    accounts: Vec<[u8; 32]>,
    data: Vec<u8>,
}

/// What the transaction means, independent of key ordering.
#[derive(Debug, PartialEq, Eq)]
struct Meaning {
    fee_payer: [u8; 32],
    blockhash: [u8; 32],
    accounts: BTreeSet<Account>,
    /// Length of the message key table. The set above carries no cardinality, so
    /// without this a key repeated in the table with the same flags compares
    /// equal to the same table without the repeat. Confirmed by mutation: with
    /// the set alone, duplicating a trailing key left all five tests green.
    key_count: usize,
    calls: Vec<Call>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.bytes[self.at];
        self.at += 1;
        v
    }

    fn key(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes[self.at..self.at + 32]);
        self.at += 32;
        out
    }

    /// compact-u16, the same shortvec the encoder writes.
    fn compact_u16(&mut self) -> usize {
        let mut value = 0usize;
        let mut shift = 0;
        loop {
            let byte = self.u8();
            value |= ((byte & 0x7f) as usize) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }
}

/// Parse a serialized legacy message into what it means.
fn meaning_of(bytes: &[u8]) -> Meaning {
    let mut r = Reader { bytes, at: 0 };
    let required_signatures = r.u8() as usize;
    let readonly_signed = r.u8() as usize;
    let readonly_unsigned = r.u8() as usize;

    let key_count = r.compact_u16();
    let keys: Vec<[u8; 32]> = (0..key_count).map(|_| r.key()).collect();
    let blockhash = r.key();

    let writable_signers = required_signatures - readonly_signed;
    let writable_unsigned_end = key_count - readonly_unsigned;

    let accounts = keys
        .iter()
        .enumerate()
        .map(|(i, key)| Account {
            key: *key,
            is_signer: i < required_signatures,
            is_writable: i < writable_signers
                || (i >= required_signatures && i < writable_unsigned_end),
        })
        .collect();

    let call_count = r.compact_u16();
    let mut calls = Vec::with_capacity(call_count);
    for _ in 0..call_count {
        let program = keys[r.u8() as usize];
        let account_count = r.compact_u16();
        let accounts = (0..account_count).map(|_| keys[r.u8() as usize]).collect();
        let data_len = r.compact_u16();
        let data = bytes[r.at..r.at + data_len].to_vec();
        r.at += data_len;
        calls.push(Call {
            program,
            accounts,
            data,
        });
    }

    Meaning {
        fee_payer: keys[0],
        blockhash,
        accounts,
        key_count: keys.len(),
        calls,
    }
}

fn ours(
    authority: [u8; 32],
    ixs: &[stake_tx_build::txbuild::Instruction],
    hash: [u8; 32],
) -> Meaning {
    let msg = compile_message(authority, ixs, hash).expect("our encoder compiled the message");
    meaning_of(&serialize_message(&msg))
}

fn theirs(authority: [u8; 32], ixs: &[solana_instruction::Instruction], hash: [u8; 32]) -> Meaning {
    let payer = Pubkey::new_from_array(authority);
    let msg = SdkMessage::new_with_blockhash(ixs, Some(&payer), &Hash::new_from_array(hash));
    meaning_of(&msg.serialize())
}

#[test]
fn delegate_means_the_same_as_the_official_crate() {
    let mut rng = Rng(0x5115_ba11_0000_0001);
    for case in 0..64 {
        let stake = rng.key();
        let authority = rng.key();
        let vote = rng.key();
        let hash = rng.key();

        let mine = ours(
            authority,
            &[delegate_stake_instruction(stake, authority, vote)],
            hash,
        );
        let theirs = theirs(
            authority,
            &[sdk_stake::delegate_stake(
                &Pubkey::new_from_array(stake),
                &Pubkey::new_from_array(authority),
                &Pubkey::new_from_array(vote),
            )],
            hash,
        );
        assert_eq!(mine, theirs, "case {case}");
    }
}

#[test]
fn deactivate_means_the_same_as_the_official_crate() {
    let mut rng = Rng(0xdeac_0000_0000_0001);
    for case in 0..64 {
        let stake = rng.key();
        let authority = rng.key();
        let hash = rng.key();

        let mine = ours(authority, &[deactivate_instruction(stake, authority)], hash);
        let theirs = theirs(
            authority,
            &[sdk_stake::deactivate_stake(
                &Pubkey::new_from_array(stake),
                &Pubkey::new_from_array(authority),
            )],
            hash,
        );
        assert_eq!(mine, theirs, "case {case}");
    }
}

#[test]
fn durable_nonce_delegate_means_the_same_as_the_official_crate() {
    let mut rng = Rng(0x0ce0_0000_0000_0001);
    for case in 0..48 {
        let stake = rng.key();
        let authority = rng.key();
        let vote = rng.key();
        let nonce = rng.key();
        let nonce_authority = rng.key();
        let hash = rng.key();

        let mine = ours(
            authority,
            &[
                advance_nonce_instruction(nonce, nonce_authority),
                delegate_stake_instruction(stake, authority, vote),
            ],
            hash,
        );
        let theirs = theirs(
            authority,
            &[
                system_instruction::advance_nonce_account(
                    &Pubkey::new_from_array(nonce),
                    &Pubkey::new_from_array(nonce_authority),
                ),
                sdk_stake::delegate_stake(
                    &Pubkey::new_from_array(stake),
                    &Pubkey::new_from_array(authority),
                    &Pubkey::new_from_array(vote),
                ),
            ],
            hash,
        );
        assert_eq!(mine, theirs, "case {case}");
    }
}

/// The three tests above would pass on an empty comparison, so this one proves
/// the comparison has teeth: flip one byte of the instruction data and the
/// meaning must stop matching.
#[test]
fn the_comparison_notices_a_flipped_discriminant() {
    let mut rng = Rng(0xbad0_0000_0000_0001);
    let stake = rng.key();
    let authority = rng.key();
    let hash = rng.key();

    let honest = ours(authority, &[deactivate_instruction(stake, authority)], hash);

    let mut tampered_ix = deactivate_instruction(stake, authority);
    tampered_ix.data[0] ^= 0x01;
    let tampered = ours(authority, &[tampered_ix], hash);

    assert_ne!(honest, tampered);
    assert_eq!(honest.accounts, tampered.accounts, "only the data changed");
}

/// And that a wrong account flag is caught too, since the flags are the half of
/// the meaning the runtime enforces.
#[test]
fn the_comparison_notices_a_wrong_writable_flag() {
    let mut rng = Rng(0xf1a6_0000_0000_0001);
    let stake = rng.key();
    let authority = rng.key();
    let hash = rng.key();

    let honest = ours(authority, &[deactivate_instruction(stake, authority)], hash);

    let mut tampered_ix = deactivate_instruction(stake, authority);
    tampered_ix.accounts[0].is_writable = false;
    let tampered = ours(authority, &[tampered_ix], hash);

    assert_ne!(honest.accounts, tampered.accounts);
}
