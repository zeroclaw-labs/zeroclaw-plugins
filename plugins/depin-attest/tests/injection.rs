//! Prompt-injection defense — fail-closed transcripts (bounty hard req #8).
//!
//! Each test below is the *executable* form of an attack vector documented in
//! the `depin-attest` README ("Prompt-injection test — FAIL CLOSED"). They run
//! the attack through the **real custody guards** the T2 path enforces *before*
//! signing. The thesis: the agent builds its own instructions from the sensor
//! reading (never from message text), and a value-transfer instruction is not
//! expressible — so an LLM-injected "transfer 1 SOL" is inert by construction.
//!
//! Granular per-guard coverage (identity mismatch, key exfiltration via output,
//! config injection) lives in `tests/depin_attest.rs`; this file is the curated,
//! reviewer-facing transcript of the README's four attack vectors.

use std::str::FromStr;

use depin_attest::depin_attest::{
    enforce_daily_cap, enforce_lamport_cap, enforce_program_allowlist, AttestError, DailyCapState,
};
use palinurus_core::{Instruction, Pubkey};

/// SPL Token program — the canonical "value transfer" program an attacker
/// would want signed. It is NOT in the T2 allowlist `{System, SAS, Memo}`.
const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

fn ix(program: Pubkey) -> Instruction {
    Instruction { program_id: program, accounts: vec![], data: vec![] }
}

/// A System program ix with a given instruction-data payload (for discriminator tests).
/// `SystemInstruction::AdvanceNonceAccount` = variant 4 → `[0x04,0x00,0x00,0x00]`;
/// `SystemInstruction::Transfer` = variant 2 → `[0x02,0x00,0x00,0x00]` + 32B pubkey + 8B lamports.
fn sys_ix(data: &[u8]) -> Instruction {
    Instruction { program_id: Pubkey::SYSTEM, accounts: vec![], data: data.to_vec() }
}

const ADVANCE_NONCE_DISC: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

/// Attack 2 (README): an LLM-injected message asks the agent to move funds via a
/// non-allowed program. The T2 program allowlist blocks any value-transfer
/// program — an SPL Token instruction is rejected even if it somehow reached
/// the guard.
#[test]
fn prompt_injection_value_transfer_program_rejected() {
    let token_ix = ix(Pubkey::from_str(SPL_TOKEN).unwrap());
    let err = enforce_program_allowlist(&[token_ix]).unwrap_err();
    assert!(matches!(err, AttestError::Custody(_)));
}

/// F2 hardening: a `System::Transfer` (discriminator `0x02`) passes the
/// *program-level* allowlist (System is allowed) — but value transfer must be
/// unexpressible at the *guard*, not merely by construction. The hardened
/// allowlist rejects any System ix that isn't `AdvanceNonceAccount` (`0x04`).
#[test]
fn prompt_injection_system_transfer_rejected() {
    // System::Transfer = [0x02,0,0,0] + 32B dest + 8B lamports — would move SOL.
    let transfer = sys_ix(&[0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd]);
    let err = enforce_program_allowlist(&[transfer]).unwrap_err();
    assert!(matches!(err, AttestError::Custody(_)));
}

/// F2: a System ix with no data (or < 4 bytes) can't be AdvanceNonceAccount
/// (which is exactly `[0x04,0,0,0]`) → rejected. Nothing ambiguous.
#[test]
fn prompt_injection_short_system_ix_rejected() {
    let short = sys_ix(&[]);
    let err = enforce_program_allowlist(&[short]).unwrap_err();
    assert!(matches!(err, AttestError::Custody(_)));
}

/// F2 sanity: `System::AdvanceNonceAccount` (disc `0x04`) — the only System ix
/// the attestation path constructs — is allowed. The hardening blocks value
/// transfer, not the legitimate durable-nonce advance.
#[test]
fn prompt_injection_system_advance_nonce_allowed() {
    let advance = sys_ix(&ADVANCE_NONCE_DISC);
    enforce_program_allowlist(&[advance]).expect("AdvanceNonceAccount is allowed");
}

/// Sanity: the three programs a real attestation needs — System (as
/// `AdvanceNonceAccount`, disc `0x04`), SAS, Memo — all pass the hardened guard.
#[test]
fn prompt_injection_legit_attest_programs_allowed() {
    let legit = [sys_ix(&ADVANCE_NONCE_DISC), ix(Pubkey::SAS), ix(Pubkey::MEMO)];
    enforce_program_allowlist(&legit).expect("System(AdvanceNonceAccount)/SAS/Memo are the attestation allowlist");
}

/// Attack 4 (README): flood the agent (or roll timestamps) to mint spam
/// attestations. The per-day cap rejects the (cap+1)-th attestation in a UTC
/// day — a replay/flood guard on top of the PDA-uniqueness dedup.
#[test]
fn prompt_injection_daily_cap_blocks_flood() {
    let mut state = DailyCapState { last_day: 100, count: 0 };
    for _ in 0..3 {
        enforce_daily_cap(&mut state, 100, 3).expect("within the daily cap");
    }
    let err = enforce_daily_cap(&mut state, 100, 3).unwrap_err(); // 4th → fail closed
    assert!(matches!(err, AttestError::Custody(_)));
}

/// Secondary bound: even with the session key in hand, the per-tx fee cap
/// bounds spend. An estimated fee above the cap is rejected (the program
/// allowlist is the primary guard; this is defense in depth).
#[test]
fn prompt_injection_fee_cap_blocks_overspend() {
    let err = enforce_lamport_cap(5000, 4, 10_000).unwrap_err(); // 20_000 > 10_000 cap
    assert!(matches!(err, AttestError::Custody(_)));
}
