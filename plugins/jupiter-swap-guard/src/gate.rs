//! The instruction gate: run every guardrail over a parsed Jupiter route and
//! either refuse (fail closed) or return a verdict carrying the validated values
//! the encoder needs. This is where the safety properties become one decision.
//!
//! Checks, in order: mint allowlist + cap + slippage (`P1`/`P3`/`P2`), then a
//! sweep over every instruction for the program allowlist (`P4`), the signer set
//! (`P5`), ATA-create ownership and destination binding (`D1`), fund-moving
//! System instructions (`D2`), and the priority fee (`D4`). `min_out` is computed
//! from the quote the plugin actually received, binding the two API calls (`D3`).
//!
//! Static-vs-lookup account roles (`D5`) are enforced at the encode step, which
//! owns the static/lookup partition; the gate records the accounts that must be
//! static so the encoder can reject any that resolve through a lookup table.

#![forbid(unsafe_code)]

use crate::ata::associated_token_address;
use crate::b58::{decode_pubkey, encode_pubkey};
use crate::decode::{
    decode_compute_budget, decode_system, ComputeBudgetIx, SystemIx, ATA_CREATE_OWNER_INDEX,
    COMPUTE_BUDGET_PROGRAM_ID, SYSTEM_PROGRAM_ID,
};
use crate::encode::Pubkey;
use crate::instruction::Instruction;
use crate::jupiter::{Quote, SwapInstructions};
use crate::policy::{min_out_floor, priority_fee_lamports, Policy, Reject};

/// What the agent asked for (already parsed from the tool arguments).
#[derive(Debug, Clone)]
pub struct SwapRequest {
    pub input_mint: Pubkey,
    pub output_mint: Pubkey,
    pub amount_atoms: u64,
    pub slippage_bps: u16,
}

/// The token programs and ATA program in play, resolved by the caller (from the
/// mint owners via RPC, or from the route's own ATA-create instructions).
#[derive(Debug, Clone)]
pub struct Programs {
    pub input_token_program: Pubkey,
    pub output_token_program: Pubkey,
    pub ata_program: Pubkey,
}

/// The validated result: everything the encoder and summary need, and nothing the
/// aggregator could have tampered with unchecked.
#[derive(Debug, Clone)]
pub struct GuardVerdict {
    /// Minimum output computed from OUR quote (not Jupiter's embedded value).
    pub min_out: u64,
    /// The priority fee the transaction will pay, in lamports.
    pub fee_lamports: u64,
    /// The payer's own ATA the output must land in.
    pub expected_output_ata: Pubkey,
    /// The payer's own ATA the input is drawn from.
    pub expected_input_ata: Pubkey,
    /// Accounts that must appear in the message's STATIC keys (never resolved via
    /// a lookup table) for the guarantees to hold — enforced by the encoder (D5).
    pub must_be_static: Vec<Pubkey>,
}

/// Run the full guard. `Ok` means every property held and the transaction is safe
/// to build; `Err(Reject)` means fail closed — no transaction is emitted.
pub fn evaluate(
    policy: &Policy,
    request: &SwapRequest,
    quote: &Quote,
    swap: &SwapInstructions,
    programs: &Programs,
) -> Result<GuardVerdict, Reject> {
    // P1 / P3 / P2: the request itself, against operator policy.
    policy.require_mint(&request.output_mint)?;
    policy.require_amount_within_cap(&request.input_mint, request.amount_atoms)?;
    policy.require_slippage_within_max(request.slippage_bps)?;

    // D3: bind min_out to the quote WE received (never Jupiter's embedded field).
    let min_out = min_out_floor(quote.out_amount, request.slippage_bps);

    // D1: the payer's own ATAs. The output can only legitimately land here.
    let expected_output_ata = associated_token_address(
        &policy.payer,
        &request.output_mint,
        &programs.output_token_program,
        &programs.ata_program,
    );
    let expected_input_ata = associated_token_address(
        &policy.payer,
        &request.input_mint,
        &programs.input_token_program,
        &programs.ata_program,
    );

    let system = decode_pubkey(SYSTEM_PROGRAM_ID).expect("valid system id");
    let compute_budget = decode_pubkey(COMPUTE_BUDGET_PROGRAM_ID).expect("valid cb id");

    let mut unit_limit: u32 = 200_000; // Solana default if no SetComputeUnitLimit.
    let mut unit_price: u64 = 0;

    for ix in swap.ordered() {
        // P4: top-level program must be allowlisted.
        if !policy.allowed_programs.contains(&ix.program_id) {
            return Err(Reject::ProgramNotAllowed(encode_pubkey(&ix.program_id)));
        }
        // P5: the only signer may be the payer (plus the nonce authority in nonce mode).
        for acc in &ix.accounts {
            if acc.is_signer && !is_allowed_signer(policy, &acc.pubkey) {
                return Err(Reject::UnexpectedSigner(encode_pubkey(&acc.pubkey)));
            }
        }
        // D1a: an ATA-create may only create an ATA the payer owns.
        if ix.program_id == programs.ata_program {
            check_ata_create_owner(&ix, &policy.payer)?;
        }
        // D2: decode fund-moving System instructions.
        if ix.program_id == system {
            check_system_ix(&ix, &policy.payer, &expected_input_ata)?;
        }
        // D4: gather the compute-budget settings.
        if ix.program_id == compute_budget {
            match decode_compute_budget(&ix.data).map_err(Reject::UnsupportedInstruction)? {
                ComputeBudgetIx::SetComputeUnitLimit(l) => unit_limit = l,
                ComputeBudgetIx::SetComputeUnitPrice(p) => unit_price = p,
                ComputeBudgetIx::Other(_) => {}
            }
        }
    }

    // D4: the resulting priority fee must be within the cap.
    let fee_lamports = priority_fee_lamports(unit_limit, unit_price);
    policy.require_priority_fee_within_cap(fee_lamports)?;

    // D1b: the swap output must be bound to the payer's own ATA — it has to appear
    // as a writable account in the swap instruction.
    if !is_writable_account(&swap.swap, &expected_output_ata) {
        return Err(Reject::DestinationNotBound(encode_pubkey(
            &expected_output_ata,
        )));
    }

    Ok(GuardVerdict {
        min_out,
        fee_lamports,
        expected_output_ata,
        expected_input_ata,
        must_be_static: vec![policy.payer, expected_output_ata, expected_input_ata],
    })
}

fn is_allowed_signer(policy: &Policy, key: &Pubkey) -> bool {
    if *key == policy.payer {
        return true;
    }
    matches!(policy.nonce, Some((_, authority)) if authority == *key)
}

fn check_ata_create_owner(ix: &Instruction, payer: &Pubkey) -> Result<(), Reject> {
    let owner = ix
        .accounts
        .get(ATA_CREATE_OWNER_INDEX)
        .ok_or_else(|| Reject::UnsupportedInstruction("ATA create with too few accounts".into()))?;
    if owner.pubkey != *payer {
        return Err(Reject::FundsToNonPayer(encode_pubkey(&owner.pubkey)));
    }
    Ok(())
}

fn check_system_ix(
    ix: &Instruction,
    payer: &Pubkey,
    payer_input_ata: &Pubkey,
) -> Result<(), Reject> {
    match decode_system(&ix.data, ix.accounts.len()).map_err(Reject::UnsupportedInstruction)? {
        SystemIx::Transfer { to_index, .. } => {
            let dest = ix.accounts.get(to_index).ok_or_else(|| {
                Reject::UnsupportedInstruction("System Transfer missing destination".into())
            })?;
            // Only the wSOL wrap (to the payer's own input ATA) or a transfer back
            // to the payer is legitimate in a swap.
            if dest.pubkey != *payer && dest.pubkey != *payer_input_ata {
                return Err(Reject::FundsToNonPayer(encode_pubkey(&dest.pubkey)));
            }
            Ok(())
        }
        SystemIx::Other(tag) => Err(Reject::UnsupportedInstruction(format!(
            "System instruction {tag} in a swap"
        ))),
    }
}

fn is_writable_account(ix: &Instruction, key: &Pubkey) -> bool {
    ix.accounts
        .iter()
        .any(|a| a.pubkey == *key && a.is_writable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ata::{ATA_PROGRAM_ID, TOKEN_PROGRAM_ID};
    use crate::jupiter::{parse_quote, parse_swap_instructions};
    use std::collections::HashMap;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    const WSOL: &str = "So11111111111111111111111111111111111111112";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const PAYER: &str = "4sLWYqVXqQHs7s4PQPrQ2agNVX1y3W4sL5QtzFsuijDz";
    const JUP: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    const SYS: &str = "11111111111111111111111111111111";
    const CB: &str = "ComputeBudget111111111111111111111111111111";

    fn programs() -> Programs {
        Programs {
            input_token_program: decode_pubkey(TOKEN_PROGRAM_ID).unwrap(),
            output_token_program: decode_pubkey(TOKEN_PROGRAM_ID).unwrap(),
            ata_program: decode_pubkey(ATA_PROGRAM_ID).unwrap(),
        }
    }

    fn request() -> SwapRequest {
        SwapRequest {
            input_mint: decode_pubkey(WSOL).unwrap(),
            output_mint: decode_pubkey(USDC).unwrap(),
            amount_atoms: 100_000_000,
            slippage_bps: 50,
        }
    }

    fn policy_with(max_fee: u64) -> Policy {
        let cfg: HashMap<String, String> = [
            ("rpc_url", "https://api.mainnet-beta.solana.com"),
            ("jupiter_base_url", "https://lite-api.jup.ag/swap/v1"),
            ("payer_pubkey", PAYER),
            (
                "allowed_mints",
                &format!("{WSOL}:9:1000000000,{USDC}:6:500000000")[..],
            ),
            ("max_slippage_bps", "50"),
            ("max_priority_fee_lamports", &max_fee.to_string()[..]),
            (
                "allowed_programs",
                &format!("{SYS},{CB},{JUP},{TOKEN_PROGRAM_ID},{ATA_PROGRAM_ID}")[..],
            ),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        Policy::parse(&cfg).unwrap()
    }

    fn fixtures() -> (Quote, SwapInstructions) {
        let q = parse_quote(&std::fs::read_to_string(format!("{FX}/quote.json")).unwrap()).unwrap();
        let s = parse_swap_instructions(
            &std::fs::read_to_string(format!("{FX}/swap-instructions.json")).unwrap(),
        )
        .unwrap();
        (q, s)
    }

    // POSITIVE CONTROL: the real, honest Jupiter route passes every check.
    #[test]
    fn real_route_passes_the_gate() {
        let (q, s) = fixtures();
        // The real route's fee is 100_000 lamports; allow 200_000.
        let v = evaluate(&policy_with(200_000), &request(), &q, &s, &programs()).unwrap();
        assert_eq!(v.fee_lamports, 100_000);
        assert_eq!(v.min_out, min_out_floor(q.out_amount, 50));
        assert_eq!(
            encode_pubkey(&v.expected_output_ata),
            "FMbvJrg96qADXK2QYx2kuEVbSHwbjxAh2z4qeYjd2MSw"
        );
    }

    // NEGATIVE CONTROL (D4): the same route with a tight fee cap is refused.
    #[test]
    fn priority_fee_over_cap_is_refused() {
        let (q, s) = fixtures();
        assert!(matches!(
            evaluate(&policy_with(50_000), &request(), &q, &s, &programs()),
            Err(Reject::PriorityFeeOverMax { .. })
        ));
    }

    // NEGATIVE CONTROL (D2): a System.transfer to an attacker is refused, even
    // though the System program is allowlisted.
    #[test]
    fn system_transfer_to_attacker_is_refused() {
        let (q, mut s) = fixtures();
        let attacker = [9u8; 32];
        // Point the wSOL-wrap transfer's destination at an attacker account.
        for ix in s.setup.iter_mut() {
            if ix.program_id == decode_pubkey(SYS).unwrap() {
                ix.accounts[1].pubkey = attacker;
            }
        }
        assert!(matches!(
            evaluate(&policy_with(200_000), &request(), &q, &s, &programs()),
            Err(Reject::FundsToNonPayer(_))
        ));
    }

    // NEGATIVE CONTROL (D1a): an ATA created for a non-payer owner is refused.
    #[test]
    fn ata_create_for_non_payer_is_refused() {
        let (q, mut s) = fixtures();
        let attacker = [9u8; 32];
        for ix in s.setup.iter_mut() {
            if ix.program_id == decode_pubkey(ATA_PROGRAM_ID).unwrap() {
                ix.accounts[ATA_CREATE_OWNER_INDEX].pubkey = attacker;
            }
        }
        assert!(matches!(
            evaluate(&policy_with(200_000), &request(), &q, &s, &programs()),
            Err(Reject::FundsToNonPayer(_))
        ));
    }

    // NEGATIVE CONTROL (P4): an extra instruction on a non-allowlisted program is refused.
    #[test]
    fn non_allowlisted_program_is_refused() {
        let (q, mut s) = fixtures();
        s.swap.program_id = [7u8; 32]; // unknown program
        assert!(matches!(
            evaluate(&policy_with(200_000), &request(), &q, &s, &programs()),
            Err(Reject::ProgramNotAllowed(_))
        ));
    }

    // NEGATIVE CONTROL (D1b): if the swap's writable destination is not the payer's
    // ATA, the output is not bound and the build is refused.
    #[test]
    fn unbound_destination_is_refused() {
        let (q, mut s) = fixtures();
        // Strip the payer's real output ATA out of the swap's writable set.
        let real = decode_pubkey("FMbvJrg96qADXK2QYx2kuEVbSHwbjxAh2z4qeYjd2MSw").unwrap();
        for a in s.swap.accounts.iter_mut() {
            if a.pubkey == real {
                a.pubkey = [3u8; 32];
            }
        }
        assert!(matches!(
            evaluate(&policy_with(200_000), &request(), &q, &s, &programs()),
            Err(Reject::DestinationNotBound(_))
        ));
    }
}
