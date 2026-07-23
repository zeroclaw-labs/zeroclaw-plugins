//! Pure Solana transaction assembly — no wasm, no network, no keys.
//!
//! Builds an **unsigned** SOL or SPL transfer transaction from public keys, an
//! amount, and a recent blockhash, and serializes it to base64 wire bytes for a
//! human's wallet (or a Squads multisig) to sign. It never holds or uses a
//! private key. Uses the modular Solana crates (which compile to `wasm32-wasip2`,
//! unlike the monolithic `solana-sdk`). Native-testable via `cargo test`.

use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};
use solana_message::Message;
use solana_program::hash::Hash;
use solana_program::instruction::Instruction;
use solana_program::pubkey::Pubkey;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;

/// Parse a UI decimal amount into integer base units at `decimals` precision.
/// Integer-safe (no f64); rejects negatives, malformed input, and over-precision.
pub fn ui_to_base_units(amount: &str, decimals: u32) -> Result<u64, String> {
    let s = amount.trim();
    if s.is_empty() {
        return Err("amount is empty".into());
    }
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return Err("amount has no digits".into());
    }
    for c in int_part.chars().chain(frac_part.chars()) {
        if !c.is_ascii_digit() {
            return Err(format!(
                "amount must be a non-negative decimal; found {c:?}"
            ));
        }
    }
    if frac_part.len() > decimals as usize {
        return Err(format!(
            "amount has more precision ({}) than the token supports ({decimals} decimals)",
            frac_part.len()
        ));
    }
    let int_v: u128 = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse()
            .map_err(|_| "amount integer part too large")?
    };
    let mut frac = frac_part.to_string();
    while frac.len() < decimals as usize {
        frac.push('0');
    }
    let frac_v: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse().map_err(|_| "amount fraction invalid")?
    };
    let base = int_v
        .checked_mul(10u128.pow(decimals))
        .and_then(|v| v.checked_add(frac_v))
        .ok_or("amount too large")?;
    u64::try_from(base).map_err(|_| "amount too large for u64 base units".into())
}

fn pubkey(s: &str, field: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(s.trim()).map_err(|e| format!("invalid `{field}` pubkey: {e}"))
}

/// The associated token account address for `owner` + `mint` (base58). Used by
/// the shim to check whether the recipient's ATA already exists.
pub fn associated_token_account(owner: &str, mint: &str) -> Result<String, String> {
    let owner = pubkey(owner, "owner")?;
    let mint = pubkey(mint, "spl_token")?;
    Ok(spl_associated_token_account::get_associated_token_address(&owner, &mint).to_string())
}

fn blockhash(s: &str) -> Result<Hash, String> {
    let bytes = bs58::decode(s.trim())
        .into_vec()
        .map_err(|e| format!("invalid blockhash base58: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "blockhash is not 32 bytes".to_string())?;
    Ok(Hash::new_from_array(arr))
}

/// Serialize an unsigned transaction (payer = `payer`) built from `ixs` and a
/// recent blockhash into base64 wire bytes.
fn assemble(payer: &Pubkey, ixs: &[Instruction], recent_blockhash: &str) -> Result<String, String> {
    let hash = blockhash(recent_blockhash)?;
    let msg = Message::new_with_blockhash(ixs, Some(payer), &hash);
    let tx = Transaction::new_unsigned(msg);
    let wire = bincode::serialize(&tx).map_err(|e| format!("serialize transaction: {e}"))?;
    Ok(STANDARD.encode(wire))
}

/// Build an **unsigned** native SOL transfer. `lamports` is in base units.
pub fn build_sol_transfer(
    from: &str,
    to: &str,
    lamports: u64,
    recent_blockhash: &str,
) -> Result<String, String> {
    let from = pubkey(from, "from")?;
    let to = pubkey(to, "to")?;
    let ix = system_instruction::transfer(&from, &to, lamports);
    assemble(&from, &[ix], recent_blockhash)
}

/// Build an **unsigned** SPL-token transfer (`transfer_checked`) between the
/// owners' associated token accounts, prepending an ATA-creation instruction for
/// the recipient when `create_dest_ata` is set. `amount` is in token base units;
/// `decimals` is the mint's decimals.
#[allow(clippy::too_many_arguments)]
pub fn build_spl_transfer(
    from: &str,
    to: &str,
    mint: &str,
    amount: u64,
    decimals: u8,
    create_dest_ata: bool,
    recent_blockhash: &str,
) -> Result<String, String> {
    use spl_associated_token_account::get_associated_token_address;
    use spl_associated_token_account::instruction::create_associated_token_account;

    let from = pubkey(from, "from")?;
    let to = pubkey(to, "to")?;
    let mint = pubkey(mint, "spl_token")?;

    let source_ata = get_associated_token_address(&from, &mint);
    let dest_ata = get_associated_token_address(&to, &mint);

    let mut ixs: Vec<Instruction> = Vec::new();
    if create_dest_ata {
        // Funder = from (payer); creates the recipient's ATA if it does not exist.
        ixs.push(create_associated_token_account(
            &from,
            &to,
            &mint,
            &spl_token::id(),
        ));
    }
    let transfer_ix = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &source_ata,
        &mint,
        &dest_ata,
        &from,
        &[],
        amount,
        decimals,
    )
    .map_err(|e| format!("build transfer_checked: {e}"))?;
    ixs.push(transfer_ix);

    assemble(&from, &ixs, recent_blockhash)
}
