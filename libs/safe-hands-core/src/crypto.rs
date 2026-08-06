//! Address derivation: PDAs and Associated Token Accounts via `solana-pubkey`
//! (validator-grade curve checks included — no hand-rolled ed25519).

use solana_pubkey::Pubkey;
use std::str::FromStr;

/// The SPL Token program (classic).
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// The Token-2022 program.
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// The Associated Token Account program.
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// The System program.
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// Parse a base58 address into a `Pubkey`, rejecting anything that is not a
/// canonical 32-byte base58 string.
pub fn parse_pubkey(input: &str) -> Result<Pubkey, String> {
    let input = input.trim();
    Pubkey::from_str(input).map_err(|_| format!("invalid base58 pubkey: {input:?}"))
}

/// Derive the Associated Token Account address for (owner, token program, mint).
/// Seed order is owner → token program → mint, per the ATA spec.
pub fn ata_address(owner: &Pubkey, token_program: &Pubkey, mint: &Pubkey) -> Pubkey {
    let owner_b: &[u8] = owner.as_ref();
    let token_b: &[u8] = token_program.as_ref();
    let mint_b: &[u8] = mint.as_ref();
    let (ata, _bump) = Pubkey::derive_program_address(
        &[owner_b, token_b, mint_b],
        &parse_pubkey(ATA_PROGRAM).expect("constant program id is valid"),
    )
    .expect("ATA derivation always finds a valid bump");
    ata
}

/// Convenience wrapper taking base58 strings.
pub fn ata_address_str(owner: &str, token_program: &str, mint: &str) -> Result<String, String> {
    let owner = parse_pubkey(owner)?;
    let token_program = parse_pubkey(token_program)?;
    let mint = parse_pubkey(mint)?;
    Ok(ata_address(&owner, &token_program, &mint).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector generated independently with @solana/web3.js v1
    /// (scratch/golden-gen/gen.js): keypair from seed [1;32], classic SPL token
    /// program, mainnet USDC mint.
    #[test]
    fn ata_matches_web3js_golden() {
        let ata = ata_address_str(
            "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9",
            TOKEN_PROGRAM,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        )
        .expect("derivation");
        assert_eq!(ata, "3wvJdyFnGvaMWpbq93NU91SggiVRveULUXL6iX5VZDGP");
    }

    #[test]
    fn rejects_bad_pubkeys() {
        assert!(parse_pubkey("not-a-key").is_err());
        assert!(parse_pubkey("").is_err());
        assert!(parse_pubkey("0x1234").is_err());
    }

    #[test]
    fn system_program_is_all_zeros() {
        let system = parse_pubkey(SYSTEM_PROGRAM).expect("system");
        assert_eq!(system.as_ref(), &[0u8; 32]);
    }
}
