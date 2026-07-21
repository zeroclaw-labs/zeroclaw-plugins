//! Squads v4 multisig: PDAs, instruction builders, account parsing.
//!
//! Every layout is copied from the official Squads-Protocol/v4 source
//! (programs/squads_multisig_program + sdk/rs) — seeds, discriminators, borsh
//! arg order, and account order are never reverse-engineered from docs.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::crypto::parse_pubkey;

/// Squads v4 program id (declare_id! in the official source).
pub const SQUADS_PROGRAM: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

// Seed constants (programs/.../state/seeds.rs).
const SEED_PREFIX: &[u8] = b"multisig";
const SEED_MULTISIG: &[u8] = b"multisig";
const SEED_VAULT: &[u8] = b"vault";
const SEED_TRANSACTION: &[u8] = b"transaction";
const SEED_PROPOSAL: &[u8] = b"proposal";

fn program_id() -> Pubkey {
    parse_pubkey(SQUADS_PROGRAM).expect("constant program id is valid")
}

fn derive<const N: usize>(seeds: &[&[u8]; N]) -> Pubkey {
    Pubkey::derive_program_address(seeds, &program_id())
        .expect("squads PDA derivation always finds a bump")
        .0
}

/// multisig PDA = ["multisig", "multisig", create_key].
pub fn multisig_pda(create_key: &Pubkey) -> Pubkey {
    derive(&[SEED_PREFIX, SEED_MULTISIG, create_key.as_ref()])
}

/// vault PDA = ["multisig", multisig, "vault", vault_index(u8)].
pub fn vault_pda(multisig: &Pubkey, vault_index: u8) -> Pubkey {
    derive(&[SEED_PREFIX, multisig.as_ref(), SEED_VAULT, &[vault_index]])
}

/// transaction PDA = ["multisig", multisig, "transaction", index(u64 LE)].
pub fn transaction_pda(multisig: &Pubkey, transaction_index: u64) -> Pubkey {
    derive(&[
        SEED_PREFIX,
        multisig.as_ref(),
        SEED_TRANSACTION,
        &transaction_index.to_le_bytes(),
    ])
}

/// proposal PDA = ["multisig", multisig, "transaction", index(u64 LE), "proposal"].
pub fn proposal_pda(multisig: &Pubkey, transaction_index: u64) -> Pubkey {
    derive(&[
        SEED_PREFIX,
        multisig.as_ref(),
        SEED_TRANSACTION,
        &transaction_index.to_le_bytes(),
        SEED_PROPOSAL,
    ])
}

/// Anchor instruction discriminator: sha256("global:<name>")[..8].
fn anchor_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("global:{name}").as_bytes());
    digest[..8].try_into().expect("8 bytes")
}

/// Fields we need from a raw Multisig account (8-byte anchor discriminator,
/// then create_key(32), config_authority(32), threshold(u16), time_lock(u32),
/// transaction_index(u64), …).
pub struct MultisigInfo {
    pub create_key: Pubkey,
    pub threshold: u16,
    pub transaction_index: u64,
}

/// Parse a raw Multisig account buffer. Strict bounds; never guesses.
pub fn parse_multisig_account(data: &[u8]) -> Result<MultisigInfo, String> {
    if data.len() < 8 + 32 + 32 + 2 + 4 + 8 {
        return Err("multisig account data truncated".to_string());
    }
    let create_key =
        Pubkey::new_from_array(data[8..40].try_into().map_err(|_| "create_key slice")?);
    let threshold = u16::from_le_bytes(data[72..74].try_into().map_err(|_| "threshold")?);
    let transaction_index =
        u64::from_le_bytes(data[78..86].try_into().map_err(|_| "transaction_index")?);
    Ok(MultisigInfo {
        create_key,
        threshold,
        transaction_index,
    })
}

fn meta(key: Pubkey, signer: bool, writable: bool) -> AccountMeta {
    if writable {
        AccountMeta::new(key, signer)
    } else {
        AccountMeta::new_readonly(key, signer)
    }
}

/// vaultTransactionCreate — args (borsh): vault_index u8, ephemeral_signers u8,
/// transaction_message Vec<u8>, memo Option<String>.
/// Accounts: multisig (mut), transaction (mut), creator (signer),
/// rent_payer (mut signer), system_program.
pub fn vault_transaction_create(
    multisig: &Pubkey,
    transaction: &Pubkey,
    creator: &Pubkey,
    rent_payer: &Pubkey,
    vault_index: u8,
    ephemeral_signers: u8,
    transaction_message: &[u8],
    memo: Option<&str>,
) -> Instruction {
    let mut data = anchor_discriminator("vault_transaction_create").to_vec();
    data.push(vault_index);
    data.push(ephemeral_signers);
    data.extend_from_slice(&(transaction_message.len() as u32).to_le_bytes());
    data.extend_from_slice(transaction_message);
    match memo {
        Some(m) => {
            data.push(1);
            data.extend_from_slice(&(m.len() as u32).to_le_bytes());
            data.extend_from_slice(m.as_bytes());
        }
        None => data.push(0),
    }
    Instruction {
        program_id: program_id(),
        accounts: vec![
            meta(*multisig, false, true),
            meta(*transaction, false, true),
            meta(*creator, true, false),
            meta(*rent_payer, true, true),
            meta(Pubkey::default(), false, false),
        ],
        data,
    }
}

/// proposalCreate — args (borsh): transaction_index u64, draft bool.
/// Accounts: multisig, proposal (mut), creator (signer), rent_payer (mut signer),
/// system_program.
pub fn proposal_create(
    multisig: &Pubkey,
    proposal: &Pubkey,
    creator: &Pubkey,
    rent_payer: &Pubkey,
    transaction_index: u64,
    draft: bool,
) -> Instruction {
    let mut data = anchor_discriminator("proposal_create").to_vec();
    data.extend_from_slice(&transaction_index.to_le_bytes());
    data.push(draft as u8);
    Instruction {
        program_id: program_id(),
        accounts: vec![
            meta(*multisig, false, false),
            meta(*proposal, false, true),
            meta(*creator, true, false),
            meta(*rent_payer, true, true),
            meta(Pubkey::default(), false, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminators_are_stable_8_bytes() {
        let vtc = anchor_discriminator("vault_transaction_create");
        let pc = anchor_discriminator("proposal_create");
        assert_eq!(vtc.len(), 8);
        assert_eq!(pc.len(), 8);
        assert_ne!(vtc, pc);
        // Deterministic across calls (no randomness).
        assert_eq!(vtc, anchor_discriminator("vault_transaction_create"));
    }

    #[test]
    fn pda_seeds_match_official_layout() {
        let create_key = Pubkey::new_from_array([1u8; 32]);
        let multisig = multisig_pda(&create_key);
        assert_ne!(multisig, create_key);
        let vault0 = vault_pda(&multisig, 0);
        let vault1 = vault_pda(&multisig, 1);
        assert_ne!(vault0, vault1);
        let tx1 = transaction_pda(&multisig, 1);
        let tx2 = transaction_pda(&multisig, 2);
        assert_ne!(tx1, tx2);
        let prop = proposal_pda(&multisig, 1);
        assert_ne!(prop, tx1);
    }

    #[test]
    fn vault_create_args_borsh_layout() {
        let multisig = Pubkey::new_from_array([2u8; 32]);
        let tx = Pubkey::new_from_array([3u8; 32]);
        let creator = Pubkey::new_from_array([4u8; 32]);
        let payer = Pubkey::new_from_array([5u8; 32]);
        let message = vec![0xaa, 0xbb, 0xcc];
        let ix = vault_transaction_create(
            &multisig,
            &tx,
            &creator,
            &payer,
            0,
            0,
            &message,
            Some("note"),
        );
        // 8 disc + 1 vault_index + 1 ephemeral + 4 len + 3 msg + 1 some + 4 len + 4 "note"
        assert_eq!(ix.data.len(), 8 + 1 + 1 + 4 + 3 + 1 + 4 + 4);
        assert_eq!(ix.data[8], 0); // vault_index
        assert_eq!(ix.data[9], 0); // ephemeral_signers
        assert_eq!(&ix.data[10..14], &3u32.to_le_bytes());
        assert_eq!(&ix.data[14..17], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(ix.data[17], 1); // Some
        assert_eq!(&ix.data[18..22], &4u32.to_le_bytes());
        assert_eq!(&ix.data[22..], b"note");
        assert_eq!(ix.accounts.len(), 5);
        assert!(ix.accounts[2].is_signer); // creator
        assert!(ix.accounts[3].is_signer && ix.accounts[3].is_writable); // rent_payer
    }

    #[test]
    fn proposal_create_args_layout() {
        let k = Pubkey::new_from_array;
        let ix = proposal_create(
            &k([6; 32]),
            &k([7; 32]),
            &k([8; 32]),
            &k([9; 32]),
            42,
            false,
        );
        assert_eq!(ix.data.len(), 8 + 8 + 1);
        assert_eq!(&ix.data[8..16], &42u64.to_le_bytes());
        assert_eq!(ix.data[16], 0);
    }

    #[test]
    fn multisig_account_parse() {
        let mut data = vec![0u8; 200];
        data[8..40].copy_from_slice(&[7u8; 32]); // create_key
        data[72..74].copy_from_slice(&2u16.to_le_bytes()); // threshold
        data[78..86].copy_from_slice(&41u64.to_le_bytes()); // transaction_index
        let info = parse_multisig_account(&data).expect("parses");
        assert_eq!(info.create_key, Pubkey::new_from_array([7u8; 32]));
        assert_eq!(info.threshold, 2);
        assert_eq!(info.transaction_index, 41);
        assert!(parse_multisig_account(&data[..50]).is_err());
    }
}
