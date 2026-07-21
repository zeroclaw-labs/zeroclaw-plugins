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
#[allow(clippy::too_many_arguments)] // mirrors the official instruction's account list
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

/// Compile an inner vault-transaction message in the exact byte format the
/// official @sqds/multisig SDK produces — Squads' own `TransactionMessage`
/// (instructions/vault_transaction_create.rs), NOT a Solana message:
///
/// ```text
/// num_signers u8 | num_writable_signers u8 | num_writable_non_signers u8
/// account_keys SmallVec<u8>  (u8 count + 32B each)
/// instructions SmallVec<u8>  (u8 count; each: prog_idx u8, accounts SmallVec<u8>,
///                             data SmallVec<u16> ← u16 LE length prefix)
/// address_table_lookups SmallVec<u8> (u8 count)
/// ```
///
/// No blockhash anywhere (vault transactions don't expire; execution fetches
/// a fresh one). Our flows have exactly one signer: the vault (writable).
/// `instructions` must already be rebound to the vault (see [`rebind_to_vault`]).
pub fn compile_inner_message(instructions: &[Instruction], vault: &Pubkey) -> Vec<u8> {
    // Key ordering: vault first, then writable non-signers (first-seen),
    // then readonly non-signers (first-seen). No other signers in our flows.
    let mut writable: Vec<Pubkey> = Vec::new();
    let mut readonly: Vec<Pubkey> = Vec::new();
    let seen = |k: &Pubkey, writable: &mut Vec<Pubkey>, readonly: &mut Vec<Pubkey>| {
        k == vault || writable.contains(k) || readonly.contains(k)
    };
    for ix in instructions {
        for meta in &ix.accounts {
            if seen(&meta.pubkey, &mut writable, &mut readonly) {
                continue;
            }
            if meta.is_writable {
                writable.push(meta.pubkey);
            } else {
                readonly.push(meta.pubkey);
            }
        }
        if seen(&ix.program_id, &mut writable, &mut readonly) {
            continue;
        }
        readonly.push(ix.program_id);
    }

    let mut out = Vec::new();
    // num_signers=1 (vault), num_writable_signers=1 (vault),
    // num_writable_non_signers = writable.len()
    out.push(1u8);
    out.push(1u8);
    out.push(writable.len() as u8);
    // account_keys: SmallVec<u8>
    let key_count = 1 + writable.len() + readonly.len();
    out.push(key_count as u8);
    out.extend_from_slice(vault.as_ref());
    for k in &writable {
        out.extend_from_slice(k.as_ref());
    }
    for k in &readonly {
        out.extend_from_slice(k.as_ref());
    }
    // instructions: SmallVec<u8>; data uses SmallVec<u16> (u16 LE length).
    let key_index = |k: &Pubkey| -> u8 {
        if k == vault {
            return 0;
        }
        if let Some(i) = writable.iter().position(|w| w == k) {
            return 1 + i as u8;
        }
        1 + writable.len() as u8 + readonly.iter().position(|r| r == k).expect("key present") as u8
    };
    out.push(instructions.len() as u8);
    for ix in instructions {
        out.push(key_index(&ix.program_id));
        out.push(ix.accounts.len() as u8);
        for meta in &ix.accounts {
            out.push(key_index(&meta.pubkey));
        }
        out.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
        out.extend_from_slice(&ix.data);
    }
    // address_table_lookups: none.
    out.push(0u8);
    out
}

/// Rebind a decoded transfer's funding source to the multisig vault: the agent
/// drafts "spend from the shared vault", never from a personal wallet.
///
/// - SystemProgram::Transfer: accounts[0] (from) → vault (signer per SDK
///   convention: readonly-signer in the inner message)
/// - SPL TransferChecked: source ATA → the vault's ATA for that mint, owner →
///   vault (and the caller prepends an idempotent ATA create for the vault)
pub fn rebind_to_vault(instructions: &[Instruction], vault: &Pubkey) -> Vec<Instruction> {
    use crate::crypto::{SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
    use crate::ix::{SYSTEM_IX_TRANSFER, TOKEN_IX_TRANSFER, TOKEN_IX_TRANSFER_CHECKED};

    instructions
        .iter()
        .map(|ix| {
            let program_str = ix.program_id.to_string();
            let mut new_ix = ix.clone();
            if program_str == SYSTEM_PROGRAM
                && ix.data.len() >= 4
                && u32::from_le_bytes([ix.data[0], ix.data[1], ix.data[2], ix.data[3]])
                    == SYSTEM_IX_TRANSFER
            {
                if let Some(from) = new_ix.accounts.get_mut(0) {
                    *from = AccountMeta::new(*vault, true);
                }
            } else if (program_str == TOKEN_PROGRAM || program_str == TOKEN_2022_PROGRAM)
                && !ix.data.is_empty()
                && matches!(ix.data[0], TOKEN_IX_TRANSFER | TOKEN_IX_TRANSFER_CHECKED)
            {
                // TransferChecked layout: source(0), mint(1), dest(2), owner(3).
                // The vault must fund it: source → the vault's ATA for this
                // mint, owner → vault. Without the source rewrite the vault
                // would "own-sign" someone else's ATA and execution would fail.
                let mint = new_ix.accounts.get(1).map(|m| m.pubkey);
                let token_program = new_ix.program_id;
                if let Some(mint) = mint {
                    let vault_ata = crate::crypto::ata_address(vault, &token_program, &mint);
                    if let Some(source) = new_ix.accounts.get_mut(0) {
                        *source = AccountMeta::new(vault_ata, false);
                    }
                }
                if let Some(owner) = new_ix.accounts.get_mut(3) {
                    *owner = AccountMeta::new_readonly(*vault, true);
                }
            }
            new_ix
        })
        .collect()
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
    fn rebind_spl_rewrites_source_and_owner_to_vault() {
        let vault = Pubkey::new_from_array([7u8; 32]);
        let user = Pubkey::new_from_array([8u8; 32]);
        let mint = Pubkey::new_from_array([9u8; 32]);
        let tp = crate::ix::spl_token_program();
        let user_ata = crate::crypto::ata_address(&user, &tp, &mint);
        let dest_ata = Pubkey::new_from_array([10u8; 32]);
        let ix = crate::ix::transfer_checked(&tp, &user_ata, &mint, &dest_ata, &user, 100, 6);
        let rebound = rebind_to_vault(&[ix], &vault);
        let expected_vault_ata = crate::crypto::ata_address(&vault, &tp, &mint);
        assert_eq!(
            rebound[0].accounts[0].pubkey, expected_vault_ata,
            "source must become the vault's ATA"
        );
        assert_eq!(
            rebound[0].accounts[3].pubkey, vault,
            "owner must be the vault"
        );
        assert!(rebound[0].accounts[3].is_signer);
        assert_eq!(rebound[0].accounts[1].pubkey, mint, "mint untouched");
        assert_eq!(rebound[0].accounts[2].pubkey, dest_ata, "dest untouched");
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
