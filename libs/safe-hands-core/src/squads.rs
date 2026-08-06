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

fn derive_with_bump<const N: usize>(seeds: &[&[u8]; N]) -> (Pubkey, u8) {
    Pubkey::derive_program_address(seeds, &program_id())
        .expect("squads PDA derivation always finds a bump")
}

fn derive<const N: usize>(seeds: &[&[u8]; N]) -> Pubkey {
    derive_with_bump(seeds).0
}

/// multisig PDA and its canonical bump = ["multisig", "multisig", create_key].
pub fn multisig_pda_with_bump(create_key: &Pubkey) -> (Pubkey, u8) {
    derive_with_bump(&[SEED_PREFIX, SEED_MULTISIG, create_key.as_ref()])
}

/// multisig PDA = ["multisig", "multisig", create_key].
pub fn multisig_pda(create_key: &Pubkey) -> Pubkey {
    multisig_pda_with_bump(create_key).0
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

/// Anchor account discriminator: sha256("account:<name>")[..8].
fn anchor_account_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("account:{name}").as_bytes());
    digest[..8].try_into().expect("8 bytes")
}

/// One validated member from a Squads Multisig account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigMember {
    pub key: Pubkey,
    /// Initiate=1, Vote=2, Execute=4.
    pub permissions: u8,
}

impl MultisigMember {
    pub fn can_initiate(&self) -> bool {
        self.permissions & 1 != 0
    }
}

/// Fully validated fields from a Squads v4 Multisig account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigInfo {
    pub create_key: Pubkey,
    pub config_authority: Pubkey,
    pub threshold: u16,
    pub time_lock: u32,
    pub transaction_index: u64,
    pub stale_transaction_index: u64,
    pub rent_collector: Option<Pubkey>,
    pub bump: u8,
    pub members: Vec<MultisigMember>,
}

impl MultisigInfo {
    /// Whether `key` is a sorted member with Squads' Initiate permission.
    pub fn can_propose(&self, key: &Pubkey) -> bool {
        self.members
            .binary_search_by_key(key, |member| member.key)
            .map(|index| self.members[index].can_initiate())
            .unwrap_or(false)
    }
}

/// Parse the official full Borsh layout of a Squads v4 Multisig account.
/// Discriminator, fields, lengths, ordering, permissions, and the official
/// allocation shape are validated; malformed account data is never partially
/// accepted. Squads intentionally reserves 32 bytes when `rent_collector` is
/// `None` and can retain capacity for removed members, so valid owned accounts
/// may contain bytes beyond the serialized Borsh value.
pub fn parse_multisig_account(data: &[u8]) -> Result<MultisigInfo, String> {
    let mut cursor = MultisigCursor::new(data);
    if cursor.take(8)? != anchor_account_discriminator("Multisig") {
        return Err("invalid Multisig account discriminator".to_string());
    }
    let create_key = cursor.pubkey()?;
    let config_authority = cursor.pubkey()?;
    let threshold = cursor.u16()?;
    let time_lock = cursor.u32()?;
    let transaction_index = cursor.u64()?;
    let stale_transaction_index = cursor.u64()?;
    let rent_collector = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.pubkey()?),
        other => return Err(format!("invalid rent_collector option tag: {other}")),
    };
    let bump = cursor.u8()?;
    let member_count = cursor.u32()? as usize;
    if member_count > cursor.remaining() / 33 {
        return Err("multisig members vector is truncated".to_string());
    }
    let mut members = Vec::with_capacity(member_count);
    for _ in 0..member_count {
        let key = cursor.pubkey()?;
        let permissions = cursor.u8()?;
        if !(1..=7).contains(&permissions) {
            return Err(format!(
                "member {key} has invalid permission mask {permissions}"
            ));
        }
        members.push(MultisigMember { key, permissions });
    }
    // Squads allocates Multisig accounts as `132 + capacity * 33` bytes:
    // 132 includes 32 bytes reserved for rent_collector even when its Borsh
    // Option tag is None, and each member-capacity slot is 33 bytes. Accounts
    // can retain extra capacity (and stale removed-member bytes) after realloc,
    // so cursor exhaustion is not an official validity condition.
    const FIXED_ALLOCATED_BYTES: usize = 132;
    const MEMBER_BYTES: usize = 33;
    let minimum_size = member_count
        .checked_mul(MEMBER_BYTES)
        .and_then(|members_size| FIXED_ALLOCATED_BYTES.checked_add(members_size))
        .ok_or_else(|| "multisig account allocation size overflow".to_string())?;
    if data.len() < minimum_size {
        return Err("multisig account is smaller than its declared members require".to_string());
    }
    if !(data.len() - FIXED_ALLOCATED_BYTES).is_multiple_of(MEMBER_BYTES) {
        return Err("multisig account has an invalid allocation size".to_string());
    }
    if threshold == 0 || usize::from(threshold) > members.len() {
        return Err("multisig threshold must be within 1..=members.len()".to_string());
    }
    if stale_transaction_index > transaction_index {
        return Err("multisig stale_transaction_index exceeds transaction_index".to_string());
    }
    if members.windows(2).any(|pair| pair[0].key >= pair[1].key) {
        return Err("multisig members must be sorted and unique".to_string());
    }

    Ok(MultisigInfo {
        create_key,
        config_authority,
        threshold,
        time_lock,
        transaction_index,
        stale_transaction_index,
        rent_collector,
        bump,
        members,
    })
}

struct MultisigCursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> MultisigCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| "multisig cursor overflow".to_string())?;
        let value = self
            .data
            .get(self.position..end)
            .ok_or_else(|| "multisig account data truncated".to_string())?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| "u16")?,
        ))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| "u32")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "u64")?,
        ))
    }

    fn pubkey(&mut self) -> Result<Pubkey, String> {
        Ok(Pubkey::new_from_array(
            self.take(32)?.try_into().map_err(|_| "pubkey")?,
        ))
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }
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
/// No blockhash appears in this format. Callers must provide a vault-native
/// exact draft: this compiler never rewrites account keys or signer flags.
pub fn compile_inner_message(
    instructions: &[Instruction],
    vault: &Pubkey,
) -> Result<Vec<u8>, String> {
    #[derive(Clone, Copy)]
    struct KeyFlags {
        key: Pubkey,
        writable: bool,
    }

    let mut first_seen: Vec<KeyFlags> = Vec::new();
    let mut vault_is_signer = false;
    let add_key = |key: Pubkey, writable: bool, keys: &mut Vec<KeyFlags>| {
        if let Some(existing) = keys.iter_mut().find(|existing| existing.key == key) {
            existing.writable |= writable;
        } else {
            keys.push(KeyFlags { key, writable });
        }
    };

    for instruction in instructions {
        for account in &instruction.accounts {
            if account.is_signer {
                if account.pubkey != *vault {
                    return Err(format!(
                        "inner message signer {} is not the supplied vault",
                        account.pubkey
                    ));
                }
                vault_is_signer = true;
            }
            add_key(account.pubkey, account.is_writable, &mut first_seen);
        }
        add_key(instruction.program_id, false, &mut first_seen);
    }
    if !vault_is_signer {
        return Err("supplied vault is not a signer in the inner instructions".to_string());
    }

    let vault_writable = first_seen
        .iter()
        .find(|entry| entry.key == *vault)
        .map(|entry| entry.writable)
        .unwrap_or(false);
    let writable: Vec<Pubkey> = first_seen
        .iter()
        .filter(|entry| entry.key != *vault && entry.writable)
        .map(|entry| entry.key)
        .collect();
    let readonly: Vec<Pubkey> = first_seen
        .iter()
        .filter(|entry| entry.key != *vault && !entry.writable)
        .map(|entry| entry.key)
        .collect();
    let key_count = 1usize
        .checked_add(writable.len())
        .and_then(|count| count.checked_add(readonly.len()))
        .ok_or_else(|| "inner account-key count overflow".to_string())?;
    let key_count_u8 = u8::try_from(key_count)
        .map_err(|_| "inner account-key count exceeds u8 length bound".to_string())?;
    let writable_count_u8 = u8::try_from(writable.len())
        .map_err(|_| "writable non-signer count exceeds u8 length bound".to_string())?;
    let instruction_count_u8 = u8::try_from(instructions.len())
        .map_err(|_| "inner instruction count exceeds u8 length bound".to_string())?;

    let mut ordered_keys = Vec::with_capacity(key_count);
    ordered_keys.push(*vault);
    ordered_keys.extend_from_slice(&writable);
    ordered_keys.extend_from_slice(&readonly);
    let key_index = |key: &Pubkey| -> Result<u8, String> {
        let index = ordered_keys
            .iter()
            .position(|candidate| candidate == key)
            .ok_or_else(|| format!("inner instruction key {key} was not collected"))?;
        u8::try_from(index).map_err(|_| "inner account index exceeds u8 bound".to_string())
    };

    let mut out = vec![
        1, // num_signers: supplied vault only
        u8::from(vault_writable),
        writable_count_u8,
        key_count_u8,
    ];
    for key in &ordered_keys {
        out.extend_from_slice(key.as_ref());
    }
    out.push(instruction_count_u8);
    for instruction in instructions {
        out.push(key_index(&instruction.program_id)?);
        let account_count = u8::try_from(instruction.accounts.len())
            .map_err(|_| "instruction account count exceeds u8 length bound".to_string())?;
        out.push(account_count);
        for account in &instruction.accounts {
            out.push(key_index(&account.pubkey)?);
        }
        let data_length = u16::try_from(instruction.data.len())
            .map_err(|_| "instruction data exceeds u16 length bound".to_string())?;
        out.extend_from_slice(&data_length.to_le_bytes());
        out.extend_from_slice(&instruction.data);
    }
    out.push(0); // address_table_lookups: none
    Ok(out)
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
    fn inner_message_rejects_foreign_or_missing_signers() {
        let vault = Pubkey::new_from_array([7u8; 32]);
        let other = Pubkey::new_from_array([8u8; 32]);
        let destination = Pubkey::new_from_array([9u8; 32]);
        let foreign = crate::ix::system_transfer(&other, &destination, 1);
        assert!(compile_inner_message(&[foreign], &vault).is_err());

        let mut missing = crate::ix::system_transfer(&vault, &destination, 1);
        missing.accounts[0].is_signer = false;
        assert!(compile_inner_message(&[missing], &vault).is_err());
    }

    #[test]
    fn inner_message_validates_u8_and_u16_length_bounds() {
        let vault = Pubkey::new_from_array([7u8; 32]);
        let destination = Pubkey::new_from_array([9u8; 32]);
        let transfer = crate::ix::system_transfer(&vault, &destination, 1);
        assert!(compile_inner_message(&vec![transfer.clone(); 256], &vault).is_err());

        let mut oversized_data = transfer;
        oversized_data.data = vec![0u8; usize::from(u16::MAX) + 1];
        assert!(compile_inner_message(&[oversized_data], &vault).is_err());
    }

    #[test]
    fn multisig_account_parse_validates_full_official_layout() {
        let mut data = anchor_account_discriminator("Multisig").to_vec();
        data.extend_from_slice(&[7u8; 32]);
        data.extend_from_slice(&[8u8; 32]);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&60u32.to_le_bytes());
        data.extend_from_slice(&41u64.to_le_bytes());
        data.extend_from_slice(&40u64.to_le_bytes());
        data.push(1);
        data.extend_from_slice(&[9u8; 32]);
        data.push(254);
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[1u8; 32]);
        data.push(1);
        data.extend_from_slice(&[2u8; 32]);
        data.push(7);

        let info = parse_multisig_account(&data).expect("parses");
        assert_eq!(info.create_key, Pubkey::new_from_array([7u8; 32]));
        assert_eq!(info.config_authority, Pubkey::new_from_array([8u8; 32]));
        assert_eq!(info.threshold, 2);
        assert_eq!(info.time_lock, 60);
        assert_eq!(info.transaction_index, 41);
        assert_eq!(info.stale_transaction_index, 40);
        assert_eq!(info.rent_collector, Some(Pubkey::new_from_array([9u8; 32])));
        assert_eq!(info.bump, 254);
        assert!(info.can_propose(&Pubkey::new_from_array([1u8; 32])));
        assert_eq!(info.members.len(), 2);

        let mut bad_discriminator = data.clone();
        bad_discriminator[0] ^= 1;
        assert!(parse_multisig_account(&bad_discriminator).is_err());
        let mut invalid_allocation = data.clone();
        invalid_allocation.push(0);
        assert!(parse_multisig_account(&invalid_allocation).is_err());

        // Squads keeps extra 33-byte member-capacity slots after reallocations.
        // Their contents can be stale after member removal, so only the owned
        // account's official allocation shape—not padding contents—is trusted.
        let mut extra_capacity = data.clone();
        extra_capacity.extend_from_slice(&[0xA5; 33]);
        assert!(parse_multisig_account(&extra_capacity).is_ok());

        // When rent_collector is None, Borsh consumes only the option tag but
        // Squads still allocates its 32-byte payload area.
        let mut no_rent_collector = data.clone();
        no_rent_collector[94] = 0;
        no_rent_collector.drain(95..127);
        no_rent_collector.resize(data.len(), 0);
        let no_rent_info = parse_multisig_account(&no_rent_collector).expect("None parses");
        assert_eq!(no_rent_info.rent_collector, None);

        assert!(parse_multisig_account(&data[..50]).is_err());

        let mut stale_ahead = data.clone();
        stale_ahead[86..94].copy_from_slice(&42u64.to_le_bytes());
        assert!(parse_multisig_account(&stale_ahead).is_err());

        let mut bad_threshold = data.clone();
        bad_threshold[72..74].copy_from_slice(&3u16.to_le_bytes());
        assert!(parse_multisig_account(&bad_threshold).is_err());
        let mut bad_permissions = data.clone();
        bad_permissions[164] = 0;
        assert!(parse_multisig_account(&bad_permissions).is_err());
        let mut unsorted = data.clone();
        unsorted[165..197].fill(0);
        assert!(parse_multisig_account(&unsorted).is_err());
    }
}
