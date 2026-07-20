//! Minimal Solana wire codecs — base58 pubkeys, shortvec, PDA/ATA, legacy tx.
//! No solana-sdk (wasm32-wasip2 friendly).

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// System Program.
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
/// SPL Token program.
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Token-2022 program.
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// Associated Token Account program.
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// Memo program (v1/v2 common id used by wallets).
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// Recent blockhashes sysvar (for durable nonce advance).
pub const SYSVAR_RECENT_BLOCKHASHES: &str = "SysvarRecentB1ockHashes11111111111111111111";
/// Rent sysvar (not required for createIdempotent path with modern ATA).
pub const SYSVAR_RENT: &str = "SysvarRent111111111111111111111111111111111";

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s.trim())
            .into_vec()
            .map_err(|e| format!("invalid base58: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "pubkey must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub fn system() -> Self {
        Self::from_base58(SYSTEM_PROGRAM).expect("system program")
    }

    pub fn token() -> Self {
        Self::from_base58(TOKEN_PROGRAM).expect("token program")
    }

    pub fn token_2022() -> Self {
        Self::from_base58(TOKEN_2022_PROGRAM).expect("token-2022")
    }

    pub fn ata_program() -> Self {
        Self::from_base58(ATA_PROGRAM).expect("ata program")
    }

    pub fn memo() -> Self {
        Self::from_base58(MEMO_PROGRAM).expect("memo")
    }

    pub fn recent_blockhashes() -> Self {
        Self::from_base58(SYSVAR_RECENT_BLOCKHASHES).expect("sysvar")
    }
}

/// Lightweight address shape check (no decode).
pub fn looks_like_pubkey(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 32 || s.len() > 44 {
        return false;
    }
    s.bytes().all(|b| BASE58_ALPHABET.contains(&b))
}

#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// SPL transferChecked (instruction index 12).
pub fn ix_transfer_checked(
    source_ata: Pubkey,
    mint: Pubkey,
    dest_ata: Pubkey,
    owner: Pubkey,
    amount_raw: u64,
    decimals: u8,
    token_program: Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8 + 1);
    data.push(12); // TransferChecked
    data.extend_from_slice(&amount_raw.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta {
                pubkey: source_ata,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: mint,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: dest_ata,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: owner,
                is_signer: true,
                is_writable: false,
            },
        ],
        data,
    }
}

/// ATA CreateIdempotent (discriminator 1).
pub fn ix_create_ata_idempotent(
    payer: Pubkey,
    ata: Pubkey,
    owner: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
) -> Instruction {
    Instruction {
        program_id: Pubkey::ata_program(),
        accounts: vec![
            AccountMeta {
                pubkey: payer,
                is_signer: true,
                is_writable: true,
            },
            AccountMeta {
                pubkey: ata,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: owner,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: mint,
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: Pubkey::system(),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: token_program,
                is_signer: false,
                is_writable: false,
            },
        ],
        data: vec![1], // CreateIdempotent
    }
}

/// SPL Memo: raw memo bytes as instruction data.
pub fn ix_memo(memo: &str) -> Instruction {
    Instruction {
        program_id: Pubkey::memo(),
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    }
}

/// System AdvanceNonceAccount (index 4).
pub fn ix_advance_nonce(nonce_account: Pubkey, nonce_authority: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::system(),
        accounts: vec![
            AccountMeta {
                pubkey: nonce_account,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: Pubkey::recent_blockhashes(),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: nonce_authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data: {
            let mut d = vec![4, 0, 0, 0]; // AdvanceNonceAccount as u32 LE enum tag
            // SystemInstruction is borsh-enum: AdvanceNonceAccount has no payload after tag
            // Actually SystemInstruction uses borsh with variant index as u32 LE:
            // CreateAccount=0, Assign=1, Transfer=2, CreateAccountWithSeed=3, AdvanceNonceAccount=4
            d.truncate(4);
            d
        },
    }
}

/// Derive associated token address (standard ATA PDA).
pub fn derive_ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Result<Pubkey, String> {
    let ata_program = Pubkey::ata_program();
    let (pda, _bump) = find_program_address(
        &[owner.0.as_ref(), token_program.0.as_ref(), mint.0.as_ref()],
        &ata_program,
    )?;
    Ok(pda)
}

fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Result<(Pubkey, u8), String> {
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        for s in seeds {
            hasher.update(s);
        }
        hasher.update([bump]);
        hasher.update(program_id.0);
        hasher.update(b"ProgramDerivedAddress");
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        if !is_on_curve(&bytes) {
            return Ok((Pubkey(bytes), bump));
        }
    }
    Err("unable to find program address".into())
}

fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// Compile instructions into a legacy Message + unsigned Transaction wire bytes.
pub fn compile_legacy_unsigned_tx(
    fee_payer: &Pubkey,
    recent_blockhash: &[u8; 32],
    instructions: &[Instruction],
) -> Result<Vec<u8>, String> {
    let (header, account_keys, compiled) = compile_message(fee_payer, instructions)?;

    let mut msg = Vec::new();
    msg.push(header.0);
    msg.push(header.1);
    msg.push(header.2);
    write_shortvec(&mut msg, account_keys.len());
    for k in &account_keys {
        msg.extend_from_slice(&k.0);
    }
    msg.extend_from_slice(recent_blockhash);
    write_shortvec(&mut msg, compiled.len());
    for ix in &compiled {
        msg.push(ix.program_id_index);
        write_shortvec(&mut msg, ix.accounts.len());
        msg.extend_from_slice(&ix.accounts);
        write_shortvec(&mut msg, ix.data.len());
        msg.extend_from_slice(&ix.data);
    }

    // Transaction: shortvec signatures (num_required_signatures empty 64-byte sigs) + message
    let num_signers = header.0 as usize;
    let mut tx = Vec::new();
    write_shortvec(&mut tx, num_signers);
    for _ in 0..num_signers {
        tx.extend_from_slice(&[0u8; 64]);
    }
    tx.extend_from_slice(&msg);
    Ok(tx)
}

#[derive(Debug)]
struct CompiledIx {
    program_id_index: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

/// Returns (num_required_signatures, num_readonly_signed, num_readonly_unsigned).
fn compile_message(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
) -> Result<((u8, u8, u8), Vec<Pubkey>, Vec<CompiledIx>), String> {
    // pubkey -> (is_signer, is_writable)
    let mut map: Vec<(Pubkey, bool, bool)> = Vec::new();

    let mut upsert = |pk: Pubkey, is_signer: bool, is_writable: bool| {
        if let Some(e) = map.iter_mut().find(|(k, _, _)| k == &pk) {
            e.1 |= is_signer;
            e.2 |= is_writable;
        } else {
            map.push((pk, is_signer, is_writable));
        }
    };

    // Fee payer first: signer + writable
    upsert(*fee_payer, true, true);

    for ix in instructions {
        upsert(ix.program_id, false, false);
        for a in &ix.accounts {
            upsert(a.pubkey, a.is_signer, a.is_writable);
        }
    }

    // Ensure fee payer is index 0
    if let Some(pos) = map.iter().position(|(k, _, _)| k == fee_payer) {
        if pos != 0 {
            map.swap(0, pos);
        }
    }
    map[0].1 = true;
    map[0].2 = true;

    // Partition: writable signed, readonly signed, writable unsigned, readonly unsigned
    // Keep fee payer as first among writable signed.
    let mut w_s: Vec<Pubkey> = Vec::new();
    let mut r_s: Vec<Pubkey> = Vec::new();
    let mut w_u: Vec<Pubkey> = Vec::new();
    let mut r_u: Vec<Pubkey> = Vec::new();

    for (pk, is_signer, is_writable) in &map {
        match (*is_signer, *is_writable) {
            (true, true) => w_s.push(*pk),
            (true, false) => r_s.push(*pk),
            (false, true) => w_u.push(*pk),
            (false, false) => r_u.push(*pk),
        }
    }
    // fee payer must be first in w_s
    if let Some(pos) = w_s.iter().position(|k| k == fee_payer) {
        if pos != 0 {
            w_s.swap(0, pos);
        }
    } else {
        return Err("fee payer missing from writable signers".into());
    }

    let mut account_keys = Vec::new();
    account_keys.extend(w_s.iter().copied());
    account_keys.extend(r_s.iter().copied());
    account_keys.extend(w_u.iter().copied());
    account_keys.extend(r_u.iter().copied());

    if account_keys.len() > 256 {
        return Err("too many accounts".into());
    }

    let num_required_signatures = (w_s.len() + r_s.len()) as u8;
    let num_readonly_signed = r_s.len() as u8;
    let num_readonly_unsigned = r_u.len() as u8;

    let index_of = |pk: &Pubkey| -> Result<u8, String> {
        account_keys
            .iter()
            .position(|k| k == pk)
            .map(|i| i as u8)
            .ok_or_else(|| "account not in key list".into())
    };

    let mut compiled = Vec::new();
    for ix in instructions {
        let program_id_index = index_of(&ix.program_id)?;
        let mut accs = Vec::new();
        for a in &ix.accounts {
            accs.push(index_of(&a.pubkey)?);
        }
        compiled.push(CompiledIx {
            program_id_index,
            accounts: accs,
            data: ix.data.clone(),
        });
    }

    Ok((
        (
            num_required_signatures,
            num_readonly_signed,
            num_readonly_unsigned,
        ),
        account_keys,
        compiled,
    ))
}

fn write_shortvec(buf: &mut Vec<u8>, mut n: usize) {
    // Compact-u16 used by Solana shortvec
    let mut continue_bit = true;
    while continue_bit {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            continue_bit = false;
        } else {
            byte |= 0x80;
        }
        buf.push(byte);
    }
}

/// Decode base58 blockhash (32 bytes).
pub fn blockhash_from_base58(s: &str) -> Result<[u8; 32], String> {
    Pubkey::from_base58(s).map(|p| p.0)
}

/// Convert UI amount to raw token amount with overflow checks.
pub fn ui_to_raw(amount: f64, decimals: u8) -> Result<u64, String> {
    if !amount.is_finite() || amount <= 0.0 {
        return Err(format!("invalid amount {amount}"));
    }
    if decimals > 12 {
        return Err("decimals too large".into());
    }
    let scale = 10f64.powi(decimals as i32);
    let raw = (amount * scale).round();
    if raw > u64::MAX as f64 {
        return Err("amount overflow".into());
    }
    let raw_u = raw as u64;
    if raw_u == 0 {
        return Err("amount rounds to zero".into());
    }
    Ok(raw_u)
}

/// Mint account: decimals byte at offset 44 (SPL Token / Token-2022 mint layout base).
pub fn mint_decimals_from_data(data: &[u8]) -> Result<u8, String> {
    if data.len() < 45 {
        return Err("mint account data too short".into());
    }
    Ok(data[44])
}

/// Nonce account: durable nonce hash is 32 bytes at offset 40
/// (version u32 + state u32 + authority 32 + block 32 ...).
pub fn nonce_blockhash_from_data(data: &[u8]) -> Result<[u8; 32], String> {
    // Layout: 4 version + 4 state + 32 authority + 32 blockhash
    if data.len() < 72 {
        return Err("nonce account data too short".into());
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&data[40..72]);
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usdc_mint_decodes() {
        let p = Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        assert_eq!(p.to_base58().len(), 44);
    }

    #[test]
    fn ata_is_deterministic() {
        let owner = Pubkey::from_base58("7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDvdssTd9H").unwrap();
        let mint = Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let a1 = derive_ata(&owner, &mint, &Pubkey::token()).unwrap();
        let a2 = derive_ata(&owner, &mint, &Pubkey::token()).unwrap();
        assert_eq!(a1, a2);
        // Known-ish: must be valid 32-byte base58
        assert!(looks_like_pubkey(&a1.to_base58()));
    }

    #[test]
    fn ui_to_raw_usdc() {
        assert_eq!(ui_to_raw(25.0, 6).unwrap(), 25_000_000);
        assert_eq!(ui_to_raw(1.5, 6).unwrap(), 1_500_000);
    }

    #[test]
    fn short_tx_roundtrip_shape() {
        let payer = Pubkey::from_base58("7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDvdssTd9H").unwrap();
        let mint = Pubkey::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let src = derive_ata(&payer, &mint, &Pubkey::token()).unwrap();
        let dest_owner =
            Pubkey::from_base58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM").unwrap();
        let dst = derive_ata(&dest_owner, &mint, &Pubkey::token()).unwrap();
        let ix = ix_transfer_checked(src, mint, dst, payer, 1_000_000, 6, Pubkey::token());
        let bh = [7u8; 32];
        let tx = compile_legacy_unsigned_tx(&payer, &bh, &[ix]).unwrap();
        // at least 1 empty signature + message
        assert!(tx.len() > 64);
        assert_eq!(&tx[1..65], &[0u8; 64]); // first sig empty (after shortvec len byte)
    }
}
