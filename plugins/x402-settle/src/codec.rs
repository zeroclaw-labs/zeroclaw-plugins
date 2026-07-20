//! Minimal Solana codecs + ed25519 sign for T2 settle. No solana-sdk.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn from_base58(s: &str) -> Result<Self, String> {
        let bytes = bs58::decode(s.trim())
            .into_vec()
            .map_err(|e| format!("invalid base58: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("pubkey must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub fn system() -> Self {
        Self::from_base58(SYSTEM_PROGRAM).expect("system")
    }
    pub fn token() -> Self {
        Self::from_base58(TOKEN_PROGRAM).expect("token")
    }
    pub fn ata_program() -> Self {
        Self::from_base58(ATA_PROGRAM).expect("ata")
    }
    pub fn memo() -> Self {
        Self::from_base58(MEMO_PROGRAM).expect("memo")
    }
}

pub fn looks_like_pubkey(s: &str) -> bool {
    let s = s.trim();
    (32..=44).contains(&s.len())
        && s.bytes()
            .all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
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

pub fn ix_transfer_checked(
    source_ata: Pubkey,
    mint: Pubkey,
    dest_ata: Pubkey,
    owner: Pubkey,
    amount_raw: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12);
    data.extend_from_slice(&amount_raw.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: Pubkey::token(),
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

pub fn ix_create_ata_idempotent(
    payer: Pubkey,
    ata: Pubkey,
    owner: Pubkey,
    mint: Pubkey,
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
                pubkey: Pubkey::token(),
                is_signer: false,
                is_writable: false,
            },
        ],
        data: vec![1],
    }
}

pub fn ix_memo(memo: &str) -> Instruction {
    Instruction {
        program_id: Pubkey::memo(),
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    }
}

pub fn derive_ata(owner: &Pubkey, mint: &Pubkey) -> Result<Pubkey, String> {
    let token = Pubkey::token();
    let ata_program = Pubkey::ata_program();
    let (pda, _) = find_program_address(
        &[owner.0.as_ref(), token.0.as_ref(), mint.0.as_ref()],
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
        if CompressedEdwardsY(bytes).decompress().is_none() {
            return Ok((Pubkey(bytes), bump));
        }
    }
    Err("unable to find program address".into())
}

pub fn ui_to_raw(amount: f64, decimals: u8) -> Result<u64, String> {
    if !amount.is_finite() || amount <= 0.0 {
        return Err(format!("invalid amount {amount}"));
    }
    if decimals > 12 {
        return Err("decimals too large".into());
    }
    let scale = 10f64.powi(decimals as i32);
    let raw = (amount * scale).round();
    if raw > u64::MAX as f64 || raw < 1.0 {
        return Err("amount out of range".into());
    }
    Ok(raw as u64)
}

pub fn mint_decimals_from_data(data: &[u8]) -> Result<u8, String> {
    if data.len() < 45 {
        return Err("mint data too short".into());
    }
    Ok(data[44])
}

pub fn blockhash_from_base58(s: &str) -> Result<[u8; 32], String> {
    Pubkey::from_base58(s).map(|p| p.0)
}

/// Compile legacy message bytes + required signature count.
pub fn compile_legacy_message(
    fee_payer: &Pubkey,
    recent_blockhash: &[u8; 32],
    instructions: &[Instruction],
) -> Result<(Vec<u8>, u8), String> {
    let (header, account_keys, compiled) = compile_accounts(fee_payer, instructions)?;
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
    Ok((msg, header.0))
}

/// Assemble signed legacy transaction.
pub fn assemble_signed_tx(num_signers: u8, signatures: &[[u8; 64]], message: &[u8]) -> Result<Vec<u8>, String> {
    if signatures.len() != num_signers as usize {
        return Err("signature count mismatch".into());
    }
    let mut tx = Vec::new();
    write_shortvec(&mut tx, num_signers as usize);
    for sig in signatures {
        tx.extend_from_slice(sig);
    }
    tx.extend_from_slice(message);
    Ok(tx)
}

/// Parse session key: base58 64-byte keypair or 32-byte secret, or JSON byte array.
pub fn parse_session_key(raw: &str) -> Result<(SigningKey, Pubkey), String> {
    let raw = raw.trim();
    if raw.starts_with('[') {
        let arr: Vec<u8> =
            serde_json::from_str(raw).map_err(|e| format!("session_key json: {e}"))?;
        return key_from_bytes(&arr);
    }
    let bytes = bs58::decode(raw)
        .into_vec()
        .map_err(|e| format!("session_key base58: {e}"))?;
    key_from_bytes(&bytes)
}

fn key_from_bytes(bytes: &[u8]) -> Result<(SigningKey, Pubkey), String> {
    let secret = match bytes.len() {
        32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(bytes);
            s
        }
        64 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes[..32]);
            s
        }
        n => return Err(format!("session_key must be 32 or 64 bytes, got {n}")),
    };
    let signing = SigningKey::from_bytes(&secret);
    let pk = Pubkey(signing.verifying_key().to_bytes());
    Ok((signing, pk))
}

pub fn sign_message(signing: &SigningKey, message: &[u8]) -> [u8; 64] {
    let sig: Signature = signing.sign(message);
    sig.to_bytes()
}

struct CompiledIx {
    program_id_index: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

fn compile_accounts(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
) -> Result<((u8, u8, u8), Vec<Pubkey>, Vec<CompiledIx>), String> {
    let mut map: Vec<(Pubkey, bool, bool)> = Vec::new();
    let mut upsert = |pk: Pubkey, is_signer: bool, is_writable: bool| {
        if let Some(e) = map.iter_mut().find(|(k, _, _)| k == &pk) {
            e.1 |= is_signer;
            e.2 |= is_writable;
        } else {
            map.push((pk, is_signer, is_writable));
        }
    };
    upsert(*fee_payer, true, true);
    for ix in instructions {
        upsert(ix.program_id, false, false);
        for a in &ix.accounts {
            upsert(a.pubkey, a.is_signer, a.is_writable);
        }
    }
    if let Some(pos) = map.iter().position(|(k, _, _)| k == fee_payer) {
        if pos != 0 {
            map.swap(0, pos);
        }
    }
    map[0].1 = true;
    map[0].2 = true;

    let mut w_s = Vec::new();
    let mut r_s = Vec::new();
    let mut w_u = Vec::new();
    let mut r_u = Vec::new();
    for (pk, is_signer, is_writable) in &map {
        match (*is_signer, *is_writable) {
            (true, true) => w_s.push(*pk),
            (true, false) => r_s.push(*pk),
            (false, true) => w_u.push(*pk),
            (false, false) => r_u.push(*pk),
        }
    }
    if let Some(pos) = w_s.iter().position(|k| k == fee_payer) {
        if pos != 0 {
            w_s.swap(0, pos);
        }
    } else {
        return Err("fee payer not in writable signers".into());
    }

    let mut account_keys = Vec::new();
    account_keys.extend(w_s.iter().copied());
    account_keys.extend(r_s.iter().copied());
    account_keys.extend(w_u.iter().copied());
    account_keys.extend(r_u.iter().copied());

    let num_required_signatures = (w_s.len() + r_s.len()) as u8;
    let num_readonly_signed = r_s.len() as u8;
    let num_readonly_unsigned = r_u.len() as u8;

    let index_of = |pk: &Pubkey| -> Result<u8, String> {
        account_keys
            .iter()
            .position(|k| k == pk)
            .map(|i| i as u8)
            .ok_or_else(|| "missing account".into())
    };

    let mut compiled = Vec::new();
    for ix in instructions {
        let mut accs = Vec::new();
        for a in &ix.accounts {
            accs.push(index_of(&a.pubkey)?);
        }
        compiled.push(CompiledIx {
            program_id_index: index_of(&ix.program_id)?,
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
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
            buf.push(byte);
        } else {
            buf.push(byte);
            break;
        }
    }
}
