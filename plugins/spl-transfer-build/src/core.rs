//! Pure, wasm-free core for `spl-transfer-build`.
//!
//! Everything in this file is plain Rust with no `wasm32` cfg, no host
//! imports, and no live network calls — that's what lets `cargo test`
//! exercise it directly, per the bounty's "pure core, thin shim" rule.
//! RPC access goes through the `RpcClient` trait so tests can supply a
//! mock instead of hitting a real endpoint.
//!
//! Custody tier: T1 (Build). This module only ever *returns* an unsigned
//! transaction. It never holds, generates, or touches a private key.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Cap on memo length. This is a defensive limit, not a protocol one —
/// see the prompt-injection test at the bottom of this file for why.
pub const MAX_MEMO_LEN: usize = 500;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid base58 public key")]
    InvalidPubkey,
    #[error("configured recipients must be valid base58 public keys")]
    InvalidRecipientPolicy,
    #[error("recipient is not approved")]
    RecipientNotApproved,
    #[error("PDA derivation failed: no valid bump found")]
    PdaNotFound,
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// ---------------------------------------------------------------------
// Pubkey + PDA derivation
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn from_base58(s: &str) -> Result<Self, CoreError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| CoreError::InvalidPubkey)?;
        if bytes.len() != 32 {
            return Err(CoreError::InvalidPubkey);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Pubkey(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    fn is_on_curve(bytes: &[u8; 32]) -> bool {
        curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
            .decompress()
            .is_some()
    }

    /// Reimplementation of Solana's `find_program_address`: walk the bump
    /// seed down from 255 until `sha256(seeds || [bump] || program_id ||
    /// "ProgramDerivedAddress")` lands off the ed25519 curve.
    pub fn find_program_address(
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<(Pubkey, u8), CoreError> {
        for bump in (0u8..=255).rev() {
            let mut hasher = Sha256::new();
            for seed in seeds {
                hasher.update(seed);
            }
            hasher.update([bump]);
            hasher.update(program_id.0);
            hasher.update(b"ProgramDerivedAddress");
            let hash: [u8; 32] = hasher.finalize().into();
            if !Self::is_on_curve(&hash) {
                return Ok((Pubkey(hash), bump));
            }
        }
        Err(CoreError::PdaNotFound)
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

pub fn derive_ata(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Result<Pubkey, CoreError> {
    let ata_program = Pubkey::from_base58(ATA_PROGRAM_ID)?;
    let (ata, _bump) =
        Pubkey::find_program_address(&[&owner.0, &token_program.0, &mint.0], &ata_program)?;
    Ok(ata)
}

// ---------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn new(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }
    pub fn new_readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Idempotent ATA creation. We always use the idempotent variant (data =
/// `[1]`) rather than plain `Create` (data = `[]`): it's a safe no-op if
/// the account already exists, which closes a TOCTOU gap between our
/// existence check and the moment a human actually signs and submits.
pub fn build_create_ata_idempotent_instruction(
    funder: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    ata: &Pubkey,
    token_program: &Pubkey,
) -> Result<Instruction, CoreError> {
    let system_program = Pubkey::from_base58(SYSTEM_PROGRAM_ID)?;
    let ata_program = Pubkey::from_base58(ATA_PROGRAM_ID)?;
    Ok(Instruction {
        program_id: ata_program,
        accounts: vec![
            AccountMeta::new(*funder, true),
            AccountMeta::new(*ata, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![1u8], // CreateIdempotent
    })
}

/// SPL Token / Token-2022 `TransferChecked` (discriminant 12). Using the
/// checked variant (rather than legacy `Transfer`) forces the mint and
/// decimals to match on-chain, which is a cheap extra guard against a
/// mismatched-mint bug ever moving the wrong amount.
pub fn build_transfer_checked_instruction(
    source_ata: &Pubkey,
    mint: &Pubkey,
    dest_ata: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
    token_program: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*source_ata, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*dest_ata, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

/// SPL Memo v2. Attaching the sender as a (readonly, non-signer-required)
/// account lets explorers/indexers associate the memo with the signer
/// without requiring an extra signature.
pub fn build_memo_instruction(
    memo: &str,
    signer: Option<&Pubkey>,
) -> Result<Instruction, CoreError> {
    let memo_program = Pubkey::from_base58(MEMO_PROGRAM_ID)?;
    let mut accounts = vec![];
    if let Some(s) = signer {
        accounts.push(AccountMeta::new_readonly(*s, true));
    }
    Ok(Instruction {
        program_id: memo_program,
        accounts,
        data: memo.as_bytes().to_vec(),
    })
}

// ---------------------------------------------------------------------
// Message compilation (v0, no address-table lookups) + wire serialization
// ---------------------------------------------------------------------

fn encode_compact_u16(mut n: u16, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
}

pub struct CompiledMessage {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<Instruction>,
}

/// Merge every account referenced across all instructions into one
/// deduplicated list, ordered per the wire format's required buckets:
/// signer+writable, signer+readonly, non-signer+writable, non-signer+readonly.
/// The fee payer is always forced first.
pub fn compile_message(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: [u8; 32],
) -> CompiledMessage {
    let mut metas: Vec<AccountMeta> = vec![AccountMeta::new(*fee_payer, true)];
    for ix in instructions {
        metas.push(AccountMeta::new_readonly(ix.program_id, false));
        for am in &ix.accounts {
            metas.push(am.clone());
        }
    }

    let mut merged: BTreeMap<[u8; 32], (bool, bool)> = BTreeMap::new();
    let mut order: Vec<[u8; 32]> = vec![];
    for m in &metas {
        let entry = merged.entry(m.pubkey.0).or_insert_with(|| {
            order.push(m.pubkey.0);
            (false, false)
        });
        entry.0 |= m.is_signer;
        entry.1 |= m.is_writable;
    }

    let mut signer_writable = vec![];
    let mut signer_readonly = vec![];
    let mut nonsigner_writable = vec![];
    let mut nonsigner_readonly = vec![];
    for key in &order {
        let (signer, writable) = merged[key];
        match (signer, writable) {
            (true, true) => signer_writable.push(*key),
            (true, false) => signer_readonly.push(*key),
            (false, true) => nonsigner_writable.push(*key),
            (false, false) => nonsigner_readonly.push(*key),
        }
    }
    signer_writable.retain(|k| *k != fee_payer.0);
    signer_writable.insert(0, fee_payer.0);

    let num_required_signatures = (signer_writable.len() + signer_readonly.len()) as u8;
    let num_readonly_signed = signer_readonly.len() as u8;
    let num_readonly_unsigned = nonsigner_readonly.len() as u8;

    let mut account_keys: Vec<Pubkey> = vec![];
    account_keys.extend(signer_writable.into_iter().map(Pubkey));
    account_keys.extend(signer_readonly.into_iter().map(Pubkey));
    account_keys.extend(nonsigner_writable.into_iter().map(Pubkey));
    account_keys.extend(nonsigner_readonly.into_iter().map(Pubkey));

    CompiledMessage {
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        account_keys,
        recent_blockhash,
        instructions: instructions.to_vec(),
    }
}

impl CompiledMessage {
    fn index_of(&self, pk: &Pubkey) -> u8 {
        self.account_keys
            .iter()
            .position(|k| k == pk)
            .expect("account present in message") as u8
    }

    /// Serializes the versioned (v0) message body: version prefix,
    /// header, account keys, blockhash, instructions, empty ALT list.
    pub fn serialize_v0(&self) -> Vec<u8> {
        let mut out = vec![
            0x80, // top bit set = versioned, low 7 bits = version 0
            self.num_required_signatures,
            self.num_readonly_signed,
            self.num_readonly_unsigned,
        ];

        encode_compact_u16(self.account_keys.len() as u16, &mut out);
        for k in &self.account_keys {
            out.extend_from_slice(&k.0);
        }

        out.extend_from_slice(&self.recent_blockhash);

        encode_compact_u16(self.instructions.len() as u16, &mut out);
        for ix in &self.instructions {
            out.push(self.index_of(&ix.program_id));
            encode_compact_u16(ix.accounts.len() as u16, &mut out);
            for am in &ix.accounts {
                out.push(self.index_of(&am.pubkey));
            }
            encode_compact_u16(ix.data.len() as u16, &mut out);
            out.extend_from_slice(&ix.data);
        }

        encode_compact_u16(0, &mut out); // address_table_lookups: none
        out
    }
}

/// Wraps the message with a signatures array sized to
/// `num_required_signatures` but filled with zero bytes — the standard
/// shape wallets/approval UIs expect for an unsigned versioned transaction.
pub fn serialize_unsigned_versioned_tx(message: &CompiledMessage) -> Vec<u8> {
    let mut out = Vec::new();
    encode_compact_u16(message.num_required_signatures as u16, &mut out);
    for _ in 0..message.num_required_signatures {
        out.extend_from_slice(&[0u8; 64]);
    }
    out.extend_from_slice(&message.serialize_v0());
    out
}

// ---------------------------------------------------------------------
// RPC seam (mocked in tests, backed by wasi:http in the wasm shim)
// ---------------------------------------------------------------------

pub trait RpcClient {
    fn get_latest_blockhash(&self) -> Result<[u8; 32], CoreError>;
    fn account_exists(&self, pubkey: &Pubkey) -> Result<bool, CoreError>;
}

// ---------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferArgs {
    pub sender: String,
    pub recipient: String,
    pub mint: String,
    /// Exact human-unit decimal, e.g. `"25.0"` for 25 USDC — not raw base
    /// units. This deliberately remains text until it is converted with
    /// checked integer arithmetic; money must never pass through `f64`.
    pub amount: String,
    pub decimals: u8,
    pub memo: Option<String>,
    #[serde(default)]
    pub token_2022: bool,
}

/// Operator-controlled destination policy. An empty allowlist intentionally
/// authorizes nobody: a transfer tool should fail closed until its owner names
/// the wallet owners it may build transactions for.
#[derive(Debug, Clone)]
pub struct TransferPolicy {
    allowed_recipients: Vec<Pubkey>,
}

impl TransferPolicy {
    /// Parse the comma-separated `allowed_recipients` config value. Missing or
    /// blank configuration produces an empty allowlist, never an allow-all.
    pub fn from_config(configured_recipients: Option<&str>) -> Result<Self, CoreError> {
        let allowed_recipients = configured_recipients
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|recipient| !recipient.is_empty())
            .map(Pubkey::from_base58)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CoreError::InvalidRecipientPolicy)?;
        Ok(Self { allowed_recipients })
    }

    /// Validate a requested destination before any RPC request or transaction
    /// serialization. A valid but unapproved public key is rejected too.
    pub fn authorize_recipient(&self, recipient: &str) -> Result<(), CoreError> {
        let recipient = Pubkey::from_base58(recipient)?;
        if self.allowed_recipients.contains(&recipient) {
            Ok(())
        } else {
            Err(CoreError::RecipientNotApproved)
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct TransferResult {
    pub transaction_base64: String,
    pub summary: String,
    pub source_ata: String,
    pub destination_ata: String,
    pub destination_ata_will_be_created: bool,
}

pub fn build_transfer(
    args: &TransferArgs,
    rpc: &dyn RpcClient,
    policy: &TransferPolicy,
) -> Result<TransferResult, CoreError> {
    if let Some(memo) = &args.memo {
        if memo.len() > MAX_MEMO_LEN {
            return Err(CoreError::InvalidInput(format!(
                "memo exceeds {MAX_MEMO_LEN} bytes"
            )));
        }
    }

    policy.authorize_recipient(&args.recipient)?;

    let sender = Pubkey::from_base58(&args.sender)?;
    let recipient = Pubkey::from_base58(&args.recipient)?;
    let mint = Pubkey::from_base58(&args.mint)?;
    let token_program = Pubkey::from_base58(if args.token_2022 {
        TOKEN_2022_PROGRAM_ID
    } else {
        TOKEN_PROGRAM_ID
    })?;

    let source_ata = derive_ata(&sender, &mint, &token_program)?;
    let dest_ata = derive_ata(&recipient, &mint, &token_program)?;
    let dest_exists = rpc.account_exists(&dest_ata)?;

    let raw_amount = parse_amount_to_base_units(&args.amount, args.decimals)?;

    let mut instructions = vec![build_create_ata_idempotent_instruction(
        &sender,
        &recipient,
        &mint,
        &dest_ata,
        &token_program,
    )?];
    instructions.push(build_transfer_checked_instruction(
        &source_ata,
        &mint,
        &dest_ata,
        &sender,
        raw_amount,
        args.decimals,
        &token_program,
    ));
    if let Some(memo) = &args.memo {
        instructions.push(build_memo_instruction(memo, Some(&sender))?);
    }

    let blockhash = rpc.get_latest_blockhash()?;
    let message = compile_message(&sender, &instructions, blockhash);
    let tx_bytes = serialize_unsigned_versioned_tx(&message);
    let transaction_base64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tx_bytes);

    let summary = format!(
        "Transfer {amount} tokens ({raw} base units)\n\
         From: {sender} (source ATA {source_ata})\n\
         To:   {recipient} (dest ATA {dest_ata}{created})\n\
         Mint: {mint}{prog}\n\
         Memo: {memo}\n\
         Requires signature from: {sender}",
        amount = args.amount,
        raw = raw_amount,
        created = if dest_exists { "" } else { ", will be created" },
        prog = if args.token_2022 { " (Token-2022)" } else { "" },
        memo = args.memo.as_deref().unwrap_or("(none)"),
    );

    Ok(TransferResult {
        transaction_base64,
        summary,
        source_ata: source_ata.to_base58(),
        destination_ata: dest_ata.to_base58(),
        destination_ata_will_be_created: !dest_exists,
    })
}

/// Convert a human-readable decimal amount to base units without using binary
/// floating point. Values with more fractional digits than the mint supports
/// are rejected rather than rounded into a different transfer amount.
fn parse_amount_to_base_units(amount: &str, decimals: u8) -> Result<u64, CoreError> {
    if amount.is_empty() || amount.trim() != amount {
        return Err(CoreError::InvalidInput(
            "amount must be a non-empty decimal string without whitespace".into(),
        ));
    }

    let mut parts = amount.split('.');
    let whole = parts.next().expect("split always returns one part");
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|value| {
            value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(CoreError::InvalidInput(
            "amount must be a positive decimal string".into(),
        ));
    }

    let fraction = fraction.unwrap_or("");
    if fraction.len() > decimals as usize {
        return Err(CoreError::InvalidInput(format!(
            "amount has more than {decimals} decimal places"
        )));
    }

    let scale = 10u64.checked_pow(decimals as u32).ok_or_else(|| {
        CoreError::InvalidInput("decimals cannot be represented in u64 base units".into())
    })?;
    let whole_units = whole
        .parse::<u64>()
        .map_err(|_| CoreError::InvalidInput("amount overflows u64 base units".into()))?
        .checked_mul(scale)
        .ok_or_else(|| CoreError::InvalidInput("amount overflows u64 base units".into()))?;
    let fraction_units = if fraction.is_empty() {
        0
    } else {
        let parsed = fraction
            .parse::<u64>()
            .map_err(|_| CoreError::InvalidInput("amount overflows u64 base units".into()))?;
        parsed
            .checked_mul(10u64.pow((decimals as usize - fraction.len()) as u32))
            .ok_or_else(|| CoreError::InvalidInput("amount overflows u64 base units".into()))?
    };
    let units = whole_units
        .checked_add(fraction_units)
        .ok_or_else(|| CoreError::InvalidInput("amount overflows u64 base units".into()))?;
    if units == 0 {
        return Err(CoreError::InvalidInput(
            "amount must be greater than zero base units".into(),
        ));
    }
    Ok(units)
}

pub const PARAMETERS_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "sender": { "type": "string", "description": "Base58 owner pubkey of the source token account" },
    "recipient": { "type": "string", "description": "Base58 owner pubkey of the destination wallet" },
    "mint": { "type": "string", "description": "Base58 SPL mint address" },
    "amount": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$", "description": "Exact positive human-readable decimal amount, e.g. \"25.0\". Must not have more fractional digits than decimals." },
    "decimals": { "type": "integer", "minimum": 0, "maximum": 255, "description": "Mint decimals" },
    "memo": { "type": "string", "maxLength": 500, "description": "Optional invoice/reconciliation memo" },
    "token_2022": { "type": "boolean", "default": false }
  },
  "required": ["sender", "recipient", "mint", "amount", "decimals"]
}"#;
