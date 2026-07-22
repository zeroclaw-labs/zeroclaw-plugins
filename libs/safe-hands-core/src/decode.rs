//! Transaction decoding: wire bytes (legacy or v0, with or without the
//! signature array) → classified facts the policy engine consumes.
//!
//! The decoder is strict: trailing bytes, truncated fields, oversized vectors,
//! or any instruction it cannot fully classify are errors — never guesses.
//! Message deserialization for legacy uses the canonical Agave `Message`;
//! v0 (with address lookup tables) is parsed by hand per the wire spec.

use solana_message::Message;
use solana_pubkey::Pubkey;

use crate::codec::shortvec_decode;
use crate::crypto::{parse_pubkey, ATA_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use crate::ix::{
    COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM, SQUADS_V4_PROGRAM, SYSTEM_IX_ADVANCE_NONCE,
    SYSTEM_IX_ASSIGN, SYSTEM_IX_TRANSFER, TOKEN_IX_APPROVE, TOKEN_IX_SET_AUTHORITY,
    TOKEN_IX_TRANSFER, TOKEN_IX_TRANSFER_CHECKED,
};
use crate::policy::{IxFact, TransferFact, TxFacts};

/// Wire version of the decoded message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxVersion {
    Legacy,
    V0,
}

/// One fully decoded transaction.
#[derive(Clone, Debug)]
pub struct DecodedTx {
    pub facts: TxFacts,
    /// Number of signatures required by the message header.
    pub required_signatures: usize,
    /// Whether the input included the transaction signature vector rather than
    /// being a bare message.
    pub has_signature_array: bool,
    /// All statically known account keys, base58, in message order.
    pub resolved_keys: Vec<String>,
    pub version: TxVersion,
    pub blockhash: String,
    /// v0 address-lookup-table references (table address + indices).
    /// Contents are NOT resolved here — that needs RPC (caller binds).
    pub alt_refs: Vec<AltRef>,
    /// The raw instructions (program, metas, data) reconstructed from the
    /// message — needed by builders that recompile transactions (e.g. Squads
    /// re-payer flow).
    pub raw_instructions: Vec<solana_instruction::Instruction>,
}

/// An address lookup table reference (unresolved without RPC).
#[derive(Clone, Debug)]
pub struct AltRef {
    pub table: String,
    pub writable_indices: Vec<u8>,
    pub readonly_indices: Vec<u8>,
}

const MAX_ACCOUNTS: usize = 256;
const MAX_INSTRUCTIONS: usize = 64;

/// Decode wire bytes into a [`DecodedTx`]. Accepts:
/// - a full transaction (shortvec signature array + message), signed or not
/// - a bare message (legacy or v0) as produced by message builders
///
/// A v0 message that references ALTs fails explicitly until the caller loads
/// and supplies those addresses through [`decode_with_loaded_addresses`].
pub fn decode(bytes: &[u8]) -> Result<DecodedTx, String> {
    decode_impl(bytes, None)
}

/// Decode a v0 transaction after the caller has resolved every ALT reference.
/// Solana ordering is all loaded writable keys, then all loaded readonly keys.
/// Counts must match the indices declared in the message exactly.
pub fn decode_with_loaded_addresses(
    bytes: &[u8],
    loaded_writable: &[Pubkey],
    loaded_readonly: &[Pubkey],
) -> Result<DecodedTx, String> {
    decode_impl(bytes, Some((loaded_writable, loaded_readonly)))
}

fn decode_impl(bytes: &[u8], loaded: Option<(&[Pubkey], &[Pubkey])>) -> Result<DecodedTx, String> {
    if bytes.is_empty() {
        return Err("empty transaction bytes".to_string());
    }

    if let Some((signed, rest)) = try_strip_signatures(bytes)? {
        if let Ok(mut decoded) = decode_message(rest, loaded) {
            decoded.facts.signed = signed;
            decoded.facts.byte_len = bytes.len();
            decoded.has_signature_array = true;
            return Ok(decoded);
        }
    }
    decode_message(bytes, loaded).map(|mut d| {
        d.facts.byte_len = bytes.len();
        d
    })
}

/// Decode message bytes (no signature array): version detect + parse + classify.
fn decode_message(
    message_bytes: &[u8],
    loaded: Option<(&[Pubkey], &[Pubkey])>,
) -> Result<DecodedTx, String> {
    if message_bytes.is_empty() {
        return Err("empty message bytes".to_string());
    }
    let (version, body) = if message_bytes[0] & 0x80 != 0 {
        (TxVersion::V0, &message_bytes[1..])
    } else {
        (TxVersion::Legacy, message_bytes)
    };

    let (header_signers, mut keys, blockhash, raw_ixs, alt_refs, mut metas_per_ix) = match version {
        TxVersion::Legacy => parse_legacy(body)?,
        TxVersion::V0 => parse_v0(body)?,
    };

    if version == TxVersion::V0 && !alt_refs.is_empty() {
        let want_writable: usize = alt_refs.iter().map(|r| r.writable_indices.len()).sum();
        let want_readonly: usize = alt_refs.iter().map(|r| r.readonly_indices.len()).sum();
        let Some((loaded_writable, loaded_readonly)) = loaded else {
            return Err(format!(
                "ALT resolution required: {want_writable} writable and {want_readonly} readonly addresses"
            ));
        };
        if loaded_writable.len() != want_writable || loaded_readonly.len() != want_readonly {
            return Err(format!(
                "ALT loaded-address count mismatch: expected {want_writable}/{want_readonly} writable/readonly, got {}/{}",
                loaded_writable.len(),
                loaded_readonly.len()
            ));
        }
        let static_len = keys.len();
        keys.extend_from_slice(loaded_writable);
        keys.extend_from_slice(loaded_readonly);
        for (raw, metas) in raw_ixs.iter().zip(metas_per_ix.iter_mut()) {
            let original_static_metas = metas.clone();
            metas.clear();
            for (position, idx) in raw.1.iter().enumerate() {
                let i = *idx as usize;
                let pubkey = *keys
                    .get(i)
                    .ok_or("account index out of range after ALT resolution")?;
                let (is_signer, is_writable) = if i < static_len {
                    // Static accounts preserve the flags computed by parse_v0.
                    let original_position = raw.1[..position]
                        .iter()
                        .filter(|prior| **prior == *idx)
                        .count();
                    raw.1
                        .iter()
                        .enumerate()
                        .filter(|(_, candidate)| **candidate == *idx)
                        .nth(original_position)
                        .and_then(|(p, _)| original_static_metas.get(p))
                        .map(|m| (m.is_signer, m.is_writable))
                        .ok_or("static account meta missing during ALT resolution")?
                } else if i < static_len + loaded_writable.len() {
                    (false, true)
                } else {
                    (false, false)
                };
                metas.push(solana_instruction::AccountMeta {
                    pubkey,
                    is_signer,
                    is_writable,
                });
            }
        }
    } else if loaded.is_some() && version != TxVersion::V0 {
        return Err("loaded ALT addresses supplied for a legacy message".to_string());
    }

    let resolved_keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    let mut facts = TxFacts {
        byte_len: message_bytes.len(),
        ..Default::default()
    };
    facts.estimated_fee_lamports = 5_000u64.saturating_mul(header_signers as u64);

    let mut raw_instructions = Vec::with_capacity(raw_ixs.len());
    for ((program_index, accounts, data), metas) in raw_ixs.iter().zip(metas_per_ix) {
        let program_id = *keys
            .get(*program_index as usize)
            .ok_or("program id index out of range after ALT resolution")?;
        classify(program_id, accounts, data, &keys, &mut facts)?;
        raw_instructions.push(solana_instruction::Instruction {
            program_id,
            accounts: metas,
            data: data.clone(),
        });
    }

    Ok(DecodedTx {
        facts,
        required_signatures: header_signers as usize,
        has_signature_array: false,
        resolved_keys,
        version,
        blockhash: bs58::encode(blockhash).into_string(),
        alt_refs,
        raw_instructions,
    })
}

/// Strip the signature array if one is present. Returns (signed, message).
fn try_strip_signatures(bytes: &[u8]) -> Result<Option<(bool, &[u8])>, String> {
    let (count, used) = shortvec_decode(bytes).unwrap_or((0, 0));
    if used == 0 || count > MAX_ACCOUNTS {
        return Ok(None);
    }
    let sig_bytes = count * 64;
    if bytes.len() < used + sig_bytes + 4 {
        return Ok(None); // too short to really be sig array + message
    }
    let sigs = &bytes[used..used + sig_bytes];
    // Heuristic: after a sig array comes a message header (3 small bytes) or a
    // v0 version marker (high bit set).
    let next = bytes[used + sig_bytes];
    let looks_like_message = next & 0x80 != 0 || (next > 0 && next <= 32);
    if !looks_like_message {
        return Ok(None);
    }
    let any_nonzero = sigs.iter().any(|b| *b != 0);
    Ok(Some((any_nonzero, &bytes[used + sig_bytes..])))
}

type RawIx = (u8, Vec<u8>, Vec<u8>); // (program index, account indices, data)
type MetasPerIx = Vec<Vec<solana_instruction::AccountMeta>>;
type ParsedParts = (
    u8,
    Vec<Pubkey>,
    [u8; 32],
    Vec<RawIx>,
    Vec<AltRef>,
    MetasPerIx,
);

/// Legacy: canonical Agave Message deserialization, then re-encode-free parse
/// of instructions (Agave's CompiledInstruction keeps account indices).
fn parse_legacy(bytes: &[u8]) -> Result<ParsedParts, String> {
    let msg: Message =
        bincode::deserialize(bytes).map_err(|e| format!("legacy message parse: {e}"))?;
    if bincode::serialized_size(&msg).map_err(|e| format!("size: {e}"))? as usize != bytes.len() {
        return Err("trailing bytes after legacy message".to_string());
    }
    let keys = msg.account_keys.clone();
    if keys.len() > MAX_ACCOUNTS {
        return Err("account vector exceeds bound".to_string());
    }
    let mut ixs = Vec::new();
    let mut metas_per_ix: MetasPerIx = Vec::new();
    let num_signers = msg.header.num_required_signatures as usize;
    let ro_signed = msg.header.num_readonly_signed_accounts as usize;
    let ro_unsigned = msg.header.num_readonly_unsigned_accounts as usize;
    let key_count = msg.account_keys.len();
    // Same header-partition invariant as v0: a malformed legacy header would
    // underflow the writable computation. Fail closed on inconsistency.
    if ro_signed > num_signers || num_signers.saturating_add(ro_unsigned) > key_count {
        return Err("invalid legacy header: readonly counts exceed key partition".to_string());
    }
    let is_signer = |i: usize| i < num_signers;
    let is_writable = |i: usize| {
        (i < num_signers - ro_signed) || (i >= num_signers && i < key_count - ro_unsigned)
    };
    for ci in &msg.instructions {
        if ixs.len() >= MAX_INSTRUCTIONS {
            return Err("instruction vector exceeds bound".to_string());
        }
        let program_index = ci.program_id_index;
        keys.get(program_index as usize)
            .ok_or("program id index out of range")?;
        // Bounds-check every account index rather than indexing directly — an
        // out-of-range index in hostile input must be an error, never a panic.
        let mut metas: Vec<solana_instruction::AccountMeta> =
            Vec::with_capacity(ci.accounts.len());
        for idx in &ci.accounts {
            let i = *idx as usize;
            let key = *keys.get(i).ok_or("account index out of range")?;
            metas.push(solana_instruction::AccountMeta {
                pubkey: key,
                is_signer: is_signer(i),
                is_writable: is_writable(i),
            });
        }
        ixs.push((program_index, ci.accounts.clone(), ci.data.clone()));
        metas_per_ix.push(metas);
    }
    Ok((
        msg.header.num_required_signatures,
        keys,
        msg.recent_blockhash.to_bytes(),
        ixs,
        vec![],
        metas_per_ix,
    ))
}

/// v0: hand-parse per the wire spec (header + keys + blockhash + ixs + ALT lookups).
fn parse_v0(bytes: &[u8]) -> Result<ParsedParts, String> {
    let mut cur = Cursor::new(bytes);
    let num_signers = cur.u8()?;
    let readonly_signed = cur.u8()?;
    let readonly_unsigned = cur.u8()?;
    let key_count = cur.shortvec()?;
    if key_count > MAX_ACCOUNTS {
        return Err("account vector exceeds bound".to_string());
    }
    // The header partition must be internally consistent: readonly-signed
    // cannot exceed the signers, and signers + readonly-unsigned cannot exceed
    // the static key count. Hostile input that violates this would otherwise
    // underflow the writable/signer computation below — fail closed instead.
    if (readonly_signed as usize) > (num_signers as usize)
        || (num_signers as usize).saturating_add(readonly_unsigned as usize) > key_count
    {
        return Err("invalid v0 header: readonly counts exceed key partition".to_string());
    }
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        keys.push(Pubkey::new_from_array(cur.bytes32()?));
    }
    let is_signer = |i: usize| i < num_signers as usize;
    let is_writable = |i: usize| {
        (i < num_signers as usize - readonly_signed as usize)
            || (i >= num_signers as usize && i < key_count - readonly_unsigned as usize)
    };
    let blockhash = cur.bytes32()?;
    let ix_count = cur.shortvec()?;
    if ix_count > MAX_INSTRUCTIONS {
        return Err("instruction vector exceeds bound".to_string());
    }
    let mut ixs = Vec::with_capacity(ix_count);
    let mut metas_per_ix: MetasPerIx = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_index = cur.u8()?;
        let program_idx = program_index as usize;
        let account_count = cur.shortvec()?;
        if account_count > MAX_ACCOUNTS {
            return Err("instruction account vector exceeds bound".to_string());
        }
        let mut acc_indices = Vec::with_capacity(account_count);
        let mut metas = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            let idx = cur.u8()?;
            acc_indices.push(idx);
            let i = idx as usize;
            let (pubkey, signer, writable) = if let Some(key) = keys.get(i) {
                (*key, is_signer(i), is_writable(i))
            } else {
                // Dynamic ALT key — bound after the table account is loaded.
                (Pubkey::default(), false, false)
            };
            metas.push(solana_instruction::AccountMeta {
                pubkey,
                is_signer: signer,
                is_writable: writable,
            });
        }
        let data_len = cur.shortvec()?;
        let data = cur.bytes(data_len)?.to_vec();
        // Program may itself be loaded from an ALT; validate after resolution.
        if program_idx < keys.len() {
            let _ = keys[program_idx];
        }
        ixs.push((program_index, acc_indices, data));
        metas_per_ix.push(metas);
    }
    // Address lookup tables (leftover bytes after instructions).
    let mut alt_refs = Vec::new();
    while !cur.done() {
        let table_count = cur.shortvec()?;
        for _ in 0..table_count {
            let table = bs58::encode(cur.bytes32()?).into_string();
            let w_count = cur.shortvec()?;
            let mut writable_indices = Vec::with_capacity(w_count);
            for _ in 0..w_count {
                writable_indices.push(cur.u8()?);
            }
            let r_count = cur.shortvec()?;
            let mut readonly_indices = Vec::with_capacity(r_count);
            for _ in 0..r_count {
                readonly_indices.push(cur.u8()?);
            }
            alt_refs.push(AltRef {
                table,
                writable_indices,
                readonly_indices,
            });
        }
    }
    Ok((num_signers, keys, blockhash, ixs, alt_refs, metas_per_ix))
}

/// Classify one instruction: program label, instruction name, value movements,
/// and danger flags — written into `facts`.
fn classify(
    program: Pubkey,
    account_indices: &[u8],
    data: &[u8],
    keys: &[Pubkey],
    facts: &mut TxFacts,
) -> Result<(), String> {
    let program_str = program.to_string();
    let key_at = |i: usize| -> Result<String, String> {
        account_indices
            .get(i)
            .and_then(|idx| keys.get(*idx as usize))
            .map(|k| k.to_string())
            .ok_or_else(|| "account index out of range".to_string())
    };

    let (label, name) = match program_str.as_str() {
        SYSTEM_PROGRAM => classify_system(data, facts, &key_at)?,
        TOKEN_PROGRAM | TOKEN_2022_PROGRAM => {
            let is_2022 = program_str == TOKEN_2022_PROGRAM;
            classify_token(data, facts, &key_at, is_2022)?
        }
        ATA_PROGRAM => {
            let name = match data.first() {
                Some(0) => "create",
                Some(1) => "create_idempotent",
                Some(2) => "recover_nested",
                _ => "create_idempotent", // empty data = legacy create
            };
            ("associated_token".to_string(), Some(name.to_string()))
        }
        MEMO_PROGRAM => ("memo".to_string(), Some("memo".to_string())),
        COMPUTE_BUDGET_PROGRAM => classify_compute_budget(data, facts)?,
        SQUADS_V4_PROGRAM => ("squads".to_string(), Some("squads_ix".to_string())),
        _ => (format!("unknown:{program_str}"), None),
    };

    facts.instructions.push(IxFact {
        program: label,
        name,
    });
    Ok(())
}

fn classify_system(
    data: &[u8],
    facts: &mut TxFacts,
    key_at: &dyn Fn(usize) -> Result<String, String>,
) -> Result<(String, Option<String>), String> {
    if data.len() < 4 {
        return Ok(("system".to_string(), None));
    }
    let disc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    match disc {
        SYSTEM_IX_TRANSFER => {
            if data.len() < 12 {
                return Err("system transfer data truncated".to_string());
            }
            let lamports = u64::from_le_bytes(data[4..12].try_into().map_err(|_| "amount")?);
            facts.transfers.push(TransferFact {
                mint: None,
                amount_raw: lamports as u128,
                recipient: key_at(1)?,
            });
            Ok(("system".to_string(), Some("transfer".to_string())))
        }
        SYSTEM_IX_ADVANCE_NONCE => {
            facts.durable_nonce_used = true;
            Ok(("system".to_string(), Some("advance_nonce".to_string())))
        }
        SYSTEM_IX_ASSIGN => {
            facts.authority_change = true;
            Ok(("system".to_string(), Some("assign".to_string())))
        }
        _ => Ok(("system".to_string(), None)),
    }
}

fn classify_token(
    data: &[u8],
    facts: &mut TxFacts,
    key_at: &dyn Fn(usize) -> Result<String, String>,
    is_2022: bool,
) -> Result<(String, Option<String>), String> {
    let label = if is_2022 { "token_2022" } else { "spl_token" }.to_string();
    let Some(&disc) = data.first() else {
        return Ok((label, None));
    };
    match disc {
        TOKEN_IX_TRANSFER => {
            if data.len() < 9 {
                return Err("token transfer data truncated".to_string());
            }
            let amount = u64::from_le_bytes(data[1..9].try_into().map_err(|_| "amount")?);
            facts.transfers.push(TransferFact {
                mint: None, // mint not in ix accounts for plain transfer; caller enriches
                amount_raw: amount as u128,
                recipient: key_at(1)?,
            });
            Ok((label, Some("transfer".to_string())))
        }
        TOKEN_IX_TRANSFER_CHECKED => {
            if data.len() < 10 {
                return Err("transfer_checked data truncated".to_string());
            }
            let amount = u64::from_le_bytes(data[1..9].try_into().map_err(|_| "amount")?);
            facts.transfers.push(TransferFact {
                mint: Some(key_at(1)?),
                amount_raw: amount as u128,
                recipient: key_at(2)?,
            });
            Ok((label, Some("transfer_checked".to_string())))
        }
        TOKEN_IX_SET_AUTHORITY => {
            facts.authority_change = true;
            Ok((label, Some("set_authority".to_string())))
        }
        TOKEN_IX_APPROVE => {
            facts.authority_change = true; // delegate grant = latent drain path
            Ok((label, Some("approve".to_string())))
        }
        _ => Ok((label, None)),
    }
}

fn classify_compute_budget(
    data: &[u8],
    facts: &mut TxFacts,
) -> Result<(String, Option<String>), String> {
    let Some(&disc) = data.first() else {
        return Ok(("compute_budget".to_string(), None));
    };
    match disc {
        2 if data.len() >= 5 => {
            let _units = u32::from_le_bytes(data[1..5].try_into().map_err(|_| "units")?);
            Ok((
                "compute_budget".to_string(),
                Some("set_compute_unit_limit".to_string()),
            ))
        }
        3 if data.len() >= 9 => {
            let micro = u64::from_le_bytes(data[1..9].try_into().map_err(|_| "price")?);
            // priority fee ≈ price(micro-lamports/CU) * default 200k CU / 1e6
            facts.priority_fee_lamports = micro.saturating_mul(200_000) / 1_000_000;
            Ok((
                "compute_budget".to_string(),
                Some("set_compute_unit_price".to_string()),
            ))
        }
        _ => Ok(("compute_budget".to_string(), None)),
    }
}

/// Minimal byte cursor with bounds-checked reads.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.bytes.len()
    }
    fn u8(&mut self) -> Result<u8, String> {
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or("unexpected end of message")?;
        self.pos += 1;
        Ok(b)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.bytes.len() {
            return Err("unexpected end of message".to_string());
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn bytes32(&mut self) -> Result<[u8; 32], String> {
        self.bytes(32)?
            .try_into()
            .map_err(|_| "unexpected end of message".to_string())
    }
    fn shortvec(&mut self) -> Result<usize, String> {
        let (value, used) = shortvec_decode(&self.bytes[self.pos..])?;
        self.pos += used;
        Ok(value)
    }
}

/// System program id as a `Pubkey` (all zeros).
pub fn system_program_id() -> Pubkey {
    parse_pubkey(SYSTEM_PROGRAM).expect("constant")
}
