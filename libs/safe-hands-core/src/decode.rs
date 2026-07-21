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
    /// All statically known account keys, base58, in message order.
    pub resolved_keys: Vec<String>,
    pub version: TxVersion,
    pub blockhash: String,
    /// v0 address-lookup-table references (table address + indices).
    /// Contents are NOT resolved here — that needs RPC (caller binds).
    pub alt_refs: Vec<AltRef>,
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
pub fn decode(bytes: &[u8]) -> Result<DecodedTx, String> {
    if bytes.is_empty() {
        return Err("empty transaction bytes".to_string());
    }

    // Two legal shapes: full transaction (sig array + message) or bare message.
    // The sig-array form wins when it parses; otherwise we retry as bare
    // (a bare legacy message can start with the same byte as a sig count).
    if let Some((signed, rest)) = try_strip_signatures(bytes)? {
        if let Ok(mut decoded) = decode_message(rest) {
            decoded.facts.signed = signed;
            decoded.facts.byte_len = bytes.len();
            return Ok(decoded);
        }
    }
    decode_message(bytes).map(|mut d| {
        d.facts.byte_len = bytes.len();
        d
    })
}

/// Decode message bytes (no signature array): version detect + parse + classify.
fn decode_message(message_bytes: &[u8]) -> Result<DecodedTx, String> {
    if message_bytes.is_empty() {
        return Err("empty message bytes".to_string());
    }
    let (version, body) = if message_bytes[0] & 0x80 != 0 {
        (TxVersion::V0, &message_bytes[1..])
    } else {
        (TxVersion::Legacy, message_bytes)
    };

    let (header_signers, keys, blockhash, raw_ixs, alt_refs) = match version {
        TxVersion::Legacy => parse_legacy(body)?,
        TxVersion::V0 => parse_v0(body)?,
    };

    let resolved_keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    let mut facts = TxFacts {
        byte_len: message_bytes.len(),
        ..Default::default()
    };
    facts.estimated_fee_lamports = 5_000u64.saturating_mul(header_signers as u64);

    for (program_id, accounts, data) in &raw_ixs {
        classify(*program_id, accounts, data, &keys, &mut facts)?;
    }

    Ok(DecodedTx {
        facts,
        resolved_keys,
        version,
        blockhash: bs58::encode(blockhash).into_string(),
        alt_refs,
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

type RawIx = (Pubkey, Vec<u8>, Vec<u8>); // (program, account indices, data)
type ParsedParts = (u8, Vec<Pubkey>, [u8; 32], Vec<RawIx>, Vec<AltRef>);

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
    for ci in &msg.instructions {
        if ixs.len() >= MAX_INSTRUCTIONS {
            return Err("instruction vector exceeds bound".to_string());
        }
        let program = keys
            .get(ci.program_id_index as usize)
            .ok_or("program id index out of range")?;
        ixs.push((*program, ci.accounts.clone(), ci.data.clone()));
    }
    Ok((
        msg.header.num_required_signatures,
        keys,
        msg.recent_blockhash.to_bytes(),
        ixs,
        vec![],
    ))
}

/// v0: hand-parse per the wire spec (header + keys + blockhash + ixs + ALT lookups).
fn parse_v0(bytes: &[u8]) -> Result<ParsedParts, String> {
    let mut cur = Cursor::new(bytes);
    let num_signers = cur.u8()?;
    let _readonly_signed = cur.u8()?;
    let _readonly_unsigned = cur.u8()?;
    let key_count = cur.shortvec()?;
    if key_count > MAX_ACCOUNTS {
        return Err("account vector exceeds bound".to_string());
    }
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        keys.push(Pubkey::new_from_array(cur.bytes32()?));
    }
    let blockhash = cur.bytes32()?;
    let ix_count = cur.shortvec()?;
    if ix_count > MAX_INSTRUCTIONS {
        return Err("instruction vector exceeds bound".to_string());
    }
    let mut ixs = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_idx = cur.u8()? as usize;
        let account_count = cur.shortvec()?;
        if account_count > MAX_ACCOUNTS {
            return Err("instruction account vector exceeds bound".to_string());
        }
        let mut acc_indices = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            acc_indices.push(cur.u8()?);
        }
        let data_len = cur.shortvec()?;
        let data = cur.bytes(data_len)?.to_vec();
        let program = *keys
            .get(program_idx)
            .ok_or("program id index out of range")?;
        ixs.push((program, acc_indices, data));
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
    Ok((num_signers, keys, blockhash, ixs, alt_refs))
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
