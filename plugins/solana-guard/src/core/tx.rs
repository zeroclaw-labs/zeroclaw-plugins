//! Solana transaction wire decode (legacy + v0), SDK-less.

use crate::core::base64;
use crate::core::pubkey::{Pubkey, PUBKEY_BYTES};

#[derive(Debug, Clone)]
pub struct DecodedTransaction {
    pub version: TxVersion,
    pub signatures: Vec<[u8; 64]>,
    pub message: Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxVersion {
    Legacy,
    V0,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
    /// Address-lookup tables (v0 only). Empty for legacy.
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MessageAddressTableLookup {
    pub account_key: Pubkey,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Base64(String),
    Truncated(&'static str),
    Invalid(&'static str),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Base64(e) => write!(f, "base64: {e}"),
            DecodeError::Truncated(m) => write!(f, "truncated: {m}"),
            DecodeError::Invalid(m) => write!(f, "invalid: {m}"),
        }
    }
}

/// Decode a base64-encoded Solana transaction (legacy or v0).
pub fn decode_transaction_base64(b64: &str) -> Result<DecodedTransaction, DecodeError> {
    let bytes = base64::decode(b64.trim()).map_err(DecodeError::Base64)?;
    decode_transaction_bytes(&bytes)
}

pub fn decode_transaction_bytes(bytes: &[u8]) -> Result<DecodedTransaction, DecodeError> {
    let mut cursor = Cursor::new(bytes);
    let sig_count = cursor.read_compact_u16()? as usize;
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let mut sig = [0u8; 64];
        cursor.read_exact(&mut sig)?;
        signatures.push(sig);
    }

    let version_byte = *cursor
        .peek()
        .ok_or(DecodeError::Truncated("message version"))?;

    let (version, message) = if version_byte & 0x80 != 0 {
        let ver = version_byte & 0x7f;
        if ver != 0 {
            return Err(DecodeError::Invalid("unsupported transaction version"));
        }
        cursor.read_u8()?; // consume version prefix
        (TxVersion::V0, read_message_v0(&mut cursor)?)
    } else {
        (TxVersion::Legacy, read_message_legacy(&mut cursor)?)
    };

    if cursor.remaining() != 0 {
        return Err(DecodeError::Invalid("trailing transaction bytes"));
    }

    validate_transaction(sig_count, &message)?;

    Ok(DecodedTransaction {
        version,
        signatures,
        message,
    })
}

fn validate_transaction(signature_count: usize, message: &Message) -> Result<(), DecodeError> {
    let static_count = message.account_keys.len();
    let required = usize::from(message.header.num_required_signatures);
    let readonly_signed = usize::from(message.header.num_readonly_signed_accounts);
    let readonly_unsigned = usize::from(message.header.num_readonly_unsigned_accounts);

    if required == 0 {
        return Err(DecodeError::Invalid(
            "transaction has no fee-payer signature",
        ));
    }
    if signature_count != required {
        return Err(DecodeError::Invalid(
            "signature count does not match message header",
        ));
    }
    if required > static_count {
        return Err(DecodeError::Invalid(
            "required signatures exceed static account keys",
        ));
    }
    if readonly_signed > required {
        return Err(DecodeError::Invalid(
            "readonly signed accounts exceed required signatures",
        ));
    }
    if readonly_unsigned > static_count - required {
        return Err(DecodeError::Invalid(
            "readonly unsigned accounts exceed unsigned account keys",
        ));
    }

    let loaded_count = message
        .address_table_lookups
        .iter()
        .try_fold(0usize, |total, lookup| {
            total
                .checked_add(lookup.writable_indexes.len())
                .and_then(|n| n.checked_add(lookup.readonly_indexes.len()))
        })
        .ok_or(DecodeError::Invalid("loaded account count overflow"))?;
    let total_count = static_count
        .checked_add(loaded_count)
        .ok_or(DecodeError::Invalid("account count overflow"))?;
    if total_count > usize::from(u8::MAX) + 1 {
        return Err(DecodeError::Invalid(
            "transaction has more than 256 accounts",
        ));
    }

    for ix in &message.instructions {
        if usize::from(ix.program_id_index) >= total_count {
            return Err(DecodeError::Invalid("program id index out of range"));
        }
        if ix
            .accounts
            .iter()
            .any(|index| usize::from(*index) >= total_count)
        {
            return Err(DecodeError::Invalid(
                "instruction account index out of range",
            ));
        }
    }

    Ok(())
}

fn read_message_legacy(cursor: &mut Cursor<'_>) -> Result<Message, DecodeError> {
    let header = read_header(cursor)?;
    let account_keys = read_pubkeys(cursor)?;
    let recent_blockhash = read_hash(cursor)?;
    let instructions = read_instructions(cursor)?;
    Ok(Message {
        header,
        account_keys,
        recent_blockhash,
        instructions,
        address_table_lookups: Vec::new(),
    })
}

fn read_message_v0(cursor: &mut Cursor<'_>) -> Result<Message, DecodeError> {
    let header = read_header(cursor)?;
    let account_keys = read_pubkeys(cursor)?;
    let recent_blockhash = read_hash(cursor)?;
    let instructions = read_instructions(cursor)?;
    let lookup_count = cursor.read_compact_u16()? as usize;
    let mut address_table_lookups = Vec::with_capacity(lookup_count);
    for _ in 0..lookup_count {
        let account_key = read_pubkey(cursor)?;
        let writable_indexes = read_byte_array(cursor)?;
        let readonly_indexes = read_byte_array(cursor)?;
        address_table_lookups.push(MessageAddressTableLookup {
            account_key,
            writable_indexes,
            readonly_indexes,
        });
    }
    Ok(Message {
        header,
        account_keys,
        recent_blockhash,
        instructions,
        address_table_lookups,
    })
}

fn read_header(cursor: &mut Cursor<'_>) -> Result<MessageHeader, DecodeError> {
    Ok(MessageHeader {
        num_required_signatures: cursor.read_u8()?,
        num_readonly_signed_accounts: cursor.read_u8()?,
        num_readonly_unsigned_accounts: cursor.read_u8()?,
    })
}

fn read_pubkeys(cursor: &mut Cursor<'_>) -> Result<Vec<Pubkey>, DecodeError> {
    let n = cursor.read_compact_u16()? as usize;
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        keys.push(read_pubkey(cursor)?);
    }
    Ok(keys)
}

fn read_pubkey(cursor: &mut Cursor<'_>) -> Result<Pubkey, DecodeError> {
    let mut buf = [0u8; PUBKEY_BYTES];
    cursor.read_exact(&mut buf)?;
    Ok(Pubkey::new(buf))
}

fn read_hash(cursor: &mut Cursor<'_>) -> Result<[u8; 32], DecodeError> {
    let mut buf = [0u8; 32];
    cursor.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_instructions(cursor: &mut Cursor<'_>) -> Result<Vec<CompiledInstruction>, DecodeError> {
    let n = cursor.read_compact_u16()? as usize;
    let mut ixs = Vec::with_capacity(n);
    for _ in 0..n {
        let program_id_index = cursor.read_u8()?;
        let accounts = read_byte_array(cursor)?;
        let data = read_byte_array(cursor)?;
        ixs.push(CompiledInstruction {
            program_id_index,
            accounts,
            data,
        });
    }
    Ok(ixs)
}

fn read_byte_array(cursor: &mut Cursor<'_>) -> Result<Vec<u8>, DecodeError> {
    let n = cursor.read_compact_u16()? as usize;
    cursor.read_vec(n)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn peek(&self) -> Option<&u8> {
        self.data.get(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(DecodeError::Truncated("u8"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
        if self.remaining() < buf.len() {
            return Err(DecodeError::Truncated("bytes"));
        }
        buf.copy_from_slice(&self.data[self.pos..self.pos + buf.len()]);
        self.pos += buf.len();
        Ok(())
    }

    fn read_vec(&mut self, n: usize) -> Result<Vec<u8>, DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated("vec"));
        }
        let v = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    /// Solana shortvec / compact-u16.
    fn read_compact_u16(&mut self) -> Result<u16, DecodeError> {
        let mut val: u16 = 0;
        for i in 0..3 {
            let byte = self.read_u8()?;
            if i == 2 && byte > 0x03 {
                return Err(DecodeError::Invalid("compact-u16 overflow"));
            }
            if i > 0 && byte == 0 {
                return Err(DecodeError::Invalid("non-canonical compact-u16"));
            }
            val |= u16::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(val);
            }
        }
        Err(DecodeError::Invalid("compact-u16 overflow"))
    }
}

impl DecodedTransaction {
    pub fn program_id_for(&self, ix: &CompiledInstruction) -> Option<&Pubkey> {
        self.message.account_keys.get(ix.program_id_index as usize)
    }

    pub fn account_at(&self, index: u8) -> Option<&Pubkey> {
        self.message.account_keys.get(index as usize)
    }
}
