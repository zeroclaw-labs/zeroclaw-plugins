//! Strict Solana wire-format parsing for legacy and v0 transactions.
//!
//! This module intentionally avoids `solana-sdk`: the plugin must compile as a
//! small `wasm32-wasip2` component. Every length and index is bounds checked,
//! non-canonical compact lengths are rejected, and unresolved lookup tables
//! fail closed.

use crate::rpc::RpcClient;

pub const ADDRESS_LOOKUP_TABLE_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
const MAX_TRANSACTION_BYTES: usize = 1232;
const LOOKUP_TABLE_META_BYTES: usize = 56;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageVersion {
    Legacy,
    V0,
}

impl MessageVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::V0 => "v0",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMetaView {
    pub address: String,
    pub signer: bool,
    pub writable: bool,
    pub from_lookup_table: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInstruction {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransaction {
    pub version: MessageVersion,
    pub message_bytes: Vec<u8>,
    pub signature_count: usize,
    pub nonzero_signatures: usize,
    pub fee_payer: String,
    pub signers: Vec<String>,
    pub accounts: Vec<AccountMetaView>,
    pub recent_blockhash: String,
    pub instructions: Vec<ParsedInstruction>,
    pub lookup_table_count: usize,
}

impl ParsedTransaction {
    pub fn writable_account_count(&self) -> usize {
        self.accounts
            .iter()
            .filter(|account| account.writable)
            .count()
    }
}

#[derive(Clone, Debug)]
struct WireInstruction {
    program_index: u8,
    account_indexes: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct AddressLookup {
    table_address: String,
    writable_indexes: Vec<u8>,
    readonly_indexes: Vec<u8>,
}

pub fn parse_transaction(
    bytes: &[u8],
    rpc: &mut dyn RpcClient,
) -> Result<ParsedTransaction, String> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(format!(
            "transaction is {} bytes; Solana packet limit is {MAX_TRANSACTION_BYTES}",
            bytes.len()
        ));
    }
    if bytes.len() < 4 {
        return Err("transaction is too short".to_string());
    }

    let mut tx_cursor = Cursor::new(bytes);
    let signature_count = tx_cursor.read_compact_len("signature count", 64)?;
    let signatures = tx_cursor.read_exact(
        signature_count
            .checked_mul(64)
            .ok_or_else(|| "signature byte length overflow".to_string())?,
        "signatures",
    )?;
    let nonzero_signatures = signatures
        .chunks_exact(64)
        .filter(|signature| signature.iter().any(|byte| *byte != 0))
        .count();
    let message_bytes = tx_cursor.remaining().to_vec();
    if message_bytes.is_empty() {
        return Err("transaction has no message".to_string());
    }

    let mut cursor = Cursor::new(&message_bytes);
    let first = cursor.read_u8("message prefix")?;
    let (version, required_signatures) = if first & 0x80 != 0 {
        let version = first & 0x7f;
        if version != 0 {
            return Err(format!("unsupported versioned message v{version}"));
        }
        (MessageVersion::V0, cursor.read_u8("required signatures")?)
    } else {
        (MessageVersion::Legacy, first)
    };
    let readonly_signed = cursor.read_u8("readonly signed accounts")? as usize;
    let readonly_unsigned = cursor.read_u8("readonly unsigned accounts")? as usize;
    let required_signatures = required_signatures as usize;

    if signature_count != required_signatures {
        return Err(format!(
            "signature vector has {signature_count} entries but message requires {required_signatures}"
        ));
    }

    let static_count = cursor.read_compact_len("static account count", 256)?;
    if static_count == 0 {
        return Err("message has no fee payer".to_string());
    }
    if required_signatures > static_count || readonly_signed > required_signatures {
        return Err("message header signer counts are inconsistent".to_string());
    }
    let unsigned_count = static_count - required_signatures;
    if readonly_unsigned > unsigned_count {
        return Err("message header unsigned-account counts are inconsistent".to_string());
    }

    let mut static_keys = Vec::with_capacity(static_count);
    for _ in 0..static_count {
        static_keys.push(read_pubkey(&mut cursor, "static account")?);
    }
    let recent_blockhash = read_pubkey(&mut cursor, "recent blockhash")?;

    let instruction_count = cursor.read_compact_len("instruction count", 256)?;
    let mut wire_instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program_index = cursor.read_u8("program index")?;
        let account_count = cursor.read_compact_len("instruction account count", 256)?;
        let account_indexes = cursor
            .read_exact(account_count, "instruction account indexes")?
            .to_vec();
        let data_len = cursor.read_compact_len("instruction data length", MAX_TRANSACTION_BYTES)?;
        let data = cursor.read_exact(data_len, "instruction data")?.to_vec();
        wire_instructions.push(WireInstruction {
            program_index,
            account_indexes,
            data,
        });
    }

    let lookups = if version == MessageVersion::V0 {
        let count = cursor.read_compact_len("lookup table count", 32)?;
        let mut lookups = Vec::with_capacity(count);
        for _ in 0..count {
            let table_address = read_pubkey(&mut cursor, "lookup table address")?;
            let writable_count = cursor.read_compact_len("lookup writable count", 256)?;
            let writable_indexes = cursor
                .read_exact(writable_count, "lookup writable indexes")?
                .to_vec();
            let readonly_count = cursor.read_compact_len("lookup readonly count", 256)?;
            let readonly_indexes = cursor
                .read_exact(readonly_count, "lookup readonly indexes")?
                .to_vec();
            lookups.push(AddressLookup {
                table_address,
                writable_indexes,
                readonly_indexes,
            });
        }
        lookups
    } else {
        Vec::new()
    };

    if !cursor.is_finished() {
        return Err(format!(
            "message has {} trailing bytes",
            cursor.remaining().len()
        ));
    }

    let signed_writable_end = required_signatures - readonly_signed;
    let unsigned_writable_end = static_count - readonly_unsigned;
    let mut accounts = static_keys
        .iter()
        .enumerate()
        .map(|(index, address)| AccountMetaView {
            address: address.clone(),
            signer: index < required_signatures,
            writable: if index < required_signatures {
                index < signed_writable_end
            } else {
                index < unsigned_writable_end
            },
            from_lookup_table: false,
        })
        .collect::<Vec<_>>();

    let mut lookup_writable = Vec::new();
    let mut lookup_readonly = Vec::new();
    for lookup in &lookups {
        let table = rpc
            .get_account(&lookup.table_address)?
            .ok_or_else(|| format!("lookup table {} does not exist", lookup.table_address))?;
        if table.owner != ADDRESS_LOOKUP_TABLE_PROGRAM {
            return Err(format!(
                "lookup table {} has unexpected owner {}",
                lookup.table_address, table.owner
            ));
        }
        let addresses = lookup_addresses(&table.data)?;
        for index in &lookup.writable_indexes {
            let address = addresses.get(*index as usize).ok_or_else(|| {
                format!(
                    "lookup table {} has no writable index {}",
                    lookup.table_address, index
                )
            })?;
            lookup_writable.push(address.clone());
        }
        for index in &lookup.readonly_indexes {
            let address = addresses.get(*index as usize).ok_or_else(|| {
                format!(
                    "lookup table {} has no readonly index {}",
                    lookup.table_address, index
                )
            })?;
            lookup_readonly.push(address.clone());
        }
    }
    accounts.extend(lookup_writable.into_iter().map(|address| AccountMetaView {
        address,
        signer: false,
        writable: true,
        from_lookup_table: true,
    }));
    accounts.extend(lookup_readonly.into_iter().map(|address| AccountMetaView {
        address,
        signer: false,
        writable: false,
        from_lookup_table: true,
    }));

    let mut instructions = Vec::with_capacity(wire_instructions.len());
    for instruction in wire_instructions {
        let program_id = accounts
            .get(instruction.program_index as usize)
            .ok_or_else(|| {
                format!(
                    "program index {} is out of range",
                    instruction.program_index
                )
            })?
            .address
            .clone();
        let instruction_accounts = instruction
            .account_indexes
            .iter()
            .map(|index| {
                accounts
                    .get(*index as usize)
                    .map(|account| account.address.clone())
                    .ok_or_else(|| format!("instruction account index {index} is out of range"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        instructions.push(ParsedInstruction {
            program_id,
            accounts: instruction_accounts,
            data: instruction.data,
        });
    }

    let fee_payer = accounts[0].address.clone();
    let signers = accounts
        .iter()
        .filter(|account| account.signer)
        .map(|account| account.address.clone())
        .collect();

    Ok(ParsedTransaction {
        version,
        message_bytes,
        signature_count,
        nonzero_signatures,
        fee_payer,
        signers,
        accounts,
        recent_blockhash,
        instructions,
        lookup_table_count: lookups.len(),
    })
}

fn lookup_addresses(data: &[u8]) -> Result<Vec<String>, String> {
    if data.len() < LOOKUP_TABLE_META_BYTES {
        return Err("lookup table account is shorter than its metadata header".to_string());
    }
    let address_bytes = &data[LOOKUP_TABLE_META_BYTES..];
    if !address_bytes.len().is_multiple_of(32) {
        return Err("lookup table address payload is not aligned to 32 bytes".to_string());
    }
    Ok(address_bytes
        .chunks_exact(32)
        .map(|bytes| bs58::encode(bytes).into_string())
        .collect())
}

fn read_pubkey(cursor: &mut Cursor<'_>, label: &str) -> Result<String, String> {
    Ok(bs58::encode(cursor.read_exact(32, label)?).into_string())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self, label: &str) -> Result<u8, String> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| format!("unexpected end while reading {label}"))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_exact(&mut self, length: usize, label: &str) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| format!("{label} length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| format!("unexpected end while reading {label}"))?;
        self.position = end;
        Ok(value)
    }

    fn read_compact_len(&mut self, label: &str, max: usize) -> Result<usize, String> {
        let mut value = 0u16;
        for byte_index in 0..3 {
            let byte = self.read_u8(label)?;
            if byte_index == 2 && byte & 0xfc != 0 {
                return Err(format!("{label} compact length overflows u16"));
            }
            let payload = (byte & 0x7f) as u16;
            if byte_index > 0 && payload == 0 && byte & 0x80 == 0 {
                return Err(format!("{label} compact length is not canonical"));
            }
            value |= payload << (byte_index * 7);
            if byte & 0x80 == 0 {
                let value = value as usize;
                if value > max {
                    return Err(format!("{label} {value} exceeds limit {max}"));
                }
                return Ok(value);
            }
        }
        Err(format!("{label} compact length is too long"))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::{parse_transaction, Cursor};
    use crate::rpc::{RpcAccount, RpcClient, SimulationResult};

    struct NoopRpc;

    impl RpcClient for NoopRpc {
        fn get_account(&mut self, _address: &str) -> Result<Option<RpcAccount>, String> {
            Err("random fixture has no RPC accounts".to_string())
        }

        fn get_fee_for_message(&mut self, _message_base64: &str) -> Result<Option<u64>, String> {
            Ok(Some(5_000))
        }

        fn get_minimum_balance_for_rent_exemption(
            &mut self,
            _data_len: usize,
        ) -> Result<u64, String> {
            Ok(2_039_280)
        }

        fn simulate_transaction(
            &mut self,
            _transaction_base64: &str,
        ) -> Result<SimulationResult, String> {
            unreachable!("wire parser never simulates")
        }
    }

    #[test]
    fn compact_lengths_are_strict() {
        let mut one = Cursor::new(&[0x7f]);
        assert_eq!(one.read_compact_len("test", 200).unwrap(), 127);

        let mut two = Cursor::new(&[0x80, 0x01]);
        assert_eq!(two.read_compact_len("test", 200).unwrap(), 128);

        let mut noncanonical = Cursor::new(&[0x81, 0x00]);
        assert!(noncanonical.read_compact_len("test", 200).is_err());

        let mut overflow = Cursor::new(&[0xff, 0xff, 0x04]);
        assert!(overflow.read_compact_len("test", usize::MAX).is_err());
    }

    #[test]
    fn bounded_random_wire_inputs_never_panic() {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for case in 0..4_096usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state as usize ^ case) % 1_233;
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let mut rpc = NoopRpc;
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = parse_transaction(&bytes, &mut rpc);
            }));
            assert!(result.is_ok(), "parser panicked on random case {case}");
        }
    }
}
