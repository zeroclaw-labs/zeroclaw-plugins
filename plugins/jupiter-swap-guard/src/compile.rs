//! Compile a list of full-pubkey `Instruction`s plus fetched lookup-table
//! contents into a `V0Message` — the static/lookup account partition, the header
//! counts, and the index-compiled instructions. A faithful reimplementation of
//! Solana's `CompiledKeys` / `v0::Message::try_compile`, kept byte-exact by the
//! differential test against the Anza crates on a real route.
//!
//! This is also where `D5` is enforced: the caller's `must_be_static` accounts
//! (payer, the payer's own ATAs) are asserted to land in the STATIC key set, never
//! resolved through a lookup table — so a malicious RPC's table contents can never
//! silently change which account fills a fund role.

#![forbid(unsafe_code)]

use crate::encode::{
    CompiledInstruction, MessageAddressTableLookup, MessageHeader, Pubkey, V0Message,
};
use crate::instruction::Instruction;
use std::collections::BTreeMap;

/// The resolved contents of one on-chain address lookup table.
#[derive(Debug, Clone)]
pub struct AddressLookupTable {
    pub key: Pubkey,
    pub addresses: Vec<Pubkey>,
}

#[derive(Default, Clone, Copy)]
struct KeyMeta {
    is_signer: bool,
    is_writable: bool,
    is_invoked: bool,
}

/// Reason a compile was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    TooManyAccounts,
    AccountNotFound,
    /// A `D5` violation: an account that must stay static was drained into a lookup.
    MustBeStaticWasLookedUp(Pubkey),
}

struct CompiledKeys {
    payer: Pubkey,
    map: BTreeMap<Pubkey, KeyMeta>,
}

impl CompiledKeys {
    fn compile(instructions: &[Instruction], payer: Pubkey) -> Self {
        let mut map: BTreeMap<Pubkey, KeyMeta> = BTreeMap::new();
        for ix in instructions {
            map.entry(ix.program_id).or_default().is_invoked = true;
            for am in &ix.accounts {
                let m = map.entry(am.pubkey).or_default();
                m.is_signer |= am.is_signer;
                m.is_writable |= am.is_writable;
            }
        }
        let m = map.entry(payer).or_default();
        m.is_signer = true;
        m.is_writable = true;
        CompiledKeys { payer, map }
    }

    /// Drain every non-signer, non-invoked key matching `writable` that appears in
    /// `table`, returning (indexes into the table, drained keys) in key-sorted order.
    fn drain_into_lookup(&mut self, table: &[Pubkey], writable: bool) -> (Vec<u8>, Vec<Pubkey>) {
        let candidates: Vec<Pubkey> = self
            .map
            .iter()
            .filter(|(_, m)| !m.is_signer && !m.is_invoked && m.is_writable == writable)
            .map(|(k, _)| *k)
            .collect();
        let mut indexes = Vec::new();
        let mut drained = Vec::new();
        for key in candidates {
            if let Some(pos) = table.iter().position(|a| *a == key) {
                if let Ok(idx) = u8::try_from(pos) {
                    indexes.push(idx);
                    drained.push(key);
                    self.map.remove(&key);
                }
            }
        }
        (indexes, drained)
    }

    fn extract_lookup(
        &mut self,
        table: &AddressLookupTable,
    ) -> Option<(MessageAddressTableLookup, Vec<Pubkey>, Vec<Pubkey>)> {
        let (writable_indexes, writable_keys) = self.drain_into_lookup(&table.addresses, true);
        let (readonly_indexes, readonly_keys) = self.drain_into_lookup(&table.addresses, false);
        if writable_indexes.is_empty() && readonly_indexes.is_empty() {
            return None;
        }
        Some((
            MessageAddressTableLookup {
                account_key: table.key,
                writable_indexes,
                readonly_indexes,
            },
            writable_keys,
            readonly_keys,
        ))
    }

    /// (header, static_keys) with the payer forced first among writable signers.
    fn into_static(mut self) -> (MessageHeader, Vec<Pubkey>) {
        self.map.remove(&self.payer);
        let pick = |map: &BTreeMap<Pubkey, KeyMeta>, sign: bool, write: bool| -> Vec<Pubkey> {
            map.iter()
                .filter(|(_, m)| m.is_signer == sign && m.is_writable == write)
                .map(|(k, _)| *k)
                .collect()
        };
        let mut writable_signers = vec![self.payer];
        writable_signers.extend(pick(&self.map, true, true));
        let readonly_signers = pick(&self.map, true, false);
        let writable_non = pick(&self.map, false, true);
        let readonly_non = pick(&self.map, false, false);
        let header = MessageHeader {
            num_required_signatures: (writable_signers.len() + readonly_signers.len()) as u8,
            num_readonly_signed_accounts: readonly_signers.len() as u8,
            num_readonly_unsigned_accounts: readonly_non.len() as u8,
        };
        let mut static_keys = writable_signers;
        static_keys.extend(readonly_signers);
        static_keys.extend(writable_non);
        static_keys.extend(readonly_non);
        (header, static_keys)
    }
}

/// Compile instructions + lookup tables into a `V0Message`. Enforces `D5`:
/// every `must_be_static` account must end up in the static key set.
pub fn compile_v0(
    payer: Pubkey,
    instructions: &[Instruction],
    lookup_tables: &[AddressLookupTable],
    recent_blockhash: [u8; 32],
    must_be_static: &[Pubkey],
) -> Result<V0Message, CompileError> {
    let mut keys = CompiledKeys::compile(instructions, payer);

    let mut address_table_lookups = Vec::new();
    let mut loaded_writable: Vec<Pubkey> = Vec::new();
    let mut loaded_readonly: Vec<Pubkey> = Vec::new();
    for table in lookup_tables {
        if let Some((lookup, w, r)) = keys.extract_lookup(table) {
            address_table_lookups.push(lookup);
            loaded_writable.extend(w);
            loaded_readonly.extend(r);
        }
    }

    // D5: anything that must stay static must NOT have been drained into a lookup.
    for req in must_be_static {
        if loaded_writable.contains(req) || loaded_readonly.contains(req) {
            return Err(CompileError::MustBeStaticWasLookedUp(*req));
        }
    }

    let (header, static_keys) = keys.into_static();

    // Combined address order the instruction indices reference:
    // static keys, then all loaded-writable, then all loaded-readonly.
    let mut combined = static_keys.clone();
    combined.extend(loaded_writable.iter().copied());
    combined.extend(loaded_readonly.iter().copied());
    if combined.len() > u8::MAX as usize + 1 {
        return Err(CompileError::TooManyAccounts);
    }
    let index_of = |k: &Pubkey| -> Result<u8, CompileError> {
        combined
            .iter()
            .position(|x| x == k)
            .map(|p| p as u8)
            .ok_or(CompileError::AccountNotFound)
    };

    let mut compiled = Vec::with_capacity(instructions.len());
    for ix in instructions {
        let program_id_index = index_of(&ix.program_id)?;
        let accounts = ix
            .accounts
            .iter()
            .map(|a| index_of(&a.pubkey))
            .collect::<Result<Vec<u8>, _>>()?;
        compiled.push(CompiledInstruction {
            program_id_index,
            accounts,
            data: ix.data.clone(),
        });
    }

    Ok(V0Message {
        header,
        static_keys,
        recent_blockhash,
        instructions: compiled,
        address_table_lookups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b58::decode_pubkey;
    use crate::encode::serialize_v0;
    use crate::jupiter::parse_swap_instructions;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn real_route() -> (Vec<Instruction>, AddressLookupTable, Pubkey) {
        let body = std::fs::read_to_string(format!("{FX}/swap-instructions.json")).unwrap();
        let s = parse_swap_instructions(&body).unwrap();
        let alt_key = s.address_lookup_tables[0];
        let alt_json = std::fs::read_to_string(format!("{FX}/alt_account.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&alt_json).unwrap();
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(v["result"]["value"]["data"][0].as_str().unwrap())
            .unwrap();
        let addresses = data[56..]
            .chunks_exact(32)
            .map(|c| <[u8; 32]>::try_from(c).unwrap())
            .collect();
        let payer = decode_pubkey(
            std::fs::read_to_string(format!("{FX}/payer_pubkey.txt"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        (
            s.ordered(),
            AddressLookupTable {
                key: alt_key,
                addresses,
            },
            payer,
        )
    }

    #[test]
    fn compiles_real_route_to_expected_shape() {
        let (ixs, alt, payer) = real_route();
        let msg = compile_v0(payer, &ixs, &[alt], [7u8; 32], &[payer]).unwrap();
        // Matches the shape solana-message produced in KT-1.
        assert_eq!(msg.static_keys.len(), 9);
        assert_eq!(msg.address_table_lookups.len(), 1);
        assert_eq!(msg.address_table_lookups[0].writable_indexes.len(), 3);
        assert_eq!(msg.address_table_lookups[0].readonly_indexes.len(), 4);
        assert_eq!(msg.static_keys[0], payer); // payer is the first signer
                                               // Serialized length matches the KT-1 golden length (505 bytes).
        assert_eq!(serialize_v0(&msg).len(), 505);
    }

    #[test]
    fn d5_refuses_when_a_required_static_account_is_in_the_table() {
        let (ixs, mut alt, payer) = real_route();
        // Force the payer's output ATA to be resolvable via the lookup table.
        let output_ata = decode_pubkey("FMbvJrg96qADXK2QYx2kuEVbSHwbjxAh2z4qeYjd2MSw").unwrap();
        alt.addresses.push(output_ata);
        let err = compile_v0(payer, &ixs, &[alt], [7u8; 32], &[output_ata]).unwrap_err();
        assert_eq!(err, CompileError::MustBeStaticWasLookedUp(output_ata));
    }
}
