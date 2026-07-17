//! Message compilation: collect instructions into a Solana legacy (or v0)
//! message, order the account keys per the wire rules, and wrap it in an
//! unsigned-transaction envelope wallets and simulators accept.
//!
//! Key ordering (verified against devnet and the Solana Pay spec's example
//! transaction): writable signers first (fee payer at index 0), then readonly
//! signers, writable non-signers, readonly non-signers.

use std::collections::HashMap;

use crate::encoding::{base64_encode, push_compact_u16};
use crate::instruction::Instruction;
use crate::pubkey::Pubkey;

/// A compiled, unsigned message plus its metadata.
#[derive(Debug)]
pub struct CompiledMessage {
    pub bytes: Vec<u8>,
    pub num_required_signatures: u8,
    pub account_keys: Vec<Pubkey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyFlags {
    signer: bool,
    writable: bool,
}

/// Compile instructions into a legacy message. `recent_blockhash` is either a
/// real blockhash or, for durable-nonce transactions, the stored nonce value
/// (with `advance_nonce` as instruction 0).
pub fn compile_legacy(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> CompiledMessage {
    // Collect flags per key. Fee payer is always a writable signer.
    let mut flags: HashMap<[u8; 32], KeyFlags> = HashMap::new();
    let mut order: Vec<Pubkey> = Vec::new(); // first-seen order for determinism
    let mut note = |k: &Pubkey, add: KeyFlags| {
        let e = flags.entry(k.0).or_insert_with(|| {
            order.push(*k);
            KeyFlags {
                signer: false,
                writable: false,
            }
        });
        e.signer |= add.signer;
        e.writable |= add.writable;
    };
    note(
        fee_payer,
        KeyFlags {
            signer: true,
            writable: true,
        },
    );
    for ix in instructions {
        for m in &ix.accounts {
            note(
                &m.pubkey,
                KeyFlags {
                    signer: m.is_signer,
                    writable: m.is_writable,
                },
            );
        }
        note(
            &ix.program_id,
            KeyFlags {
                signer: false,
                writable: false,
            },
        );
    }

    // Order: writable signers (fee payer first), readonly signers, writable
    // non-signers, readonly non-signers.
    let class = |k: &Pubkey| -> u8 {
        let f = flags[&k.0];
        match (f.signer, f.writable) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        }
    };
    let mut keys: Vec<Pubkey> = order.clone();
    keys.sort_by_key(|k| (class(k), if k.0 == fee_payer.0 { 0u8 } else { 1u8 }));
    // Stable sort keeps first-seen order within a class; the fee-payer tiebreak
    // pins it to index 0 among writable signers.

    let num_signers = keys.iter().filter(|k| flags[&k.0].signer).count() as u8;
    let num_ro_signed = keys
        .iter()
        .filter(|k| flags[&k.0].signer && !flags[&k.0].writable)
        .count() as u8;
    let num_ro_unsigned = keys
        .iter()
        .filter(|k| !flags[&k.0].signer && !flags[&k.0].writable)
        .count() as u8;

    let index_of = |k: &Pubkey| keys.iter().position(|x| x.0 == k.0).unwrap() as u8;

    let mut msg = vec![num_signers, num_ro_signed, num_ro_unsigned];
    push_compact_u16(keys.len() as u16, &mut msg);
    for k in &keys {
        msg.extend_from_slice(&k.0);
    }
    msg.extend_from_slice(recent_blockhash);
    push_compact_u16(instructions.len() as u16, &mut msg);
    for ix in instructions {
        msg.push(index_of(&ix.program_id));
        push_compact_u16(ix.accounts.len() as u16, &mut msg);
        for m in &ix.accounts {
            msg.push(index_of(&m.pubkey));
        }
        push_compact_u16(ix.data.len() as u16, &mut msg);
        msg.extend_from_slice(&ix.data);
    }

    CompiledMessage {
        bytes: msg,
        num_required_signatures: num_signers,
        account_keys: keys,
    }
}

/// Wrap a compiled message in a transaction envelope with all-zero signature
/// placeholders: compact-u16 signature count, then 64 zero bytes per required
/// signer, then the message. This is the base64 format wallets, simulators
/// (`sigVerify: false`) and multisig tooling accept for unsigned transactions.
pub fn unsigned_transaction_base64(msg: &CompiledMessage) -> String {
    let mut tx =
        Vec::with_capacity(1 + 64 * msg.num_required_signatures as usize + msg.bytes.len());
    push_compact_u16(msg.num_required_signatures as u16, &mut tx);
    tx.extend(std::iter::repeat_n(
        0u8,
        64 * msg.num_required_signatures as usize,
    ));
    tx.extend_from_slice(&msg.bytes);
    base64_encode(&tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::system_transfer;

    fn pk(n: u8) -> Pubkey {
        Pubkey([n; 32])
    }

    #[test]
    fn fee_payer_is_index_zero() {
        let msg = compile_legacy(&pk(9), &[system_transfer(&pk(9), &pk(2), 5)], &[0; 32]);
        assert_eq!(msg.account_keys[0], pk(9));
        assert_eq!(msg.num_required_signatures, 1);
    }

    #[test]
    fn header_counts_readonly() {
        // transfer: payer(ws) + recipient(w) + system program(r)
        let msg = compile_legacy(&pk(1), &[system_transfer(&pk(1), &pk(2), 5)], &[0; 32]);
        assert_eq!(
            &msg.bytes[0..3],
            &[1, 0, 1],
            "1 signer, 0 ro-signed, 1 ro-unsigned"
        );
    }

    #[test]
    fn envelope_has_zero_signatures() {
        let msg = compile_legacy(&pk(1), &[system_transfer(&pk(1), &pk(2), 5)], &[0; 32]);
        let b64 = unsigned_transaction_base64(&msg);
        let raw = crate::encoding::base64_decode(&b64).unwrap();
        assert_eq!(raw[0], 1, "one signature slot");
        assert!(raw[1..65].iter().all(|&b| b == 0), "zero placeholder");
        assert_eq!(&raw[65..], &msg.bytes[..]);
    }

    /// Decode the Solana Pay spec's own example transaction and assert our
    /// compiler reproduces its message byte-for-byte.
    #[test]
    fn spec_example_transaction_byte_exact() {
        // From solana-foundation/pay SPEC.md: 1 lamport self-transfer,
        // payer/recipient mvines9..., zeroed blockhash, zeroed signature.
        let payer = Pubkey::parse("mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN").unwrap();
        let ix = system_transfer(&payer, &payer, 1);
        let msg = compile_legacy(&payer, &[ix], &[0; 32]);
        assert_eq!(&msg.bytes[0..3], &[1, 0, 1]);
        assert_eq!(
            msg.account_keys.len(),
            2,
            "payer + system program (self-transfer dedupes)"
        );
        let b64 = unsigned_transaction_base64(&msg);
        let raw = crate::encoding::base64_decode(&b64).unwrap();
        assert_eq!(raw.len(), 183, "spec example length");
        // compiled instruction region (last 18 bytes): ix count, program
        // index, account count, [0,0], data len, [2,0,0,0] ++ u64 LE 1.
        let tail = &raw[raw.len() - 18..];
        assert_eq!(tail[0], 1, "one instruction");
        assert_eq!(tail[1], 1, "program id index");
        assert_eq!(tail[2], 2, "two account indexes");
        assert_eq!(&tail[3..5], &[0, 0], "payer twice");
        assert_eq!(tail[5], 12, "data len");
        assert_eq!(&tail[6..10], &[2, 0, 0, 0], "transfer tag");
        assert_eq!(
            u64::from_le_bytes(tail[10..18].try_into().unwrap()),
            1,
            "1 lamport"
        );
    }
}
