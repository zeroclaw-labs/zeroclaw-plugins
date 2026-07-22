//! Manual Solana `VersionedTransaction` wire format, built without `solana-sdk`.
//!
//! Solana's transaction wire format is *not* plain Borsh at the outer level:
//! vector lengths use "compact-u16" (shortvec) encoding rather than Borsh's
//! default 4-byte little-endian length prefix, and a versioned message has a
//! one-byte version tag that a legacy message omits entirely. To stay
//! byte-compatible with the real network format while still exposing the
//! ergonomic `BorshSerialize`/`BorshDeserialize` trait interface, the
//! length-prefixed collections below (`ShortVec<T>`) and the version tag
//! (`VersionedMessage`) get hand-written Borsh impls instead of `#[derive]`.
//!
//! This module is pure Solana transaction mechanics only -- no tool-specific
//! orchestration. Each plugin's own pure core module (e.g.
//! `plugins/depin-attest/src/depin_attest.rs`) imports `Instruction`,
//! `AccountMeta`, and `build_durable_nonce_transaction` to build whatever
//! transaction its tool actually needs.

use borsh::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::crypto::{recent_blockhashes_sysvar, Blockhash, Pubkey, Signature, SIGNATURE_LEN};

/// Encodes `len` using Solana's compact-u16 ("shortvec") scheme: 7 payload
/// bits per byte, continuation bit set on every byte but the last. Solana
/// caps this at 3 bytes (values 0..=2^21-1 fit, but only 0..=u16::MAX are
/// ever produced by real transactions), so we reject anything larger.
pub fn encode_shortvec_len(len: usize, out: &mut Vec<u8>) -> Result<(), String> {
    if len > u16::MAX as usize {
        return Err(format!("shortvec length {len} exceeds u16::MAX"));
    }
    let mut rem = len as u16;
    loop {
        let mut byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
    Ok(())
}

/// Decodes a compact-u16 length from the front of `buf`, returning
/// `(value, bytes_consumed)`.
///
/// Mirrors the canonical `solana-short-vec` crate's `visit_byte` validation
/// exactly (verified by differential proptest against that crate), which
/// rejects three malformed-but-otherwise-plausible shapes a naive decoder
/// would silently accept:
/// - a non-minimal ("aliased") encoding, e.g. `[0x80, 0x00]` for the value 0,
///   which has a strictly shorter canonical encoding (`[0x00]`);
/// - a third byte with the continuation bit still set, implying a 4th byte
///   that can never come (compact-u16 caps at 3 bytes by construction);
/// - a bit pattern whose accumulated value exceeds `u16::MAX`, which the
///   3-byte cap alone does not rule out (the 3rd byte contributes 7 more
///   bits than the 2 that actually fit before overflowing 16 bits).
pub fn decode_shortvec_len(buf: &[u8]) -> Result<(usize, usize), String> {
    let mut value: u32 = 0;
    for (nth_byte, &byte) in buf.iter().take(3).enumerate() {
        if byte == 0 && nth_byte != 0 {
            return Err(
                "non-canonical shortvec encoding: zero byte in continuation position".to_string(),
            );
        }
        let elem_done = byte & 0x80 == 0;
        if nth_byte == 2 && !elem_done {
            return Err(
                "malformed shortvec: third byte must not set the continuation bit".to_string(),
            );
        }
        let shift = (nth_byte as u32) * 7;
        value |= ((byte & 0x7f) as u32) << shift;
        if elem_done {
            let value =
                u16::try_from(value).map_err(|_| "shortvec length overflows u16".to_string())?;
            return Ok((value as usize, nth_byte + 1));
        }
    }
    Err("truncated or malformed shortvec length".to_string())
}

/// A `Vec<T>` that (de)serializes with Solana's shortvec length prefix
/// instead of Borsh's default u32-LE length prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShortVec<T>(pub Vec<T>);

impl<T: BorshSerialize> BorshSerialize for ShortVec<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        let mut len_buf = Vec::new();
        encode_shortvec_len(self.0.len(), &mut len_buf)
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
        writer.write_all(&len_buf)?;
        for item in &self.0 {
            item.serialize(writer)?;
        }
        Ok(())
    }
}

impl<T: BorshDeserialize> BorshDeserialize for ShortVec<T> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> IoResult<Self> {
        let mut len_bytes = Vec::with_capacity(3);
        loop {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte)?;
            len_bytes.push(byte[0]);
            if byte[0] & 0x80 == 0 || len_bytes.len() == 3 {
                break;
            }
        }
        let (len, _) =
            decode_shortvec_len(&len_bytes).map_err(|e| IoError::new(ErrorKind::InvalidData, e))?;
        // Deliberately *not* `Vec::with_capacity(len)`: `len` is an
        // attacker-controlled claim (up to u16::MAX) read from the wire
        // before a single element has actually been validated. Nested
        // ShortVecs (e.g. every CompiledInstruction inside a ShortVec of
        // instructions) would otherwise let a tiny malicious payload force
        // many large upfront allocations -- a classic length-prefix memory-
        // amplification attack. Starting empty means real memory use tracks
        // how many elements are *actually* read from `reader`, since a
        // short/truncated input makes `T::deserialize_reader` fail long
        // before `len` iterations complete.
        let mut items = Vec::new();
        for _ in 0..len {
            items.push(T::deserialize_reader(reader)?);
        }
        Ok(ShortVec(items))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: ShortVec<u8>,
    pub data: ShortVec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MessageAddressTableLookup {
    pub account_key: Pubkey,
    pub writable_indexes: ShortVec<u8>,
    pub readonly_indexes: ShortVec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LegacyMessage {
    pub header: MessageHeader,
    pub account_keys: ShortVec<Pubkey>,
    pub recent_blockhash: Blockhash,
    pub instructions: ShortVec<CompiledInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MessageV0 {
    pub header: MessageHeader,
    pub account_keys: ShortVec<Pubkey>,
    pub recent_blockhash: Blockhash,
    pub instructions: ShortVec<CompiledInstruction>,
    pub address_table_lookups: ShortVec<MessageAddressTableLookup>,
}

/// A legacy message has no version marker at all: its first byte is simply
/// `header.num_required_signatures`, which real transactions never set above
/// 127. A v0 message is prefixed with a single byte, `0x80 | version`, whose
/// high bit distinguishes it unambiguously from a legacy message's header.
const VERSION_PREFIX_MASK: u8 = 0x80;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionedMessage {
    Legacy(LegacyMessage),
    V0(MessageV0),
}

impl BorshSerialize for VersionedMessage {
    fn serialize<W: Write>(&self, writer: &mut W) -> IoResult<()> {
        match self {
            VersionedMessage::Legacy(msg) => msg.serialize(writer),
            VersionedMessage::V0(msg) => {
                writer.write_all(&[VERSION_PREFIX_MASK])?;
                msg.serialize(writer)
            }
        }
    }
}

impl BorshDeserialize for VersionedMessage {
    fn deserialize_reader<R: Read>(reader: &mut R) -> IoResult<Self> {
        let mut first = [0u8; 1];
        reader.read_exact(&mut first)?;
        if first[0] & VERSION_PREFIX_MASK != 0 {
            let version = first[0] & 0x7f;
            if version != 0 {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("unsupported message version {version}"),
                ));
            }
            let msg = MessageV0::deserialize_reader(reader)?;
            Ok(VersionedMessage::V0(msg))
        } else {
            let header = MessageHeader {
                num_required_signatures: first[0],
                num_readonly_signed_accounts: u8::deserialize_reader(reader)?,
                num_readonly_unsigned_accounts: u8::deserialize_reader(reader)?,
            };
            let account_keys = ShortVec::<Pubkey>::deserialize_reader(reader)?;
            let recent_blockhash = Blockhash::deserialize_reader(reader)?;
            let instructions = ShortVec::<CompiledInstruction>::deserialize_reader(reader)?;
            Ok(VersionedMessage::Legacy(LegacyMessage {
                header,
                account_keys,
                recent_blockhash,
                instructions,
            }))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VersionedTransaction {
    pub signatures: ShortVec<Signature>,
    pub message: VersionedMessage,
}

/// An uncompiled account reference, before deduplication/ordering assigns it
/// a `u8` index into the message's flat account-key table.
#[derive(Clone, Debug)]
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

/// An uncompiled instruction, referencing accounts by `Pubkey` rather than by
/// message-local index.
#[derive(Clone, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// System Program instruction ordinal for `AdvanceNonceAccount`, matching
/// `solana_program::system_instruction::SystemInstruction::AdvanceNonceAccount`
/// (variant index 4), bincode-encoded as a 4-byte little-endian discriminant
/// with no further payload.
const SYSTEM_ADVANCE_NONCE_ACCOUNT: u32 = 4;

/// Builds the System Program instruction that must precede any durable-nonce
/// transaction's real payload: it invalidates the nonce account's current
/// stored value and rewrites it to a fresh one, which is why a durable-nonce
/// transaction can only ever be submitted once.
pub fn advance_nonce_instruction(nonce_account: Pubkey, nonce_authority: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::SYSTEM_PROGRAM,
        accounts: vec![
            AccountMeta::new(nonce_account, false),
            AccountMeta::new_readonly(recent_blockhashes_sysvar(), false),
            AccountMeta::new_readonly(nonce_authority, true),
        ],
        data: SYSTEM_ADVANCE_NONCE_ACCOUNT.to_le_bytes().to_vec(),
    }
}

struct AccountSlot {
    pubkey: Pubkey,
    is_signer: bool,
    is_writable: bool,
}

fn upsert_account(slots: &mut Vec<AccountSlot>, meta: &AccountMeta) -> usize {
    if let Some(pos) = slots.iter().position(|s| s.pubkey == meta.pubkey) {
        slots[pos].is_signer |= meta.is_signer;
        slots[pos].is_writable |= meta.is_writable;
        pos
    } else {
        slots.push(AccountSlot {
            pubkey: meta.pubkey,
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        });
        slots.len() - 1
    }
}

/// Compiles a fee payer plus a sequence of uncompiled instructions into a
/// `LegacyMessage`, following Solana's account-ordering rule: fee payer
/// first, then signer+writable, signer+readonly, non-signer+writable,
/// non-signer+readonly, each bucket preserving first-seen order.
pub fn compile_legacy_message(
    fee_payer: Pubkey,
    recent_blockhash: Blockhash,
    instructions: &[Instruction],
) -> Result<LegacyMessage, String> {
    let mut slots: Vec<AccountSlot> = Vec::new();

    // The fee payer is always index 0: a signer, and writable (it pays fees).
    upsert_account(&mut slots, &AccountMeta::new(fee_payer, true));

    for ix in instructions {
        upsert_account(&mut slots, &AccountMeta::new_readonly(ix.program_id, false));
        for meta in &ix.accounts {
            upsert_account(&mut slots, meta);
        }
    }

    if slots.len() > 256 {
        return Err("too many distinct accounts to compile into u8 indices".to_string());
    }

    let (mut signer_write, mut signer_read, mut nonsigner_write, mut nonsigner_read) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (i, slot) in slots.iter().enumerate() {
        match (slot.is_signer, slot.is_writable) {
            (true, true) => signer_write.push(i),
            (true, false) => signer_read.push(i),
            (false, true) => nonsigner_write.push(i),
            (false, false) => nonsigner_read.push(i),
        }
    }

    let ordered: Vec<usize> = signer_write
        .iter()
        .chain(signer_read.iter())
        .chain(nonsigner_write.iter())
        .chain(nonsigner_read.iter())
        .copied()
        .collect();

    let mut new_index = vec![0u8; slots.len()];
    for (new_pos, &old_pos) in ordered.iter().enumerate() {
        new_index[old_pos] = new_pos as u8;
    }

    let account_keys: Vec<Pubkey> = ordered.iter().map(|&i| slots[i].pubkey).collect();

    let header = MessageHeader {
        num_required_signatures: (signer_write.len() + signer_read.len()) as u8,
        num_readonly_signed_accounts: signer_read.len() as u8,
        num_readonly_unsigned_accounts: nonsigner_read.len() as u8,
    };

    let mut compiled_instructions = Vec::with_capacity(instructions.len());
    for ix in instructions {
        let program_id_index = slots
            .iter()
            .position(|s| s.pubkey == ix.program_id)
            .map(|old| new_index[old])
            .ok_or_else(|| "program id missing from compiled account list".to_string())?;
        let mut accounts = Vec::with_capacity(ix.accounts.len());
        for meta in &ix.accounts {
            let old = slots
                .iter()
                .position(|s| s.pubkey == meta.pubkey)
                .ok_or_else(|| {
                    "instruction account missing from compiled account list".to_string()
                })?;
            accounts.push(new_index[old]);
        }
        compiled_instructions.push(CompiledInstruction {
            program_id_index,
            accounts: ShortVec(accounts),
            data: ShortVec(ix.data.clone()),
        });
    }

    Ok(LegacyMessage {
        header,
        account_keys: ShortVec(account_keys),
        recent_blockhash,
        instructions: ShortVec(compiled_instructions),
    })
}

/// Builds an unsigned durable-nonce transaction: an `AdvanceNonceAccount`
/// instruction packed ahead of the caller's instructions, with the nonce
/// account's current stored value substituted for `recent_blockhash`. Unlike
/// a normal blockhash, a durable nonce does not expire after ~150 blocks
/// (roughly a minute), so the transaction remains valid to submit until the
/// nonce account is advanced again — essential for edge/DePIN nodes, or any
/// agent flow that drops a transaction into a human approval queue and can't
/// guarantee the human signs it within a minute.
///
/// Signature slots are left zeroed; an external signer (the operator
/// approval flow) fills them in before broadcast.
pub fn build_durable_nonce_transaction(
    fee_payer: Pubkey,
    nonce_account: Pubkey,
    nonce_authority: Pubkey,
    nonce_value: Blockhash,
    mut instructions: Vec<Instruction>,
) -> Result<VersionedTransaction, String> {
    let mut all_instructions = Vec::with_capacity(instructions.len() + 1);
    all_instructions.push(advance_nonce_instruction(nonce_account, nonce_authority));
    all_instructions.append(&mut instructions);

    let message = compile_legacy_message(fee_payer, nonce_value, &all_instructions)?;
    let num_sigs = message.header.num_required_signatures as usize;

    Ok(VersionedTransaction {
        signatures: ShortVec(vec![Signature([0u8; SIGNATURE_LEN]); num_sigs]),
        message: VersionedMessage::Legacy(message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Every value in shortvec's representable range (0..=u16::MAX) must
        /// encode to at most 3 bytes and decode back to exactly the value
        /// that went in, regardless of which specific value proptest picks
        /// (not just the 6 hand-picked cases below).
        #[test]
        fn shortvec_len_round_trips_for_any_representable_value(len in 0usize..=u16::MAX as usize) {
            let mut out = Vec::new();
            encode_shortvec_len(len, &mut out).unwrap();
            prop_assert!(out.len() <= 3);
            let (decoded, consumed) = decode_shortvec_len(&out).unwrap();
            prop_assert_eq!(decoded, len);
            prop_assert_eq!(consumed, out.len());
        }

        /// Differential test against the canonical `solana-short-vec` crate
        /// (the standalone crate `solana_program::short_vec` itself
        /// re-exports, per its own deprecation notice) for every
        /// representable value: our encoding must be byte-for-byte
        /// identical to what real Solana transactions actually use on the
        /// wire, not just internally self-consistent.
        #[test]
        fn shortvec_encoding_matches_canonical_solana_short_vec_crate(len in 0usize..=u16::MAX as usize) {
            let mut ours = Vec::new();
            encode_shortvec_len(len, &mut ours).unwrap();

            let canonical = bincode::serialize(&solana_short_vec::ShortU16(len as u16)).unwrap();
            prop_assert_eq!(&ours, &canonical, "our shortvec encoding diverges from solana-short-vec for len={}", len);

            let (canonical_decoded, canonical_consumed) =
                solana_short_vec::decode_shortu16_len(&ours).unwrap();
            prop_assert_eq!(canonical_decoded, len);
            prop_assert_eq!(canonical_consumed, ours.len());
        }

        /// Same differential check from the decode side, over *arbitrary*
        /// (not just validly-encoded) byte sequences: our decoder must
        /// agree with the canonical crate on every input, success or
        /// failure alike.
        #[test]
        fn shortvec_decode_agrees_with_canonical_crate_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..8),
        ) {
            let ours = decode_shortvec_len(&bytes);
            let canonical = solana_short_vec::decode_shortu16_len(&bytes);
            match (ours, canonical) {
                (Ok(ours), Ok(canonical)) => prop_assert_eq!(ours, canonical),
                (Err(_), Err(())) => {} // both correctly rejected
                (ours, canonical) => prop_assert!(
                    false,
                    "divergence on {:?}: ours={:?}, canonical={:?}",
                    bytes, ours, canonical
                ),
            }
        }

        /// A durable-nonce transaction built from an arbitrary single
        /// instruction (arbitrary accounts, signer/writable flags, and
        /// instruction data) must survive a full Borsh serialize/deserialize
        /// round trip byte-for-byte -- this is the property that actually
        /// matters for wire compatibility, exercised over many randomized
        /// shapes instead of the few hand-built cases below.
        #[test]
        fn durable_nonce_transaction_round_trips_for_arbitrary_instruction_shapes(
            fee_payer_byte in any::<u8>(),
            nonce_account_byte in any::<u8>(),
            nonce_authority_byte in any::<u8>(),
            program_byte in any::<u8>(),
            extra_account_byte in any::<u8>(),
            data in prop::collection::vec(any::<u8>(), 0..64),
            is_signer in any::<bool>(),
            is_writable in any::<bool>(),
        ) {
            let fee_payer = Pubkey([fee_payer_byte; 32]);
            let nonce_account = Pubkey([nonce_account_byte; 32]);
            let nonce_authority = Pubkey([nonce_authority_byte; 32]);
            let ix = Instruction {
                program_id: Pubkey([program_byte; 32]),
                accounts: vec![AccountMeta {
                    pubkey: Pubkey([extra_account_byte; 32]),
                    is_signer,
                    is_writable,
                }],
                data,
            };

            let tx = build_durable_nonce_transaction(
                fee_payer,
                nonce_account,
                nonce_authority,
                [0u8; 32],
                vec![ix],
            ).unwrap();

            let bytes = borsh::to_vec(&tx).unwrap();
            let decoded: VersionedTransaction = borsh::from_slice(&bytes).unwrap();
            prop_assert_eq!(decoded, tx);
        }
    }

    #[test]
    fn shortvec_round_trips_and_matches_known_encodings() {
        let cases: [(usize, &[u8]); 6] = [
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (255, &[0xff, 0x01]),
            (16384, &[0x80, 0x80, 0x01]),
            (65535, &[0xff, 0xff, 0x03]),
        ];
        for (value, expected_bytes) in cases {
            let mut out = Vec::new();
            encode_shortvec_len(value, &mut out).unwrap();
            assert_eq!(out, expected_bytes, "encoding mismatch for {value}");
            let (decoded, consumed) = decode_shortvec_len(&out).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, out.len());
        }
    }

    #[test]
    fn shortvec_rejects_over_u16_max() {
        let mut out = Vec::new();
        assert!(encode_shortvec_len(u16::MAX as usize + 1, &mut out).is_err());
    }

    fn dummy_pubkey(byte: u8) -> Pubkey {
        Pubkey([byte; 32])
    }

    #[test]
    fn compiles_simple_transfer_with_correct_header_and_ordering() {
        let fee_payer = dummy_pubkey(1);
        let recipient = dummy_pubkey(2);
        let system_program = Pubkey::SYSTEM_PROGRAM;

        let transfer_ix = Instruction {
            program_id: system_program,
            accounts: vec![
                AccountMeta::new(fee_payer, true),
                AccountMeta::new(recipient, false),
            ],
            data: vec![2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0], // Transfer(lamports=100)
        };

        let msg = compile_legacy_message(fee_payer, [9u8; 32], &[transfer_ix]).unwrap();

        assert_eq!(msg.header.num_required_signatures, 1);
        assert_eq!(msg.header.num_readonly_signed_accounts, 0);
        assert_eq!(msg.header.num_readonly_unsigned_accounts, 1); // system program

        // fee payer first, recipient (writable, non-signer) next, program id last (readonly).
        assert_eq!(msg.account_keys.0[0], fee_payer);
        assert_eq!(msg.account_keys.0[1], recipient);
        assert_eq!(msg.account_keys.0[2], system_program);

        let ix = &msg.instructions.0[0];
        assert_eq!(ix.program_id_index, 2);
        assert_eq!(ix.accounts.0, vec![0u8, 1u8]);
    }

    #[test]
    fn durable_nonce_transaction_packs_advance_instruction_first() {
        let fee_payer = dummy_pubkey(1);
        let nonce_account = dummy_pubkey(2);
        let nonce_authority = dummy_pubkey(3);
        let nonce_value = [5u8; 32];

        let payload_ix = Instruction {
            program_id: dummy_pubkey(9),
            accounts: vec![AccountMeta::new_readonly(fee_payer, true)],
            data: vec![1, 2, 3],
        };

        let tx = build_durable_nonce_transaction(
            fee_payer,
            nonce_account,
            nonce_authority,
            nonce_value,
            vec![payload_ix],
        )
        .unwrap();

        let VersionedMessage::Legacy(msg) = &tx.message else {
            panic!("expected a legacy message");
        };

        assert_eq!(msg.recent_blockhash, nonce_value);
        assert_eq!(msg.instructions.0.len(), 2);

        let advance_ix = &msg.instructions.0[0];
        assert_eq!(advance_ix.data.0, vec![4, 0, 0, 0]);

        let system_program_index = msg
            .account_keys
            .0
            .iter()
            .position(|k| *k == Pubkey::SYSTEM_PROGRAM)
            .unwrap() as u8;
        assert_eq!(advance_ix.program_id_index, system_program_index);

        // fee payer + nonce_authority both signers => 2 required signatures.
        assert_eq!(tx.signatures.0.len(), 2);
        assert!(tx.signatures.0.iter().all(|s| *s == Signature::unsigned()));
    }

    #[test]
    fn versioned_transaction_round_trips_through_borsh() {
        let fee_payer = dummy_pubkey(1);
        let ix = Instruction {
            program_id: Pubkey::SYSTEM_PROGRAM,
            accounts: vec![AccountMeta::new(fee_payer, true)],
            data: vec![9, 9],
        };
        let tx = build_durable_nonce_transaction(
            fee_payer,
            dummy_pubkey(2),
            fee_payer,
            [3u8; 32],
            vec![ix],
        )
        .unwrap();

        let bytes = borsh::to_vec(&tx).unwrap();
        let decoded: VersionedTransaction = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded, tx);

        // Legacy messages carry no version-tag byte: the wire size is exactly
        // signatures + header(3) + account-keys + blockhash(32) + instructions.
        assert!(!bytes.is_empty());
    }

    #[test]
    fn v0_message_round_trips_with_version_prefix_byte() {
        let msg = MessageV0 {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: ShortVec(vec![dummy_pubkey(1), dummy_pubkey(2)]),
            recent_blockhash: [4u8; 32],
            instructions: ShortVec(vec![]),
            address_table_lookups: ShortVec(vec![]),
        };
        let versioned = VersionedMessage::V0(msg.clone());
        let bytes = borsh::to_vec(&versioned).unwrap();
        assert_eq!(
            bytes[0], 0x80,
            "v0 message must start with the version tag byte"
        );

        let decoded: VersionedMessage = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded, VersionedMessage::V0(msg));
    }
}
