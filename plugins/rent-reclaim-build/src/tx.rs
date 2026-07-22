//! Minimal legacy Solana transaction assembly — hand-rolled, no `solana-sdk`
//! (which does not compile cleanly inside a wasip2 WIT component; see README).
//!
//! Only what this plugin needs: a single-signer legacy message carrying
//! ComputeBudget instructions plus SPL `CloseAccount` instructions. The rent
//! destination of every close is **structurally** the owner: the encoder takes
//! no destination input at all.

/// SPL Token program id.
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SPL Token-2022 program id.
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// ComputeBudget program id.
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

/// SPL Token `CloseAccount` instruction discriminant.
const CLOSE_ACCOUNT_IX: u8 = 9;
/// ComputeBudget `SetComputeUnitLimit` discriminant.
const SET_CU_LIMIT_IX: u8 = 2;
/// ComputeBudget `SetComputeUnitPrice` discriminant.
const SET_CU_PRICE_IX: u8 = 3;

/// Compute units budgeted per close instruction (measured ~2.9k; padded).
const CU_PER_CLOSE: u32 = 4_000;
const CU_BASE: u32 = 2_000;

/// One account to close: its address and the token program that owns it.
pub struct CloseTarget {
    pub pubkey: [u8; 32],
    pub token_program: [u8; 32],
}

/// Solana short-vec (compact-u16) length encoding.
pub fn compact_u16(mut n: u16, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

struct RawInstruction {
    program_idx: u8,
    account_idxs: Vec<u8>,
    data: Vec<u8>,
}

/// Build an unsigned single-signer legacy transaction that closes `targets`
/// and returns each account's lamports to `owner`.
///
/// Layout invariant (enforced by construction, verified in tests): the
/// destination account index of every `CloseAccount` instruction equals the
/// owner/fee-payer index (0). There is no code path that can point the rent
/// anywhere else.
pub fn build_close_tx(
    owner: [u8; 32],
    targets: &[CloseTarget],
    blockhash: [u8; 32],
    priority_fee_micro_lamports: Option<u64>,
) -> Result<Vec<u8>, String> {
    if targets.is_empty() {
        return Err("no accounts to close".to_string());
    }
    if targets.len() > u8::MAX as usize {
        return Err("too many accounts".to_string());
    }

    // Account keys.
    // [0]                    owner       — signer, writable (fee payer + rent destination)
    // [1..=n]                accounts    — writable, non-signer
    // [n+1..]                programs    — readonly, non-signer
    let mut keys: Vec<[u8; 32]> = vec![owner];
    for t in targets {
        if t.pubkey == owner {
            return Err("refusing to close the owner account itself".to_string());
        }
        if keys.contains(&t.pubkey) {
            return Err("duplicate account in close list".to_string());
        }
        keys.push(t.pubkey);
    }
    let mut readonly: Vec<[u8; 32]> = Vec::new();
    let idx_of = |keys: &mut Vec<[u8; 32]>, readonly: &mut Vec<[u8; 32]>, k: [u8; 32]| -> u8 {
        if let Some(i) = keys.iter().position(|x| *x == k) {
            return i as u8;
        }
        keys.push(k);
        readonly.push(k);
        (keys.len() - 1) as u8
    };

    let compute_budget = decode_key(COMPUTE_BUDGET_PROGRAM)?;
    let mut instructions: Vec<RawInstruction> = Vec::new();

    // ComputeBudget: explicit CU limit (and optional priority fee) so the
    // human-approved transaction lands predictably.
    let cb_idx = idx_of(&mut keys, &mut readonly, compute_budget);
    let cu_limit = CU_BASE + CU_PER_CLOSE * targets.len() as u32;
    let mut limit_data = vec![SET_CU_LIMIT_IX];
    limit_data.extend_from_slice(&cu_limit.to_le_bytes());
    instructions.push(RawInstruction {
        program_idx: cb_idx,
        account_idxs: vec![],
        data: limit_data,
    });
    if let Some(price) = priority_fee_micro_lamports {
        let mut price_data = vec![SET_CU_PRICE_IX];
        price_data.extend_from_slice(&price.to_le_bytes());
        instructions.push(RawInstruction {
            program_idx: cb_idx,
            account_idxs: vec![],
            data: price_data,
        });
    }

    for (i, t) in targets.iter().enumerate() {
        let program_idx = idx_of(&mut keys, &mut readonly, t.token_program);
        instructions.push(RawInstruction {
            program_idx,
            // [account to close, destination = OWNER (index 0), authority = OWNER]
            account_idxs: vec![(i + 1) as u8, 0, 0],
            data: vec![CLOSE_ACCOUNT_IX],
        });
    }

    // Message: header | keys | blockhash | instructions.
    let num_readonly_unsigned = readonly.len() as u8;
    let mut msg: Vec<u8> = vec![1, 0, num_readonly_unsigned];
    compact_u16(keys.len() as u16, &mut msg);
    for k in &keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(&blockhash);
    compact_u16(instructions.len() as u16, &mut msg);
    for ix in &instructions {
        msg.push(ix.program_idx);
        compact_u16(ix.account_idxs.len() as u16, &mut msg);
        msg.extend_from_slice(&ix.account_idxs);
        compact_u16(ix.data.len() as u16, &mut msg);
        msg.extend_from_slice(&ix.data);
    }

    // Unsigned wire transaction: one zeroed signature slot + the message.
    let mut tx: Vec<u8> = Vec::with_capacity(65 + msg.len());
    compact_u16(1, &mut tx);
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(&msg);
    Ok(tx)
}

pub fn decode_key(s: &str) -> Result<[u8; 32], String> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|_| format!("invalid base58: {s}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("not a 32-byte key: {s}"))
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn compact_u16_matches_solana_shortvec() {
        let cases: [(u16, &[u8]); 5] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (16384, &[0x80, 0x80, 0x01]),
        ];
        for (n, expect) in cases {
            let mut out = Vec::new();
            compact_u16(n, &mut out);
            assert_eq!(out, expect, "n={n}");
        }
    }

    #[test]
    fn refuses_owner_and_duplicates() {
        let owner = [1u8; 32];
        let tp = decode_key(TOKEN_PROGRAM).unwrap();
        let mk = |pk: [u8; 32]| CloseTarget {
            pubkey: pk,
            token_program: tp,
        };
        assert!(build_close_tx(owner, &[mk(owner)], [9; 32], None).is_err());
        assert!(build_close_tx(owner, &[mk([2; 32]), mk([2; 32])], [9; 32], None).is_err());
        assert!(build_close_tx(owner, &[], [9; 32], None).is_err());
    }
}
