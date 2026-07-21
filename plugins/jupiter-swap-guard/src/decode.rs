//! Pure decoders for the instruction data of the *allowlisted* programs that can
//! move funds. Program-id allowlisting alone is not enough: a `System.transfer`
//! to an attacker or a runaway `SetComputeUnitPrice` both use allowlisted
//! programs. The gate decodes their data (`D2`, `D4`) rather than trusting the id.
//!
//! No I/O, no wasm dependency. Formats verified against a real captured Jupiter
//! route (System Transfer, ComputeBudget SetComputeUnitLimit/Price, ATA
//! CreateIdempotent).

#![forbid(unsafe_code)]

/// System program id (base58 `1111...1111`).
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
/// ComputeBudget program id.
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
/// Memo program id (v2).
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// A decoded System-program instruction — only the variants a swap can legitimately
/// contain, plus a catch-all the gate treats as unsupported (fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemIx {
    /// Transfer lamports. `to_index` is the index into the instruction's account
    /// list of the destination.
    Transfer { lamports: u64, to_index: usize },
    /// Any other System instruction (CreateAccount, Assign, ...). The gate refuses
    /// these in a swap rather than reasoning about each.
    Other(u32),
}

/// Decode a System instruction's data + account count. The 4-byte little-endian
/// tag selects the variant; Transfer (tag 2) is followed by 8 bytes of lamports
/// and uses account index 1 as the destination.
pub fn decode_system(data: &[u8], account_count: usize) -> Result<SystemIx, String> {
    if data.len() < 4 {
        return Err("System instruction data too short for a tag".into());
    }
    let tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    match tag {
        2 => {
            if data.len() < 12 {
                return Err("System Transfer data too short for lamports".into());
            }
            if account_count < 2 {
                return Err("System Transfer needs a destination account".into());
            }
            let lamports = u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]);
            Ok(SystemIx::Transfer {
                lamports,
                to_index: 1,
            })
        }
        other => Ok(SystemIx::Other(other)),
    }
}

/// A decoded ComputeBudget instruction (the two that affect the fee).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeBudgetIx {
    SetComputeUnitLimit(u32),
    SetComputeUnitPrice(u64),
    Other(u8),
}

/// Decode a ComputeBudget instruction. First byte is the discriminator:
/// 2 = SetComputeUnitLimit (u32 LE), 3 = SetComputeUnitPrice (u64 LE micro-lamports/CU).
pub fn decode_compute_budget(data: &[u8]) -> Result<ComputeBudgetIx, String> {
    let disc = *data.first().ok_or("empty ComputeBudget instruction")?;
    match disc {
        2 => {
            if data.len() < 5 {
                return Err("SetComputeUnitLimit data too short".into());
            }
            Ok(ComputeBudgetIx::SetComputeUnitLimit(u32::from_le_bytes([
                data[1], data[2], data[3], data[4],
            ])))
        }
        3 => {
            if data.len() < 9 {
                return Err("SetComputeUnitPrice data too short".into());
            }
            Ok(ComputeBudgetIx::SetComputeUnitPrice(u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ])))
        }
        other => Ok(ComputeBudgetIx::Other(other)),
    }
}

/// The account index of the `owner` in an SPL Associated Token Account create
/// instruction: `[funder, ata, owner, mint, system, token_program]`. Both
/// `Create` (empty data) and `CreateIdempotent` (`[1]`) share this layout.
pub const ATA_CREATE_OWNER_INDEX: usize = 2;
pub const ATA_CREATE_ATA_INDEX: usize = 1;
pub const ATA_CREATE_MINT_INDEX: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_real_system_wsol_wrap_transfer() {
        // From the fixture: tag 2, lamports 100_000_000.
        let data = [2u8, 0, 0, 0, 0, 225, 245, 5, 0, 0, 0, 0];
        assert_eq!(
            decode_system(&data, 2).unwrap(),
            SystemIx::Transfer {
                lamports: 100_000_000,
                to_index: 1
            }
        );
    }

    #[test]
    fn decodes_real_compute_budget() {
        assert_eq!(
            decode_compute_budget(&[2, 192, 92, 21, 0]).unwrap(),
            ComputeBudgetIx::SetComputeUnitLimit(1_400_000)
        );
        assert_eq!(
            decode_compute_budget(&[3, 4, 23, 1, 0, 0, 0, 0, 0]).unwrap(),
            ComputeBudgetIx::SetComputeUnitPrice(71_428)
        );
    }

    #[test]
    fn unknown_system_tag_is_other_not_a_crash() {
        assert_eq!(decode_system(&[8, 0, 0, 0], 1).unwrap(), SystemIx::Other(8));
    }

    #[test]
    fn short_data_errors_cleanly() {
        assert!(decode_system(&[2, 0], 2).is_err());
        assert!(decode_compute_budget(&[]).is_err());
    }
}
