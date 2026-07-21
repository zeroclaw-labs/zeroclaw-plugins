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

/// The amount fields Jupiter embeds at the TAIL of an ExactIn route instruction,
/// after the variable-length `route_plan`: `in_amount` (u64), `quoted_out_amount`
/// (u64), `slippage_bps` (u16), `platform_fee_bps` (u8) — 19 bytes. Decoding from
/// the tail is robust to `route_plan` length. Used by `D3` to bind the built
/// transaction's on-chain amounts to the quote the plugin actually received,
/// instead of trusting the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAmounts {
    pub in_amount: u64,
    pub quoted_out_amount: u64,
    pub slippage_bps: u16,
}

/// Anchor discriminators (sha256("global:<method>")[:8]) for the Jupiter v6
/// ExactIn route instructions that share the `RouteAmounts` tail layout.
const EXACT_IN_ROUTE_DISCRIMINATORS: [[u8; 8]; 4] = [
    [229, 23, 203, 151, 122, 227, 173, 42],  // route
    [193, 32, 155, 51, 65, 214, 156, 129],   // shared_accounts_route
    [150, 86, 71, 116, 167, 93, 14, 104],    // route_with_token_ledger
    [230, 121, 143, 80, 119, 159, 106, 170], // shared_accounts_route_with_token_ledger
];

/// The account index of the user's `destination_token_account` in a Jupiter route
/// instruction, by discriminator — the account the program actually credits with
/// the swap output. `route` puts it at index 3; `shared_accounts_route` at index 6
/// (per the Jupiter v6 IDL). Returns `None` for shapes whose destination index we
/// do not pin, so `D1b` falls back to a documented presence check for those.
pub fn jupiter_destination_account_index(data: &[u8]) -> Option<usize> {
    let disc: [u8; 8] = data.get(..8)?.try_into().ok()?;
    match disc {
        [229, 23, 203, 151, 122, 227, 173, 42] => Some(3), // route
        [193, 32, 155, 51, 65, 214, 156, 129] => Some(6),  // shared_accounts_route
        _ => None,
    }
}

/// Decode the tail amounts of a Jupiter ExactIn route instruction. Returns `None`
/// for any other discriminator (incl. ExactOut variants, whose tail differs) so
/// the gate fails closed on a route shape it cannot fully account for.
pub fn decode_jupiter_route_amounts(data: &[u8]) -> Option<RouteAmounts> {
    if data.len() < 8 + 19 {
        return None;
    }
    let disc: [u8; 8] = data[..8].try_into().ok()?;
    if !EXACT_IN_ROUTE_DISCRIMINATORS.contains(&disc) {
        return None;
    }
    let tail = &data[data.len() - 19..];
    Some(RouteAmounts {
        in_amount: u64::from_le_bytes(tail[0..8].try_into().ok()?),
        quoted_out_amount: u64::from_le_bytes(tail[8..16].try_into().ok()?),
        slippage_bps: u16::from_le_bytes(tail[16..18].try_into().ok()?),
    })
}

/// A classified top-level SPL Token / Token-2022 instruction. Program-id
/// allowlisting is not enough: a top-level `Transfer` moves the user's tokens and
/// a `CloseAccount` sends the account's lamports (unwrapped SOL + rent) to its
/// second account — both must be checked, not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenIx {
    /// `CloseAccount` (disc 9): `[account, destination, owner, ...]`. The
    /// destination receives the lamports; it must be the payer.
    CloseAccount { destination_index: usize },
    /// No-fund-movement setup ops that are safe inside a swap: SyncNative (17),
    /// InitializeAccount/2/3 (1/16/18), InitializeImmutableOwner (22).
    Benign,
    /// Anything that moves tokens or changes control (Transfer, TransferChecked,
    /// Approve, SetAuthority, MintTo, Burn, Freeze, ...). Refused inside a swap.
    Dangerous(u8),
}

/// Classify a top-level SPL Token / Token-2022 instruction by its 1-byte
/// discriminator.
pub fn decode_token(data: &[u8]) -> TokenIx {
    match data.first().copied() {
        Some(9) => TokenIx::CloseAccount {
            destination_index: 1,
        },
        // SyncNative, InitializeAccount / *2 / *3, InitializeImmutableOwner.
        Some(17) | Some(1) | Some(16) | Some(18) | Some(22) => TokenIx::Benign,
        Some(other) => TokenIx::Dangerous(other),
        None => TokenIx::Dangerous(255),
    }
}

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

    #[test]
    fn decodes_real_jupiter_route_amounts() {
        // The real fixture's `route` instruction data (discriminator + route_plan
        // + tail amounts). Tail: in=100_000_000, quoted_out=7_813_715, slippage=50.
        let data = [
            229u8, 23, 203, 151, 122, 227, 173, 42, // route discriminator
            1, 0, // one route-plan entry (truncated shape for the test tail)
            // pad the middle so total length exercises tail-relative decoding
            0, 0, 0, 0, 0, 0, 0, // filler between discriminator and tail
            0, 225, 245, 5, 0, 0, 0, 0, // in_amount = 100_000_000
            83, 58, 119, 0, 0, 0, 0, 0, // quoted_out = 7_813_715
            50, 0, // slippage = 50
            0, // platform_fee
        ];
        let a = decode_jupiter_route_amounts(&data).unwrap();
        assert_eq!(a.in_amount, 100_000_000);
        assert_eq!(a.quoted_out_amount, 7_813_715);
        assert_eq!(a.slippage_bps, 50);
    }

    #[test]
    fn refuses_unknown_route_discriminator() {
        let mut data = vec![9u8; 40];
        data[..8].copy_from_slice(&[208, 51, 239, 151, 123, 43, 237, 92]); // exact_out_route
        assert!(decode_jupiter_route_amounts(&data).is_none());
    }
}
